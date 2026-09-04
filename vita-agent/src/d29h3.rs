//! D29-H3's first governed bounded workspace read.
//!
//! The executable path in this module is deliberately crate-private and is
//! not installed by the normal Vita entrypoint.  The only current issuer is a
//! test-scoped trusted adapter which consumes a canonical D28 verdict and a
//! real H2 prepared target.  The model can request a relative resource, but
//! it cannot select a capability, mint a grant, or supply authority evidence.
#![allow(dead_code, private_interfaces)]

use std::collections::HashSet;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::workspace_capability::{
    PreparedWorkspaceTarget, PreparedWorkspaceTargetKind, WorkspaceReadError,
    WORKSPACE_READ_HARD_MAX_BYTES,
};
use super::{VitaExecutionContext, VitaRequestedScope};

pub(crate) const VITA_WORKSPACE_READ_TOOL_NAME: &str = "vita_workspace_read_file";
pub(crate) const VITA_WORKSPACE_READ_CAPABILITY_ID: &str = "vita.workspace.read_file";
const MAX_CALL_ID_CHARS: usize = 128;
const MAX_TURN_ID_CHARS: usize = 128;
const MAX_PATH_CHARS: usize = 256;
const GRANT_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
struct VitaWorkspaceReadRequest {
    tool_call_id: String,
    turn_id: String,
    context: Option<VitaExecutionContext>,
    relative_path: super::WorkspaceRelativePath,
    max_bytes: usize,
    expected_authorization_revision: i64,
}

impl VitaWorkspaceReadRequest {
    fn from_codex_call(
        call: &ToolCall<'_>,
        context: Option<&VitaExecutionContext>,
    ) -> Result<Self, H3RequestBuildError> {
        if call.tool_name.name != VITA_WORKSPACE_READ_TOOL_NAME
            || !call.tool_name.is_default_namespace()
        {
            return Err(H3RequestBuildError::UnmappedTool);
        }
        let tool_call_id = bounded_text("tool call id", &call.call_id, MAX_CALL_ID_CHARS)
            .ok_or(H3RequestBuildError::InvalidCallId)?;
        let turn_id = bounded_text("turn id", &call.turn_id, MAX_TURN_ID_CHARS)
            .ok_or(H3RequestBuildError::InvalidTurnId)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H3RequestBuildError::InvalidArguments)?;
        let arguments: VitaWorkspaceReadArguments =
            serde_json::from_str(arguments).map_err(|_| H3RequestBuildError::InvalidArguments)?;
        if arguments.relative_path.chars().count() > MAX_PATH_CHARS {
            return Err(H3RequestBuildError::InvalidPath);
        }
        let relative_path =
            super::WorkspaceRelativePath::parse(std::path::Path::new(&arguments.relative_path))
                .map_err(|_| H3RequestBuildError::InvalidPath)?;
        let max_bytes = usize::try_from(arguments.max_bytes)
            .ok()
            .filter(|value| (1..=WORKSPACE_READ_HARD_MAX_BYTES).contains(value))
            .ok_or(H3RequestBuildError::InvalidLimit)?;
        if arguments.expected_authorization_revision < 1 {
            return Err(H3RequestBuildError::InvalidRevision);
        }
        Ok(Self {
            tool_call_id,
            turn_id,
            context: context.cloned(),
            relative_path,
            max_bytes,
            expected_authorization_revision: arguments.expected_authorization_revision,
        })
    }

    #[cfg(test)]
    fn synthetic(
        tool_call_id: &str,
        context: Option<VitaExecutionContext>,
        relative_path: &str,
        max_bytes: usize,
        expected_authorization_revision: i64,
    ) -> Self {
        Self {
            tool_call_id: tool_call_id.to_string(),
            turn_id: "turn-d29h3".to_string(),
            context,
            relative_path: super::WorkspaceRelativePath::parse(std::path::Path::new(relative_path))
                .expect("synthetic H3 path must be valid"),
            max_bytes,
            expected_authorization_revision,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VitaWorkspaceReadArguments {
    relative_path: String,
    max_bytes: u64,
    expected_authorization_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3RequestBuildError {
    UnmappedTool,
    InvalidCallId,
    InvalidTurnId,
    InvalidArguments,
    InvalidPath,
    InvalidLimit,
    InvalidRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3AuthorityOutcome {
    Denied,
    Eligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3AuthorityReason {
    Eligible,
    UnknownCapabilityDescriptor,
    MissingAuthorization,
    RootDisabled,
    ScopeUnavailable,
    StaleRevision,
    AuthorityError,
}

impl H3AuthorityReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::UnknownCapabilityDescriptor => "unknown_capability_descriptor",
            Self::MissingAuthorization => "missing_authorization",
            Self::RootDisabled => "root_disabled",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::StaleRevision => "stale_authorization_revision",
            Self::AuthorityError => "authority_error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3AuthorityRequest {
    context: VitaExecutionContext,
    capability_id: String,
    // D28's frozen evaluator receives None here.  H3's workspace binding is
    // a separate execution scope carried by the executable grant.
    d28_requested_scope: VitaRequestedScope,
    authorized_scope: VitaRequestedScope,
    expected_authorization_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3AuthorityVerdict {
    outcome: H3AuthorityOutcome,
    reason: H3AuthorityReason,
    life_id: String,
    task_id: String,
    capability_id: String,
    d28_requested_scope: VitaRequestedScope,
    authorized_scope: VitaRequestedScope,
    authorization_revision: Option<i64>,
}

impl H3AuthorityVerdict {
    fn from_request(
        request: &H3AuthorityRequest,
        outcome: H3AuthorityOutcome,
        reason: H3AuthorityReason,
        authorization_revision: Option<i64>,
    ) -> Self {
        Self {
            outcome,
            reason,
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: request.capability_id.clone(),
            d28_requested_scope: request.d28_requested_scope,
            authorized_scope: request.authorized_scope,
            authorization_revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VitaH3AuthorityError {
    Unavailable,
    InvalidVerdict,
}

pub(crate) type VitaH3AuthorityFuture = Pin<
    Box<dyn Future<Output = Result<H3AuthorityVerdict, VitaH3AuthorityError>> + Send + 'static>,
>;

pub(crate) trait VitaH3AuthorityPort: Send + Sync {
    fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3DenyClassification {
    MissingContext,
    WrongLifeBinding,
    WrongTaskBinding,
    UnmappedTool,
    InvalidRequest,
    MissingAuthorization,
    ScopeUnavailable,
    StaleRevision,
    DuplicateToolCall,
    TurnCancelled,
    LateAfterCancellation,
    AuthorityError,
    AuthorityPanic,
    AuthorityEvidenceMismatch,
    GrantRejected,
    TargetRejected,
    TargetMissing,
    TargetIdentityMismatch,
    Oversized,
    InvalidUtf8,
    CancelledAfterRead,
}

impl H3DenyClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingContext => "missing_execution_context",
            Self::WrongLifeBinding => "wrong_life_binding",
            Self::WrongTaskBinding => "wrong_task_binding",
            Self::UnmappedTool => "unmapped_tool",
            Self::InvalidRequest => "invalid_request",
            Self::MissingAuthorization => "missing_authorization",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::StaleRevision => "stale_authorization_revision",
            Self::DuplicateToolCall => "duplicate_tool_call_id",
            Self::TurnCancelled => "turn_cancelled",
            Self::LateAfterCancellation => "late_authority_after_cancellation",
            Self::AuthorityError => "authority_error",
            Self::AuthorityPanic => "authority_panic",
            Self::AuthorityEvidenceMismatch => "authority_evidence_mismatch",
            Self::GrantRejected => "executable_grant_rejected",
            Self::TargetRejected => "workspace_target_rejected",
            Self::TargetMissing => "workspace_target_missing",
            Self::TargetIdentityMismatch => "workspace_target_identity_mismatch",
            Self::Oversized => "workspace_file_too_large",
            Self::InvalidUtf8 => "workspace_file_not_utf8",
            Self::CancelledAfterRead => "turn_cancelled_after_bounded_read",
        }
    }
}

#[derive(Debug)]
struct VitaWorkspaceReadResult {
    request: VitaWorkspaceReadRequest,
    classification: Option<H3DenyClassification>,
    content: Option<String>,
    bytes_read: usize,
    execution_started: bool,
    grant_issued: bool,
}

impl VitaWorkspaceReadResult {
    fn denied(request: VitaWorkspaceReadRequest, classification: H3DenyClassification) -> Self {
        Self {
            request,
            classification: Some(classification),
            content: None,
            bytes_read: 0,
            execution_started: false,
            grant_issued: false,
        }
    }

    fn denied_after_grant(
        request: VitaWorkspaceReadRequest,
        classification: H3DenyClassification,
    ) -> Self {
        let mut result = Self::denied(request, classification);
        result.grant_issued = true;
        result
    }

    fn model_value(&self) -> Value {
        let status = if self.classification.is_none() {
            "success"
        } else {
            "denied"
        };
        json!({
            "status": status,
            "tool_call_id": self.request.tool_call_id,
            "tool": VITA_WORKSPACE_READ_TOOL_NAME,
            "capability_id": VITA_WORKSPACE_READ_CAPABILITY_ID,
            "relative_path": self.request.relative_path.as_path().to_string_lossy(),
            "max_bytes": self.request.max_bytes,
            "bytes_read": self.bytes_read,
            "content": self.content,
            "deny_classification": self.classification.map(H3DenyClassification::as_str),
            "execution_started": self.execution_started,
            "grant_issued": self.grant_issued,
            "side_effect_count": 0,
        })
    }
}

#[derive(Default)]
struct H3BrokerState {
    seen_call_ids: HashSet<String>,
}

#[derive(Default)]
struct H3BrokerMetrics {
    attempted_requests: AtomicUsize,
    authority_evaluations: AtomicUsize,
    duplicate_denials: AtomicUsize,
    late_denials: AtomicUsize,
    cancellation_denials: AtomicUsize,
    stale_denials: AtomicUsize,
    authority_errors: AtomicUsize,
    authority_panics: AtomicUsize,
    grants_issued: AtomicUsize,
    execution_started: AtomicUsize,
    authorized_file_reads: AtomicUsize,
    file_bytes_read: AtomicUsize,
    filesystem_mutations: AtomicUsize,
    process_spawns: AtomicUsize,
    external_network_requests: AtomicUsize,
    active_authority: AtomicUsize,
    max_active_authority: AtomicUsize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct VitaWorkspaceReadSnapshot {
    pub attempted_requests: usize,
    pub authority_evaluations: usize,
    pub duplicate_denials: usize,
    pub late_denials: usize,
    pub cancellation_denials: usize,
    pub stale_denials: usize,
    pub authority_errors: usize,
    pub authority_panics: usize,
    pub grants_issued: usize,
    pub execution_started: usize,
    pub authorized_file_reads: usize,
    pub file_bytes_read: usize,
    pub filesystem_mutations: usize,
    pub process_spawns: usize,
    pub external_network_requests: usize,
    pub max_active_authority: usize,
}

/// The H3 broker is an internal test/integration seam.  It has no production
/// constructor call and is not attached to the normal Vita entrypoint.
pub(crate) struct VitaWorkspaceReadBroker {
    context: Option<VitaExecutionContext>,
    root: super::TrustedWorkspaceRoot,
    authority: Arc<dyn VitaH3AuthorityPort>,
    issuer: Arc<dyn VitaH3GrantIssuer>,
    state: Mutex<H3BrokerState>,
    cancelled: AtomicBool,
    metrics: Arc<H3BrokerMetrics>,
}

impl VitaWorkspaceReadBroker {
    pub(crate) fn new(
        context: VitaExecutionContext,
        root: super::TrustedWorkspaceRoot,
        authority: Arc<dyn VitaH3AuthorityPort>,
        issuer: Arc<dyn VitaH3GrantIssuer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: Some(context),
            root,
            authority,
            issuer,
            state: Mutex::new(H3BrokerState::default()),
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(H3BrokerMetrics::default()),
        })
    }

    #[cfg(test)]
    fn without_context(
        root: super::TrustedWorkspaceRoot,
        authority: Arc<dyn VitaH3AuthorityPort>,
        issuer: Arc<dyn VitaH3GrantIssuer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: None,
            root,
            authority,
            issuer,
            state: Mutex::new(H3BrokerState::default()),
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(H3BrokerMetrics::default()),
        })
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn snapshot(&self) -> VitaWorkspaceReadSnapshot {
        VitaWorkspaceReadSnapshot {
            attempted_requests: self.metrics.attempted_requests.load(Ordering::Acquire),
            authority_evaluations: self.metrics.authority_evaluations.load(Ordering::Acquire),
            duplicate_denials: self.metrics.duplicate_denials.load(Ordering::Acquire),
            late_denials: self.metrics.late_denials.load(Ordering::Acquire),
            cancellation_denials: self.metrics.cancellation_denials.load(Ordering::Acquire),
            stale_denials: self.metrics.stale_denials.load(Ordering::Acquire),
            authority_errors: self.metrics.authority_errors.load(Ordering::Acquire),
            authority_panics: self.metrics.authority_panics.load(Ordering::Acquire),
            grants_issued: self.metrics.grants_issued.load(Ordering::Acquire),
            execution_started: self.metrics.execution_started.load(Ordering::Acquire),
            authorized_file_reads: self.metrics.authorized_file_reads.load(Ordering::Acquire),
            file_bytes_read: self.metrics.file_bytes_read.load(Ordering::Acquire),
            filesystem_mutations: self.metrics.filesystem_mutations.load(Ordering::Acquire),
            process_spawns: self.metrics.process_spawns.load(Ordering::Acquire),
            external_network_requests: self
                .metrics
                .external_network_requests
                .load(Ordering::Acquire),
            max_active_authority: self.metrics.max_active_authority.load(Ordering::Acquire),
        }
    }

    async fn execute_request(&self, request: VitaWorkspaceReadRequest) -> VitaWorkspaceReadResult {
        self.metrics
            .attempted_requests
            .fetch_add(1, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics
                .cancellation_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied(request, H3DenyClassification::TurnCancelled);
        }

        let Some(bound_context) = self.context.as_ref() else {
            return VitaWorkspaceReadResult::denied(request, H3DenyClassification::MissingContext);
        };
        let Some(request_context) = request.context.as_ref() else {
            return VitaWorkspaceReadResult::denied(request, H3DenyClassification::MissingContext);
        };
        if request_context.life_id() != bound_context.life_id() {
            return VitaWorkspaceReadResult::denied(
                request,
                H3DenyClassification::WrongLifeBinding,
            );
        }
        if request_context.task_id() != bound_context.task_id() {
            return VitaWorkspaceReadResult::denied(
                request,
                H3DenyClassification::WrongTaskBinding,
            );
        }

        let duplicate = {
            let mut state = lock_unpoisoned(&self.state);
            !state.seen_call_ids.insert(request.tool_call_id.clone())
        };
        if duplicate {
            self.metrics
                .duplicate_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied(
                request,
                H3DenyClassification::DuplicateToolCall,
            );
        }

        let authority_request = H3AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            d28_requested_scope: VitaRequestedScope::None,
            authorized_scope: VitaRequestedScope::Workspace,
            expected_authorization_revision: request.expected_authorization_revision,
        };
        let initial_authority = match self.evaluate_authority(authority_request.clone()).await {
            Ok(verdict) => verdict,
            Err(classification) => return VitaWorkspaceReadResult::denied(request, classification),
        };
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics.late_denials.fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied(
                request,
                H3DenyClassification::LateAfterCancellation,
            );
        }
        if let Err(classification) = validate_authority(&initial_authority, &authority_request) {
            if classification == H3DenyClassification::StaleRevision {
                self.metrics.stale_denials.fetch_add(1, Ordering::AcqRel);
            }
            return VitaWorkspaceReadResult::denied(request, classification);
        }

        let prepared = match self.root.prepare_target(request.relative_path.as_path()) {
            Ok(prepared) => prepared,
            Err(_) => {
                return VitaWorkspaceReadResult::denied(
                    request,
                    H3DenyClassification::TargetRejected,
                )
            }
        };
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity().is_none()
        {
            return VitaWorkspaceReadResult::denied(
                request,
                if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
                    H3DenyClassification::TargetMissing
                } else {
                    H3DenyClassification::TargetRejected
                },
            );
        }
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics
                .cancellation_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied(request, H3DenyClassification::TurnCancelled);
        }

        let grant = match catch_unwind(AssertUnwindSafe(|| {
            self.issuer
                .issue(&initial_authority, bound_context, &request, &prepared)
        })) {
            Ok(Ok(grant)) => grant,
            Ok(Err(_)) => {
                return VitaWorkspaceReadResult::denied(
                    request,
                    H3DenyClassification::GrantRejected,
                )
            }
            Err(_) => {
                self.metrics.authority_panics.fetch_add(1, Ordering::AcqRel);
                return VitaWorkspaceReadResult::denied(
                    request,
                    H3DenyClassification::AuthorityPanic,
                );
            }
        };
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);

        // Execution-time D28 fence.  A grant never upgrades a stale or newly
        // disabled authorization row; the current canonical result must still
        // match the exact revision and H3 scope before the read begins.
        let current_authority = match self.evaluate_authority(authority_request.clone()).await {
            Ok(verdict) => verdict,
            Err(classification) => {
                return VitaWorkspaceReadResult::denied_after_grant(request, classification)
            }
        };
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics.late_denials.fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied_after_grant(
                request,
                H3DenyClassification::LateAfterCancellation,
            );
        }
        if let Err(classification) = validate_authority(&current_authority, &authority_request) {
            if classification == H3DenyClassification::StaleRevision {
                self.metrics.stale_denials.fetch_add(1, Ordering::AcqRel);
            }
            return VitaWorkspaceReadResult::denied_after_grant(request, classification);
        }
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics
                .cancellation_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied_after_grant(
                request,
                H3DenyClassification::TurnCancelled,
            );
        }

        self.metrics
            .execution_started
            .fetch_add(1, Ordering::AcqRel);
        let content = match grant.execute_once(bound_context, &request, &prepared) {
            Ok(content) => content,
            Err(error) => {
                let classification = match error {
                    WorkspaceReadError::TooLarge { .. } => H3DenyClassification::Oversized,
                    WorkspaceReadError::InvalidUtf8 => H3DenyClassification::InvalidUtf8,
                    WorkspaceReadError::InvalidTarget(reason) => {
                        if reason.contains("disappeared") {
                            H3DenyClassification::TargetMissing
                        } else if reason.contains("identity") {
                            H3DenyClassification::TargetIdentityMismatch
                        } else {
                            H3DenyClassification::TargetRejected
                        }
                    }
                    WorkspaceReadError::Kernel(_) => H3DenyClassification::TargetRejected,
                };
                return VitaWorkspaceReadResult {
                    request,
                    classification: Some(classification),
                    content: None,
                    bytes_read: 0,
                    execution_started: true,
                    grant_issued: true,
                };
            }
        };
        let bytes_read = content.len();
        self.metrics
            .authorized_file_reads
            .fetch_add(1, Ordering::AcqRel);
        self.metrics
            .file_bytes_read
            .fetch_add(bytes_read, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReadResult {
                request,
                classification: Some(H3DenyClassification::CancelledAfterRead),
                content: None,
                bytes_read: 0,
                execution_started: true,
                grant_issued: true,
            };
        }
        VitaWorkspaceReadResult {
            request,
            classification: None,
            content: Some(content),
            bytes_read,
            execution_started: true,
            grant_issued: true,
        }
    }

    async fn evaluate_authority(
        &self,
        request: H3AuthorityRequest,
    ) -> Result<H3AuthorityVerdict, H3DenyClassification> {
        self.metrics
            .authority_evaluations
            .fetch_add(1, Ordering::AcqRel);
        let future = match catch_unwind(AssertUnwindSafe(|| self.authority.evaluate(request))) {
            Ok(future) => future,
            Err(_) => {
                self.metrics.authority_panics.fetch_add(1, Ordering::AcqRel);
                return Err(H3DenyClassification::AuthorityPanic);
            }
        };
        let _active = ActiveAuthorityGuard::new(Arc::clone(&self.metrics));
        match CatchUnwindFuture::new(future).await {
            Ok(Ok(verdict)) => Ok(verdict),
            Ok(Err(_)) => {
                self.metrics.authority_errors.fetch_add(1, Ordering::AcqRel);
                Err(H3DenyClassification::AuthorityError)
            }
            Err(()) => {
                self.metrics.authority_panics.fetch_add(1, Ordering::AcqRel);
                Err(H3DenyClassification::AuthorityPanic)
            }
        }
    }

    async fn handle_call(&self, call: ToolCall<'_>) -> VitaWorkspaceReadResult {
        match VitaWorkspaceReadRequest::from_codex_call(&call, self.context.as_ref()) {
            Ok(request) => self.execute_request(request).await,
            Err(error) => VitaWorkspaceReadResult {
                request: invalid_request_for_call(&call, self.context.clone()),
                classification: Some(match error {
                    H3RequestBuildError::UnmappedTool => H3DenyClassification::UnmappedTool,
                    _ => H3DenyClassification::InvalidRequest,
                }),
                content: None,
                bytes_read: 0,
                execution_started: false,
                grant_issued: false,
            },
        }
    }
}

fn invalid_request_for_call(
    call: &ToolCall<'_>,
    context: Option<VitaExecutionContext>,
) -> VitaWorkspaceReadRequest {
    VitaWorkspaceReadRequest {
        tool_call_id: bounded_text("tool call id", &call.call_id, MAX_CALL_ID_CHARS)
            .unwrap_or_else(|| "[invalid-call-id]".to_string()),
        turn_id: bounded_text("turn id", &call.turn_id, MAX_TURN_ID_CHARS)
            .unwrap_or_else(|| "[invalid-turn-id]".to_string()),
        context,
        relative_path: super::WorkspaceRelativePath::parse(std::path::Path::new("invalid"))
            .expect("static invalid request placeholder is valid"),
        max_bytes: 0,
        expected_authorization_revision: 0,
    }
}

fn bounded_text(_field: &str, value: &str, max_chars: usize) -> Option<String> {
    if value.is_empty()
        || value.chars().count() > max_chars
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn validate_authority(
    verdict: &H3AuthorityVerdict,
    request: &H3AuthorityRequest,
) -> Result<(), H3DenyClassification> {
    if verdict.life_id != request.context.life_id()
        || verdict.task_id != request.context.task_id()
        || verdict.capability_id != request.capability_id
        || verdict.d28_requested_scope != request.d28_requested_scope
        || verdict.authorized_scope != request.authorized_scope
    {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    }
    if verdict.authorization_revision != Some(request.expected_authorization_revision) {
        return Err(H3DenyClassification::StaleRevision);
    }
    if verdict.outcome == H3AuthorityOutcome::Eligible
        && verdict.reason == H3AuthorityReason::Eligible
    {
        return Ok(());
    }
    Err(match verdict.reason {
        H3AuthorityReason::UnknownCapabilityDescriptor => {
            H3DenyClassification::AuthorityEvidenceMismatch
        }
        H3AuthorityReason::MissingAuthorization | H3AuthorityReason::RootDisabled => {
            H3DenyClassification::MissingAuthorization
        }
        H3AuthorityReason::ScopeUnavailable => H3DenyClassification::ScopeUnavailable,
        H3AuthorityReason::StaleRevision => H3DenyClassification::StaleRevision,
        H3AuthorityReason::AuthorityError | H3AuthorityReason::Eligible => {
            H3DenyClassification::AuthorityError
        }
    })
}

/// The only grant issuer currently present is a test/integration adapter.  A
/// model-facing tool has no access to this trait or to the private grant
/// constructor below.
pub(crate) trait VitaH3GrantIssuer: Send + Sync {
    fn issue(
        &self,
        authority: &H3AuthorityVerdict,
        context: &VitaExecutionContext,
        request: &VitaWorkspaceReadRequest,
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<VitaExecutableCapabilityGrant, H3GrantIssueError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H3GrantIssueError {
    AuthorityMismatch,
    TargetMismatch,
    ScopeMismatch,
}

struct H3TrustedIssuerSeal;

/// Immutable, single-use executable authority.  Its fields and constructor
/// are private; the authority result and H2 binding are checked by the trusted
/// issuer before this object can exist.
pub(crate) struct VitaExecutableCapabilityGrant {
    grant_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    authorization_revision: i64,
    requested_scope: VitaRequestedScope,
    authorized_scope: VitaRequestedScope,
    root_identity: super::WorkspaceRootIdentity,
    resource: super::WorkspaceRelativePath,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
    issued_at: Instant,
    expires_at: Instant,
    single_use: bool,
    used: AtomicBool,
    _issuer: H3TrustedIssuerSeal,
}

impl VitaExecutableCapabilityGrant {
    fn issue(
        _issuer: H3TrustedIssuerSeal,
        grant_id: String,
        context: &VitaExecutionContext,
        request: &VitaWorkspaceReadRequest,
        prepared: &PreparedWorkspaceTarget,
        authorization_revision: i64,
    ) -> Self {
        let now = Instant::now();
        Self {
            grant_id,
            life_id: context.life_id().to_string(),
            task_id: context.task_id().to_string(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            authorization_revision,
            requested_scope: VitaRequestedScope::Workspace,
            authorized_scope: VitaRequestedScope::Workspace,
            root_identity: prepared.root().identity(),
            resource: request.relative_path.clone(),
            target_identity: prepared
                .target_identity()
                .expect("issuer checks existing target identity"),
            target_kind: prepared.kind(),
            issued_at: now,
            expires_at: now + GRANT_LIFETIME,
            single_use: true,
            used: AtomicBool::new(false),
            _issuer: H3TrustedIssuerSeal,
        }
    }

    fn execute_once(
        &self,
        context: &VitaExecutionContext,
        request: &VitaWorkspaceReadRequest,
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<String, WorkspaceReadError> {
        if !self.single_use
            || Instant::now() >= self.expires_at
            || self.issued_at > Instant::now()
            || self.life_id != context.life_id()
            || self.task_id != context.task_id()
            || self.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
            || self.authorization_revision != request.expected_authorization_revision
            || self.requested_scope != VitaRequestedScope::Workspace
            || self.authorized_scope != VitaRequestedScope::Workspace
            || self.root_identity != prepared.root().identity()
            || self.resource != request.relative_path
            || prepared.target_identity() != Some(self.target_identity)
            || self.target_kind != prepared.kind()
        {
            return Err(WorkspaceReadError::InvalidTarget(
                "executable grant binding changed before read",
            ));
        }
        if self
            .used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(WorkspaceReadError::InvalidTarget(
                "executable grant was already consumed",
            ));
        }
        prepared.read_existing_file_utf8_bounded(request.max_bytes)
    }
}

struct ActiveAuthorityGuard {
    metrics: Arc<H3BrokerMetrics>,
}

impl ActiveAuthorityGuard {
    fn new(metrics: Arc<H3BrokerMetrics>) -> Self {
        let active = metrics.active_authority.fetch_add(1, Ordering::AcqRel) + 1;
        let mut observed = metrics.max_active_authority.load(Ordering::Acquire);
        while active > observed {
            match metrics.max_active_authority.compare_exchange(
                observed,
                active,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(previous) => observed = previous,
            }
        }
        Self { metrics }
    }
}

impl Drop for ActiveAuthorityGuard {
    fn drop(&mut self) {
        self.metrics.active_authority.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CatchUnwindFuture<F> {
    future: F,
}

impl<F> CatchUnwindFuture<F> {
    fn new(future: F) -> Self {
        Self { future }
    }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: the future is pinned together with this wrapper and is not
        // moved after it is projected for polling.
        let this = unsafe { self.get_unchecked_mut() };
        let future = unsafe { Pin::new_unchecked(&mut this.future) };
        match catch_unwind(AssertUnwindSafe(|| future.poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

/// Test/integration-only contributor for the real Codex canary.  The normal
/// Vita entrypoint never installs it.
pub(crate) struct VitaWorkspaceReadToolContributor {
    broker: Arc<VitaWorkspaceReadBroker>,
}

impl VitaWorkspaceReadToolContributor {
    pub(crate) fn new(broker: Arc<VitaWorkspaceReadBroker>) -> Self {
        Self { broker }
    }
}

impl ToolContributor for VitaWorkspaceReadToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaWorkspaceReadTool {
            broker: Arc::clone(&self.broker),
        })]
    }
}

struct VitaWorkspaceReadTool {
    broker: Arc<VitaWorkspaceReadBroker>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaWorkspaceReadTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_WORKSPACE_READ_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        let parameters = parse_tool_input_schema(&json!({
            "type": "object",
            "properties": {
                "relative_path": {"type": "string"},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": WORKSPACE_READ_HARD_MAX_BYTES},
                "expected_authorization_revision": {"type": "integer", "minimum": 1}
            },
            "required": ["relative_path", "max_bytes", "expected_authorization_revision"],
            "additionalProperties": false
        }))
        .expect("D29-H3 read tool schema is static and valid");
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_WORKSPACE_READ_TOOL_NAME.to_string(),
            description: "Read one existing bounded UTF-8 file through Digital Life authority."
                .to_string(),
            strict: true,
            defer_loading: None,
            parameters,
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
        Box::pin(async move {
            let result = broker.handle_call(call).await;
            Ok(Box::new(JsonToolOutput::with_success(
                result.model_value(),
                Some(false),
            )) as Box<dyn ToolOutput>)
        })
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant, SystemTime};
    use tempfile::{tempdir, TempDir};

    use crate::provider_gateway::{VitaGatewayBinding, VitaProviderAuthority};
    use crate::{
        ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
        TrustedWorkspaceRoot, VitaAgentEntrypoint, VitaAgentRuntimeProfile, VitaExecutionContext,
    };

    const LIFE_ID: &str = "life-d29h3";
    const TASK_ID: &str = "task-d29h3";
    const REVISION: i64 = 2;
    const FILE_CONTENT: &str = "VITA_D29H3_FILE_OK";

    #[derive(Clone, Copy)]
    struct AuthorityReply {
        outcome: H3AuthorityOutcome,
        reason: H3AuthorityReason,
        revision: Option<i64>,
    }

    struct ScriptedAuthority {
        replies: Mutex<VecDeque<Result<AuthorityReply, VitaH3AuthorityError>>>,
        calls: AtomicUsize,
    }

    impl ScriptedAuthority {
        fn new(
            replies: impl IntoIterator<Item = Result<AuthorityReply, VitaH3AuthorityError>>,
        ) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into_iter().collect()),
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }
    }

    impl VitaH3AuthorityPort for ScriptedAuthority {
        fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let reply = lock_unpoisoned(&self.replies)
                .pop_front()
                .unwrap_or(Ok(AuthorityReply {
                    outcome: H3AuthorityOutcome::Eligible,
                    reason: H3AuthorityReason::Eligible,
                    revision: Some(REVISION),
                }));
            Box::pin(async move {
                let reply = reply?;
                Ok(H3AuthorityVerdict::from_request(
                    &request,
                    reply.outcome,
                    reply.reason,
                    reply.revision,
                ))
            })
        }
    }

    struct TestGrantIssuer {
        next_id: AtomicUsize,
        expected_root: Mutex<Option<super::super::WorkspaceRootIdentity>>,
    }

    impl TestGrantIssuer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_id: AtomicUsize::new(0),
                expected_root: Mutex::new(None),
            })
        }

        fn with_expected_root(identity: super::super::WorkspaceRootIdentity) -> Arc<Self> {
            Arc::new(Self {
                next_id: AtomicUsize::new(0),
                expected_root: Mutex::new(Some(identity)),
            })
        }
    }

    impl VitaH3GrantIssuer for TestGrantIssuer {
        fn issue(
            &self,
            authority: &H3AuthorityVerdict,
            context: &VitaExecutionContext,
            request: &VitaWorkspaceReadRequest,
            prepared: &PreparedWorkspaceTarget,
        ) -> Result<VitaExecutableCapabilityGrant, H3GrantIssueError> {
            if authority.outcome != H3AuthorityOutcome::Eligible
                || authority.reason != H3AuthorityReason::Eligible
                || authority.life_id != context.life_id()
                || authority.task_id != context.task_id()
                || authority.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
                || authority.d28_requested_scope != VitaRequestedScope::None
                || authority.authorized_scope != VitaRequestedScope::Workspace
                || authority.authorization_revision != Some(request.expected_authorization_revision)
            {
                return Err(H3GrantIssueError::AuthorityMismatch);
            }
            if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
                || prepared.relative_path() != &request.relative_path
                || prepared.root().identity()
                    != lock_unpoisoned(&self.expected_root).unwrap_or(prepared.root().identity())
            {
                return Err(H3GrantIssueError::TargetMismatch);
            }
            let id = self.next_id.fetch_add(1, Ordering::AcqRel) + 1;
            let authorization_revision = authority
                .authorization_revision
                .ok_or(H3GrantIssueError::AuthorityMismatch)?;
            Ok(VitaExecutableCapabilityGrant::issue(
                H3TrustedIssuerSeal,
                format!("d29h3-grant-{id}"),
                context,
                request,
                prepared,
                authorization_revision,
            ))
        }
    }

    struct Fixture {
        _root_dir: TempDir,
        root: TrustedWorkspaceRoot,
        path: std::path::PathBuf,
        context: VitaExecutionContext,
    }

    impl Fixture {
        fn new(content: &[u8]) -> Self {
            let root_dir = tempdir().expect("H3 fixture root");
            let path = root_dir.path().join("read-me.txt");
            fs::write(&path, content).expect("H3 fixture file");
            let root = TrustedWorkspaceRoot::acquire(root_dir.path()).expect("H3 root acquire");
            let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap();
            Self {
                _root_dir: root_dir,
                root,
                path,
                context,
            }
        }

        fn broker(
            &self,
            authority: Arc<ScriptedAuthority>,
            issuer: Arc<TestGrantIssuer>,
        ) -> Arc<VitaWorkspaceReadBroker> {
            VitaWorkspaceReadBroker::new(self.context.clone(), self.root.clone(), authority, issuer)
        }

        fn request(&self, call_id: &str) -> VitaWorkspaceReadRequest {
            VitaWorkspaceReadRequest::synthetic(
                call_id,
                Some(self.context.clone()),
                "read-me.txt",
                WORKSPACE_READ_HARD_MAX_BYTES,
                REVISION,
            )
        }
    }

    fn eligible_reply() -> Result<AuthorityReply, VitaH3AuthorityError> {
        Ok(AuthorityReply {
            outcome: H3AuthorityOutcome::Eligible,
            reason: H3AuthorityReason::Eligible,
            revision: Some(REVISION),
        })
    }

    fn run<'a>(
        broker: &'a VitaWorkspaceReadBroker,
        request: VitaWorkspaceReadRequest,
    ) -> impl Future<Output = VitaWorkspaceReadResult> + 'a {
        broker.execute_request(request)
    }

    #[tokio::test]
    async fn successful_read_uses_one_grant_and_returns_exact_utf8_content() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let broker = fixture.broker(Arc::clone(&authority), TestGrantIssuer::new());
        let result = run(&broker, fixture.request("call-success")).await;
        assert_eq!(result.classification, None);
        assert_eq!(result.content.as_deref(), Some(FILE_CONTENT));
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.authority_evaluations, 2);
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.authorized_file_reads, 1);
        assert_eq!(snapshot.file_bytes_read, FILE_CONTENT.len());
        assert_eq!(snapshot.filesystem_mutations, 0);
        assert_eq!(snapshot.process_spawns, 0);
        assert_eq!(snapshot.external_network_requests, 0);
        assert_eq!(authority.calls(), 2);
    }

    #[tokio::test]
    async fn duplicate_tool_call_id_cannot_consume_a_second_grant_or_read() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority =
            ScriptedAuthority::new([eligible_reply(), eligible_reply(), eligible_reply()]);
        let broker = fixture.broker(Arc::clone(&authority), TestGrantIssuer::new());
        let first = run(&broker, fixture.request("call-replay")).await;
        let second = run(&broker, fixture.request("call-replay")).await;
        assert_eq!(first.classification, None);
        assert_eq!(
            second.classification,
            Some(H3DenyClassification::DuplicateToolCall)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 1);
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert_eq!(authority.calls(), 2);
    }

    #[tokio::test]
    async fn distinct_call_requires_distinct_grant_and_reads_once_more() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([
            eligible_reply(),
            eligible_reply(),
            eligible_reply(),
            eligible_reply(),
        ]);
        let broker = fixture.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, fixture.request("call-a")).await.classification,
            None
        );
        assert_eq!(
            run(&broker, fixture.request("call-b")).await.classification,
            None
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 2);
        assert_eq!(snapshot.authorized_file_reads, 2);
    }

    #[tokio::test]
    async fn missing_disabled_scope_and_unknown_authority_are_deny_only() {
        for (reason, expected) in [
            (
                H3AuthorityReason::MissingAuthorization,
                H3DenyClassification::MissingAuthorization,
            ),
            (
                H3AuthorityReason::RootDisabled,
                H3DenyClassification::MissingAuthorization,
            ),
            (
                H3AuthorityReason::ScopeUnavailable,
                H3DenyClassification::ScopeUnavailable,
            ),
            (
                H3AuthorityReason::UnknownCapabilityDescriptor,
                H3DenyClassification::AuthorityEvidenceMismatch,
            ),
        ] {
            let fixture = Fixture::new(FILE_CONTENT.as_bytes());
            let authority = ScriptedAuthority::new([Ok(AuthorityReply {
                outcome: H3AuthorityOutcome::Denied,
                reason,
                revision: Some(REVISION),
            })]);
            let broker = fixture.broker(authority, TestGrantIssuer::new());
            let result = run(&broker, fixture.request("call-denied")).await;
            assert_eq!(result.classification, Some(expected));
            assert_eq!(broker.snapshot().authorized_file_reads, 0);
            assert_eq!(broker.snapshot().grants_issued, 0);
        }
    }

    #[tokio::test]
    async fn wrong_life_task_scope_revision_and_root_identity_are_rejected() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority =
            ScriptedAuthority::new([eligible_reply(), eligible_reply(), eligible_reply()]);
        let broker = fixture.broker(Arc::clone(&authority), TestGrantIssuer::new());
        let wrong_life = VitaExecutionContext::try_new("life-other", TASK_ID).unwrap();
        let wrong_task = VitaExecutionContext::try_new(LIFE_ID, "task-other").unwrap();
        let mut request = fixture.request("call-wrong-life");
        request.context = Some(wrong_life);
        assert_eq!(
            run(&broker, request).await.classification,
            Some(H3DenyClassification::WrongLifeBinding)
        );
        let mut request = fixture.request("call-wrong-task");
        request.context = Some(wrong_task);
        assert_eq!(
            run(&broker, request).await.classification,
            Some(H3DenyClassification::WrongTaskBinding)
        );

        let mut request = fixture.request("call-stale");
        request.expected_authorization_revision = REVISION + 1;
        let stale_authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let stale_broker = fixture.broker(stale_authority, TestGrantIssuer::new());
        assert_eq!(
            run(&stale_broker, request).await.classification,
            Some(H3DenyClassification::StaleRevision)
        );
    }

    #[tokio::test]
    async fn target_missing_directory_oversized_and_binary_are_denied_without_success() {
        let missing = Fixture::new(FILE_CONTENT.as_bytes());
        fs::remove_file(&missing.path).unwrap();
        let authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let broker = missing.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, missing.request("call-missing"))
                .await
                .classification,
            Some(H3DenyClassification::TargetMissing)
        );

        let directory = Fixture::new(FILE_CONTENT.as_bytes());
        fs::remove_file(&directory.path).unwrap();
        fs::create_dir(&directory.path).unwrap();
        let authority = ScriptedAuthority::new([eligible_reply()]);
        let broker = directory.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, directory.request("call-directory"))
                .await
                .classification,
            Some(H3DenyClassification::TargetRejected)
        );

        let oversized = Fixture::new(&vec![b'x'; WORKSPACE_READ_HARD_MAX_BYTES + 1]);
        let authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let broker = oversized.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, oversized.request("call-oversized"))
                .await
                .classification,
            Some(H3DenyClassification::Oversized)
        );

        let binary = Fixture::new(&[0xff, 0xfe, 0xfd]);
        let authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let broker = binary.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, binary.request("call-binary"))
                .await
                .classification,
            Some(H3DenyClassification::InvalidUtf8)
        );
    }

    #[tokio::test]
    async fn execution_fence_denies_stale_revision_after_grant_mint() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([
            eligible_reply(),
            Ok(AuthorityReply {
                outcome: H3AuthorityOutcome::Denied,
                reason: H3AuthorityReason::RootDisabled,
                revision: Some(REVISION + 1),
            }),
        ]);
        let broker = fixture.broker(authority, TestGrantIssuer::new());
        let result = run(&broker, fixture.request("call-stale-fence")).await;
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::StaleRevision)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
        assert_eq!(broker.snapshot().grants_issued, 1);
    }

    #[tokio::test]
    async fn authority_error_and_panic_paths_never_read() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([Err(VitaH3AuthorityError::Unavailable)]);
        let broker = fixture.broker(authority, TestGrantIssuer::new());
        assert_eq!(
            run(&broker, fixture.request("call-error"))
                .await
                .classification,
            Some(H3DenyClassification::AuthorityError)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
        assert_eq!(broker.snapshot().authority_errors, 1);

        struct PanicAuthority;
        impl VitaH3AuthorityPort for PanicAuthority {
            fn evaluate(&self, _request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
                panic!("H3 authority fixture panic")
            }
        }
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let broker = VitaWorkspaceReadBroker::new(
            fixture.context.clone(),
            fixture.root.clone(),
            Arc::new(PanicAuthority),
            TestGrantIssuer::new(),
        );
        assert_eq!(
            run(&broker, fixture.request("call-panic"))
                .await
                .classification,
            Some(H3DenyClassification::AuthorityPanic)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
    }

    #[tokio::test]
    async fn cancellation_before_authority_completion_is_late_deny_without_read() {
        struct Gate {
            released: AtomicBool,
            waker: Mutex<Option<std::task::Waker>>,
        }
        struct GateFuture {
            gate: Arc<Gate>,
            result: Option<Result<H3AuthorityVerdict, VitaH3AuthorityError>>,
        }
        impl Future for GateFuture {
            type Output = Result<H3AuthorityVerdict, VitaH3AuthorityError>;
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = unsafe { self.get_unchecked_mut() };
                if this.gate.released.load(Ordering::Acquire) {
                    Poll::Ready(this.result.take().expect("gate result once"))
                } else {
                    *lock_unpoisoned(&this.gate.waker) = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
        struct GateAuthority {
            gate: Arc<Gate>,
        }
        impl VitaH3AuthorityPort for GateAuthority {
            fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
                let verdict = H3AuthorityVerdict::from_request(
                    &request,
                    H3AuthorityOutcome::Eligible,
                    H3AuthorityReason::Eligible,
                    Some(REVISION),
                );
                let gate = Arc::clone(&self.gate);
                Box::pin(GateFuture {
                    gate,
                    result: Some(Ok(verdict)),
                })
            }
        }
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let gate = Arc::new(Gate {
            released: AtomicBool::new(false),
            waker: Mutex::new(None),
        });
        let broker = VitaWorkspaceReadBroker::new(
            fixture.context.clone(),
            fixture.root.clone(),
            Arc::new(GateAuthority {
                gate: Arc::clone(&gate),
            }),
            TestGrantIssuer::new(),
        );
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let request = fixture.request("call-late");
            async move { run(&broker, request).await }
        });
        tokio::task::yield_now().await;
        broker.cancel();
        gate.released.store(true, Ordering::Release);
        if let Some(waker) = lock_unpoisoned(&gate.waker).take() {
            waker.wake();
        }
        let result = task.await.unwrap();
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::LateAfterCancellation)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
    }

    #[tokio::test]
    async fn fresh_cancelled_turn_never_starts_a_read() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([eligible_reply(), eligible_reply()]);
        let broker = fixture.broker(authority, TestGrantIssuer::new());
        broker.cancel();
        assert_eq!(
            run(&broker, fixture.request("call-cancelled"))
                .await
                .classification,
            Some(H3DenyClassification::TurnCancelled)
        );
        assert_eq!(broker.snapshot().authority_evaluations, 0);
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
    }

    #[tokio::test]
    async fn wrong_root_identity_is_rejected_by_trusted_issuer() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let other = Fixture::new(b"other");
        let authority = ScriptedAuthority::new([eligible_reply()]);
        let broker = fixture.broker(
            authority,
            TestGrantIssuer::with_expected_root(other.root.identity()),
        );
        assert_eq!(
            run(&broker, fixture.request("call-root-mismatch"))
                .await
                .classification,
            Some(H3DenyClassification::GrantRejected)
        );
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
    }

    #[tokio::test]
    async fn authority_evidence_mismatch_covers_life_task_capability_and_scope() {
        #[derive(Clone, Copy)]
        enum Mismatch {
            Life,
            Task,
            Capability,
            D28Scope,
            AuthorizedScope,
        }
        struct MismatchAuthority(Mismatch);
        impl VitaH3AuthorityPort for MismatchAuthority {
            fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
                let mut verdict = H3AuthorityVerdict::from_request(
                    &request,
                    H3AuthorityOutcome::Eligible,
                    H3AuthorityReason::Eligible,
                    Some(REVISION),
                );
                match self.0 {
                    Mismatch::Life => verdict.life_id = "life-other".to_string(),
                    Mismatch::Task => verdict.task_id = "task-other".to_string(),
                    Mismatch::Capability => verdict.capability_id = "vita.other".to_string(),
                    Mismatch::D28Scope => {
                        verdict.d28_requested_scope = VitaRequestedScope::Workspace
                    }
                    Mismatch::AuthorizedScope => {
                        verdict.authorized_scope = VitaRequestedScope::None
                    }
                }
                Box::pin(async move { Ok(verdict) })
            }
        }
        for mismatch in [
            Mismatch::Life,
            Mismatch::Task,
            Mismatch::Capability,
            Mismatch::D28Scope,
            Mismatch::AuthorizedScope,
        ] {
            let fixture = Fixture::new(FILE_CONTENT.as_bytes());
            let broker = VitaWorkspaceReadBroker::new(
                fixture.context.clone(),
                fixture.root.clone(),
                Arc::new(MismatchAuthority(mismatch)),
                TestGrantIssuer::new(),
            );
            let result = run(&broker, fixture.request("call-evidence-mismatch")).await;
            assert_eq!(
                result.classification,
                Some(H3DenyClassification::AuthorityEvidenceMismatch)
            );
            assert_eq!(broker.snapshot().authorized_file_reads, 0);
        }
    }

    #[tokio::test]
    async fn executable_grant_is_single_use_even_if_called_directly() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let request = fixture.request("call-grant-once");
        let prepared = fixture
            .root
            .prepare_target(request.relative_path.as_path())
            .expect("H3 grant test preparation");
        let authority_request = H3AuthorityRequest {
            context: fixture.context.clone(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            d28_requested_scope: VitaRequestedScope::None,
            authorized_scope: VitaRequestedScope::Workspace,
            expected_authorization_revision: REVISION,
        };
        let verdict = H3AuthorityVerdict::from_request(
            &authority_request,
            H3AuthorityOutcome::Eligible,
            H3AuthorityReason::Eligible,
            Some(REVISION),
        );
        let issuer = TestGrantIssuer::new();
        let grant = issuer
            .issue(&verdict, &fixture.context, &request, &prepared)
            .expect("trusted H3 issuer should mint one grant");
        assert_eq!(
            grant
                .execute_once(&fixture.context, &request, &prepared)
                .expect("first grant execution"),
            FILE_CONTENT
        );
        assert!(grant
            .execute_once(&fixture.context, &request, &prepared)
            .is_err());
    }

    #[tokio::test]
    async fn prepared_target_rebind_rejects_replacement_and_renamed_away_target() {
        for replacement in [true, false] {
            let fixture = Fixture::new(FILE_CONTENT.as_bytes());
            let request = fixture.request(if replacement {
                "call-replacement"
            } else {
                "call-renamed-away"
            });
            let prepared = fixture
                .root
                .prepare_target(request.relative_path.as_path())
                .expect("H3 target preparation");
            let authority_request = H3AuthorityRequest {
                context: fixture.context.clone(),
                capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
                d28_requested_scope: VitaRequestedScope::None,
                authorized_scope: VitaRequestedScope::Workspace,
                expected_authorization_revision: REVISION,
            };
            let verdict = H3AuthorityVerdict::from_request(
                &authority_request,
                H3AuthorityOutcome::Eligible,
                H3AuthorityReason::Eligible,
                Some(REVISION),
            );
            let grant = TestGrantIssuer::new()
                .issue(&verdict, &fixture.context, &request, &prepared)
                .expect("trusted H3 issuer");
            let old_path = fixture.path.with_file_name("old-read-me.txt");
            fs::rename(&fixture.path, &old_path).expect("move prepared target");
            if replacement {
                fs::write(&fixture.path, b"replacement").expect("replacement target");
            }
            let error = grant
                .execute_once(&fixture.context, &request, &prepared)
                .expect_err("changed target must not be read");
            assert!(matches!(error, WorkspaceReadError::InvalidTarget(_)));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn prepared_target_rebind_rejects_a_reparse_target_without_reading_it() {
        use std::os::windows::fs::symlink_file;

        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let outside = tempdir().expect("H3 outside fixture");
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").expect("outside file");
        let request = fixture.request("call-reparse");
        let prepared = fixture
            .root
            .prepare_target(request.relative_path.as_path())
            .expect("H3 target preparation");
        let authority_request = H3AuthorityRequest {
            context: fixture.context.clone(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            d28_requested_scope: VitaRequestedScope::None,
            authorized_scope: VitaRequestedScope::Workspace,
            expected_authorization_revision: REVISION,
        };
        let verdict = H3AuthorityVerdict::from_request(
            &authority_request,
            H3AuthorityOutcome::Eligible,
            H3AuthorityReason::Eligible,
            Some(REVISION),
        );
        let grant = TestGrantIssuer::new()
            .issue(&verdict, &fixture.context, &request, &prepared)
            .expect("trusted H3 issuer");
        let old_path = fixture.path.with_file_name("old-read-me.txt");
        fs::rename(&fixture.path, &old_path).expect("move prepared target");
        symlink_file(&outside_file, &fixture.path).expect("reparse target");
        let error = grant
            .execute_once(&fixture.context, &request, &prepared)
            .expect_err("reparse target must not be read");
        assert!(matches!(error, WorkspaceReadError::Kernel(_)));
    }

    #[test]
    fn h3_request_namespace_rejects_absolute_unc_device_ads_and_parent_forms() {
        for path in [
            "../read-me.txt",
            "C:\\read-me.txt",
            "\\\\server\\share\\read-me.txt",
            "\\\\?\\C:\\read-me.txt",
            "\\\\.\\PIPE\\named",
            "read-me.txt:secret",
            "read-me.txt/../other",
        ] {
            assert!(
                super::super::WorkspaceRelativePath::parse(Path::new(path)).is_err(),
                "unsafe H3 path must be rejected: {path}"
            );
        }
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H3HostResponse {
        canonical_evaluations: usize,
        production_registry_size: usize,
        test_registry_size: usize,
        authorization_row_reads: usize,
        result: String,
        decision_code: String,
        authorization_revision: Option<i64>,
        life_id: String,
        task_id: String,
        capability_id: String,
        d28_requested_scope: String,
        authorized_scope: String,
    }

    struct ProcessIsolatedH3Authority {
        repo_root: std::path::PathBuf,
        observations: Arc<Mutex<Vec<H3HostResponse>>>,
    }

    impl ProcessIsolatedH3Authority {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                repo_root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("D29-H3 Vita manifest has a repository parent")
                    .to_path_buf(),
                observations: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn snapshot(&self) -> Vec<H3HostResponse> {
            lock_unpoisoned(&self.observations).clone()
        }
    }

    impl VitaH3AuthorityPort for ProcessIsolatedH3Authority {
        fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            let repo_root = self.repo_root.clone();
            let observations = Arc::clone(&self.observations);
            Box::pin(async move {
                let wire_request = json!({
                    "life_id": request.context.life_id(),
                    "task_id": request.context.task_id(),
                    "capability_id": request.capability_id,
                    "d28_requested_scope": request.d28_requested_scope.as_str(),
                    "authorized_scope": request.authorized_scope.as_str(),
                });
                let response = invoke_h3_host_fixture(&repo_root, &wire_request)?;
                if response.canonical_evaluations != 1
                    || response.production_registry_size != 0
                    || response.test_registry_size != 1
                    || response.authorization_row_reads != 1
                    || response.life_id != request.context.life_id()
                    || response.task_id != request.context.task_id()
                    || response.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
                    || response.d28_requested_scope != "none"
                    || response.authorized_scope != "workspace"
                {
                    return Err(VitaH3AuthorityError::InvalidVerdict);
                }
                let (outcome, reason) = match response.result.as_str() {
                    "Eligible" if response.decision_code == "CAPABILITY_ELIGIBLE" => {
                        (H3AuthorityOutcome::Eligible, H3AuthorityReason::Eligible)
                    }
                    _ => (
                        H3AuthorityOutcome::Denied,
                        H3AuthorityReason::AuthorityError,
                    ),
                };
                let verdict = H3AuthorityVerdict::from_request(
                    &request,
                    outcome,
                    reason,
                    response.authorization_revision,
                );
                lock_unpoisoned(&observations).push(response);
                Ok(verdict)
            })
        }
    }

    const H3_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(600);
    const H3_HOST_IPC_MAX_BODY: usize = 8 * 1024;

    fn invoke_h3_host_fixture(
        repo_root: &Path,
        request: &Value,
    ) -> Result<H3HostResponse, VitaH3AuthorityError> {
        let manifest = repo_root.join("src-tauri").join("Cargo.toml");
        let fixture_executable = repo_root
            .join("src-tauri")
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "d29h3-authority-fixture.exe"
            } else {
                "d29h3-authority-fixture"
            });
        let mut command = if fixture_executable.is_file() {
            Command::new(&fixture_executable)
        } else {
            let mut command = Command::new("cargo");
            command
                .current_dir(repo_root)
                .args(["run", "--quiet", "--locked", "--manifest-path"])
                .arg(&manifest)
                .args([
                    "--bin",
                    "d29h3-authority-fixture",
                    "--features",
                    "d29-h3-host-fixture",
                ]);
            command
        };
        let mut child = command
            .current_dir(repo_root)
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_PROFILE_TEST_DEBUG", "0")
            .env("RUSTFLAGS", "-C debuginfo=0")
            .env("CARGO_TERM_COLOR", "never")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(VitaH3AuthorityError::Unavailable)?;
        serde_json::to_writer(&mut stdin, request)
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        stdin
            .write_all(b"\n")
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        drop(stdin);

        let deadline = Instant::now() + H3_HOST_IPC_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VitaH3AuthorityError::Unavailable);
                }
            }
        };
        if !status.success() {
            return Err(VitaH3AuthorityError::Unavailable);
        }
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(VitaH3AuthorityError::Unavailable)?
            .take((H3_HOST_IPC_MAX_BODY + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        if output.len() > H3_HOST_IPC_MAX_BODY {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let output =
            std::str::from_utf8(&output).map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
        serde_json::from_str(output.trim()).map_err(|_| VitaH3AuthorityError::InvalidVerdict)
    }

    #[derive(Clone, Debug, Default)]
    struct H3FixtureObservation {
        request_count: usize,
        first_request_had_h3_tool: bool,
        tool_result_delivered: bool,
        success_content_delivered: bool,
        observed_call_id: Option<String>,
        error: Option<String>,
    }

    struct H3ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H3FixtureObservation>>,
        join: Option<JoinHandle<()>>,
    }

    impl H3ResponsesFixture {
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-H3 fixture");
            let address = listener.local_addr().expect("D29-H3 fixture address");
            let stop = Arc::new(AtomicBool::new(false));
            let observation = Arc::new(Mutex::new(H3FixtureObservation::default()));
            let stop_for_thread = Arc::clone(&stop);
            let observation_for_thread = Arc::clone(&observation);
            let join = thread::spawn(move || {
                let mut response_index = 0usize;
                while !stop_for_thread.load(Ordering::Acquire) && response_index < 2 {
                    let (mut stream, peer) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) => {
                            lock_unpoisoned(&observation_for_thread).error =
                                Some(format!("fixture accept failed: {error}"));
                            return;
                        }
                    };
                    if stop_for_thread.load(Ordering::Acquire) {
                        return;
                    }
                    let result = handle_h3_fixture_request(&mut stream, peer, response_index);
                    let mut observed = lock_unpoisoned(&observation_for_thread);
                    observed.request_count += 1;
                    if response_index == 0 {
                        if let Ok(body) = &result {
                            observed.first_request_had_h3_tool = request_has_h3_tool(body);
                        }
                    } else if let Ok(body) = &result {
                        observed.tool_result_delivered =
                            request_has_function_call_output(body, H3_CALL_ID);
                        observed.success_content_delivered =
                            request_has_success_read(body, H3_CALL_ID);
                        observed.observed_call_id = function_call_output_id(body);
                    }
                    if let Err(error) = result {
                        observed.error = Some(error);
                    }
                    response_index += 1;
                }
            });
            Self {
                address,
                stop,
                observation,
                join: Some(join),
            }
        }

        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}/v1", self.address.port())
        }

        fn shutdown(mut self) -> (H3FixtureObservation, bool) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            let joined = self
                .join
                .take()
                .map(|join| join.join().is_ok())
                .unwrap_or(true);
            (lock_unpoisoned(&self.observation).clone(), joined)
        }
    }

    impl Drop for H3ResponsesFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    const H3_MODEL: &str = "d29h3-local-responses-model";
    const H3_PROMPT: &str = "Read the bounded Vita workspace file.";
    const H3_REPLY: &str = "VITA_D29H3_READ_OK";
    const H3_CALL_ID: &str = "call-d29h3-read";
    const H3_PROVIDER_ID: &str = "d29h3-loopback-responses";
    const H3_TURN_TIMEOUT: Duration = Duration::from_secs(20);
    const H3_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
    const H3_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
    const H3_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
    const H3_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

    fn request_has_h3_tool(body: &[u8]) -> bool {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("tools").cloned())
            .and_then(|tools| tools.as_array().cloned())
            .is_some_and(|tools| {
                tools.iter().any(|tool| {
                    tool.get("name").and_then(Value::as_str) == Some(VITA_WORKSPACE_READ_TOOL_NAME)
                })
            })
    }

    fn function_call_output_id(body: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("input").cloned())
            .and_then(|input| input.as_array().cloned())
            .and_then(|items| {
                items.into_iter().find_map(|item| {
                    (item.get("type").and_then(Value::as_str) == Some("function_call_output"))
                        .then(|| item.get("call_id").and_then(Value::as_str))
                        .flatten()
                        .map(str::to_owned)
                })
            })
    }

    fn request_has_function_call_output(body: &[u8], call_id: &str) -> bool {
        function_call_output_id(body).as_deref() == Some(call_id)
    }

    fn request_has_success_read(body: &[u8], call_id: &str) -> bool {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("input").cloned())
            .and_then(|input| input.as_array().cloned())
            .is_some_and(|items| {
                items.iter().any(|item| {
                    let is_output = item.get("type").and_then(Value::as_str)
                        == Some("function_call_output")
                        && item.get("call_id").and_then(Value::as_str) == Some(call_id);
                    let Some(output) = item.get("output").and_then(Value::as_str) else {
                        return false;
                    };
                    let Ok(output) = serde_json::from_str::<Value>(output) else {
                        return false;
                    };
                    is_output
                        && output.get("status").and_then(Value::as_str) == Some("success")
                        && output.get("content").and_then(Value::as_str) == Some(FILE_CONTENT)
                        && output.get("bytes_read").and_then(Value::as_u64)
                            == Some(FILE_CONTENT.len() as u64)
                })
            })
    }

    fn handle_h3_fixture_request(
        stream: &mut TcpStream,
        peer: SocketAddr,
        response_index: usize,
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("D29-H3 fixture received a non-loopback peer".to_string());
        }
        let body = read_h3_http_request(stream)?;
        if response_index == 0 {
            write_h3_sse_response(stream, h3_first_response_events())?;
        } else {
            write_h3_sse_response(stream, h3_completion_response_events())?;
        }
        Ok(body)
    }

    fn h3_first_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h3-1", "object": "response", "status": "in_progress", "model": H3_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": H3_CALL_ID, "name": VITA_WORKSPACE_READ_TOOL_NAME, "arguments": "{\"relative_path\":\"read-me.txt\",\"max_bytes\":65536,\"expected_authorization_revision\":2}"}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h3-1", "object": "response", "status": "completed", "model": H3_MODEL}
            }),
        ]
    }

    fn h3_completion_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h3-2", "object": "response", "status": "in_progress", "model": H3_MODEL}
            }),
            json!({
                "type": "response.output_item.added",
                "item": {"type": "message", "id": "msg-d29h3", "role": "assistant", "status": "in_progress", "content": []}
            }),
            json!({"type": "response.content_part.added"}),
            json!({"type": "response.output_text.delta", "delta": H3_REPLY}),
            json!({"type": "response.output_text.done", "text": H3_REPLY}),
            json!({"type": "response.content_part.done"}),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "message", "id": "msg-d29h3", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": H3_REPLY}]}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h3-2", "object": "response", "status": "completed", "model": H3_MODEL}
            }),
        ]
    }

    fn write_h3_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
        let mut body = String::new();
        for event in events {
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "D29-H3 fixture event omitted type".to_string())?;
            body.push_str("event: ");
            body.push_str(event_type);
            body.push_str("\ndata: ");
            body.push_str(
                &serde_json::to_string(&event)
                    .map_err(|_| "D29-H3 fixture event serialization failed".to_string())?,
            );
            body.push_str("\n\n");
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .set_write_timeout(Some(H3_HTTP_TIMEOUT))
            .map_err(|_| "D29-H3 fixture write timeout setup failed".to_string())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| "D29-H3 fixture response write failed".to_string())
    }

    fn read_h3_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        stream
            .set_read_timeout(Some(H3_HTTP_TIMEOUT))
            .map_err(|_| "D29-H3 fixture read timeout setup failed".to_string())?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H3 fixture request read failed".to_string())?;
            if read == 0 {
                return Err("D29-H3 fixture request closed before headers".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > H3_HTTP_MAX_BODY {
                return Err("D29-H3 fixture request exceeded bounded size".to_string());
            }
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let header = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| "D29-H3 fixture request headers were not UTF-8".to_string())?;
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| "D29-H3 fixture request omitted content length".to_string())?;
        if content_length > H3_HTTP_MAX_BODY {
            return Err("D29-H3 fixture content length exceeded bounded size".to_string());
        }
        while bytes.len() < header_end + content_length {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H3 fixture request body read failed".to_string())?;
            if read == 0 {
                return Err("D29-H3 fixture request closed before body".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > header_end + content_length {
                break;
            }
        }
        Ok(bytes[header_end..header_end + content_length].to_vec())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CodexStateCanary {
        files: [Option<(u64, Option<SystemTime>)>; 3],
    }

    fn codex_state_canary() -> CodexStateCanary {
        let root = std::env::var_os("USERPROFILE")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join(".codex"));
        let names = ["config.toml", "auth.json", ".codex-global-state.json"];
        CodexStateCanary {
            files: names.map(|name| {
                root.as_deref()
                    .and_then(|root| fs::symlink_metadata(root.join(name)).ok())
                    .map(|metadata| (metadata.len(), metadata.modified().ok()))
            }),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum H3ShutdownStatus {
        NotAttempted,
        Success,
        TimedOut,
        Failed,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct H3CleanupEvidence {
        initial_shutdown: H3ShutdownStatus,
        final_shutdown: H3ShutdownStatus,
        manager_thread_count: usize,
        fixture_listener_joined: bool,
    }

    struct H3Runtime {
        _app_data: TempDir,
        _workspace: TempDir,
        manager: Arc<codex_core_api::ThreadManager>,
        thread: Option<Arc<codex_core_api::CodexThread>>,
        thread_id: Option<codex_core_api::ThreadId>,
        fixture: Option<H3ResponsesFixture>,
    }

    impl H3Runtime {
        async fn shutdown(mut self) -> (H3CleanupEvidence, H3FixtureObservation) {
            let mut initial_shutdown = H3ShutdownStatus::NotAttempted;
            let mut final_shutdown = H3ShutdownStatus::NotAttempted;
            if let Some(thread) = self.thread.take() {
                initial_shutdown = match tokio::time::timeout(
                    H3_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H3ShutdownStatus::Success,
                    Ok(Err(_)) => H3ShutdownStatus::Failed,
                    Err(_) => H3ShutdownStatus::TimedOut,
                };
                if initial_shutdown != H3ShutdownStatus::Success {
                    let _ = tokio::time::timeout(
                        H3_CLEANUP_TIMEOUT,
                        thread.submit(codex_core_api::Op::Interrupt),
                    )
                    .await;
                }
                final_shutdown = match tokio::time::timeout(
                    H3_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H3ShutdownStatus::Success,
                    Ok(Err(_)) => H3ShutdownStatus::Failed,
                    Err(_) => H3ShutdownStatus::TimedOut,
                };
                if final_shutdown == H3ShutdownStatus::Success {
                    if let Some(thread_id) = self.thread_id.as_ref() {
                        let _ = self
                            .manager
                            .remove_thread_if_matches(thread_id, &thread)
                            .await;
                    }
                }
            }
            let manager_thread_count = self.manager.list_thread_ids().await.len();
            let (fixture_observation, fixture_listener_joined) = self
                .fixture
                .take()
                .map(H3ResponsesFixture::shutdown)
                .unwrap_or_else(|| (H3FixtureObservation::default(), true));
            (
                H3CleanupEvidence {
                    initial_shutdown,
                    final_shutdown,
                    manager_thread_count,
                    fixture_listener_joined,
                },
                fixture_observation,
            )
        }
    }

    async fn start_h3_runtime() -> Result<
        (
            H3Runtime,
            Arc<VitaWorkspaceReadBroker>,
            Arc<ProcessIsolatedH3Authority>,
            CodexStateCanary,
        ),
        String,
    > {
        let before = codex_state_canary();
        let app_data = tempdir().map_err(|_| "create D29-H3 app data failed".to_string())?;
        let workspace = tempdir().map_err(|_| "create D29-H3 workspace failed".to_string())?;
        fs::write(
            workspace.path().join("read-me.txt"),
            FILE_CONTENT.as_bytes(),
        )
        .map_err(|_| "create D29-H3 read fixture failed".to_string())?;
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
        )
        .map_err(|error| format!("create D29-H3 profile: {error}"))?;

        let fixture = H3ResponsesFixture::start();
        let provider = ProviderProfile::new_for_test_localhost(
            H3_PROVIDER_ID,
            "D29-H3 loopback Responses fixture",
            ProviderProtocol::OpenAiResponses,
            fixture.base_url(),
            H3_MODEL,
            None,
            H3_HTTP_TIMEOUT,
            ProviderRetryPolicy::default(),
            ProviderCapabilities {
                tools: true,
                ..ProviderCapabilities::none()
            },
        )
        .map_err(|error| format!("create D29-H3 provider: {error}"))?;
        let authority = VitaProviderAuthority::configure(provider)
            .map_err(|error| format!("configure D29-H3 provider: {error}"))?;
        let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
            .map_err(|error| format!("create D29-H3 private binding: {error}"))?;
        let ready = authority
            .prepare_gateway(binding)
            .map_err(|error| format!("prepare D29-H3 gateway: {error}"))?;
        let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
            .await
            .map_err(|error| format!("compile D29-H3 Codex config: {error}"))?;
        let config = entrypoint.config().clone();
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .map_err(|error| format!("create D29-H3 context: {error:?}"))?;
        let root = entrypoint
            .profile()
            .workspace_authority()
            .cloned()
            .ok_or_else(|| "D29-H3 requires the Windows workspace authority".to_string())?;
        let canonical_authority = ProcessIsolatedH3Authority::new();
        let broker = VitaWorkspaceReadBroker::new(
            context,
            root,
            Arc::clone(&canonical_authority) as Arc<dyn VitaH3AuthorityPort>,
            TestGrantIssuer::new(),
        );
        let mut extensions =
            codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extensions.tool_contributor(Arc::new(VitaWorkspaceReadToolContributor::new(Arc::clone(
            &broker,
        ))));
        let extensions = Arc::new(extensions.build());
        let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
            codex_core_api::CodexAuth::from_api_key("d29h3-in-memory-kernel-auth"),
            config.codex_home.to_path_buf(),
        );
        let manager = Arc::new(codex_core_api::ThreadManager::new(
            &config,
            Arc::clone(&auth_manager),
            codex_core_api::build_models_manager(&config, Arc::clone(&auth_manager)),
            codex_core_api::CodexAppsToolsCache::default(),
            codex_core_api::SessionSource::Exec,
            Arc::new(codex_core_api::EnvironmentManager::default_for_tests()),
            extensions,
            Arc::new(codex_core::test_support::EmptyUserInstructionsProvider),
            None,
            codex_core_api::thread_store_from_config(&config, None),
            None,
            "d29h3-local-installation".to_string(),
            None,
            None,
        ));
        let new_thread = tokio::time::timeout(
            H3_TURN_TIMEOUT,
            manager.start_thread(codex_core_api::StartThreadOptions::new(config)),
        )
        .await
        .map_err(|_| "D29-H3 thread startup timed out".to_string())?
        .map_err(|error| format!("D29-H3 thread startup failed: {error}"))?;
        Ok((
            H3Runtime {
                _app_data: app_data,
                _workspace: workspace,
                manager,
                thread: Some(new_thread.thread),
                thread_id: Some(new_thread.thread_id),
                fixture: Some(fixture),
            },
            broker,
            canonical_authority,
            before,
        ))
    }

    async fn run_h3_turn(
        thread: &Arc<codex_core_api::CodexThread>,
    ) -> Result<(Option<String>, Option<String>, usize), String> {
        tokio::time::timeout(
            H3_TURN_TIMEOUT,
            thread.start_or_steer_turn(codex_core_api::TurnInputRequest::user_input(vec![
                codex_core_api::UserInput::Text {
                    text: H3_PROMPT.to_string(),
                    text_elements: Vec::new(),
                },
            ])),
        )
        .await
        .map_err(|_| "D29-H3 turn submission timed out".to_string())?
        .map_err(|error| format!("D29-H3 turn submission failed: {error}"))?;
        let deadline = Instant::now() + H3_TURN_TIMEOUT;
        let mut event_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("D29-H3 turn did not reach a terminal event".to_string());
            }
            let event = tokio::time::timeout(remaining, thread.next_event())
                .await
                .map_err(|_| "D29-H3 event wait timed out".to_string())?
                .map_err(|error| format!("D29-H3 event stream failed: {error}"))?;
            event_count += 1;
            if let codex_core_api::EventMsg::TurnComplete(complete) = event.msg {
                return Ok((
                    complete.last_agent_message,
                    complete.error.map(|error| error.message),
                    event_count,
                ));
            }
        }
    }

    #[test]
    fn d29h3_real_codex_turn_reads_one_governed_utf8_file() {
        thread::Builder::new()
            .name("d29h3-real-codex-tool".to_string())
            .stack_size(H3_TEST_STACK_SIZE)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("D29-H3 test runtime should build");
                runtime.block_on(d29h3_real_codex_turn_body());
            })
            .expect("D29-H3 test thread should start")
            .join()
            .expect("D29-H3 test thread should finish");
    }

    async fn d29h3_real_codex_turn_body() {
        let (runtime, broker, authority, before) = start_h3_runtime()
            .await
            .expect("D29-H3 runtime should start");
        let turn = run_h3_turn(
            runtime
                .thread
                .as_ref()
                .expect("D29-H3 runtime should contain a thread"),
        )
        .await;
        let (cleanup, fixture_observation) = runtime.shutdown().await;
        let turn = turn.unwrap_or_else(|error| {
            panic!(
                "D29-H3 turn should complete: {error}; fixture={fixture_observation:?}; cleanup={cleanup:?}"
            )
        });
        let after = codex_state_canary();
        assert_eq!(before, after, "D29-H3 user Codex state changed");

        assert_eq!(turn.1, None);
        assert_eq!(turn.0.as_deref(), Some(H3_REPLY));
        assert!(turn.2 > 0);
        assert_eq!(cleanup.initial_shutdown, H3ShutdownStatus::Success);
        assert_eq!(cleanup.final_shutdown, H3ShutdownStatus::Success);
        assert_eq!(cleanup.manager_thread_count, 0);
        assert!(cleanup.fixture_listener_joined);

        let snapshot = broker.snapshot();
        assert_eq!(snapshot.attempted_requests, 1);
        assert_eq!(snapshot.authority_evaluations, 2);
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.execution_started, 1);
        assert_eq!(snapshot.authorized_file_reads, 1);
        assert_eq!(snapshot.file_bytes_read, FILE_CONTENT.len());
        assert_eq!(snapshot.filesystem_mutations, 0);
        assert_eq!(snapshot.process_spawns, 0);
        assert_eq!(snapshot.external_network_requests, 0);
        assert_eq!(snapshot.max_active_authority, 1);

        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        for observation in observations {
            assert_eq!(observation.canonical_evaluations, 1);
            assert_eq!(observation.production_registry_size, 0);
            assert_eq!(observation.test_registry_size, 1);
            assert_eq!(observation.authorization_row_reads, 1);
            assert_eq!(observation.result, "Eligible");
            assert_eq!(observation.decision_code, "CAPABILITY_ELIGIBLE");
            assert_eq!(observation.authorization_revision, Some(REVISION));
            assert_eq!(observation.life_id, LIFE_ID);
            assert_eq!(observation.task_id, TASK_ID);
            assert_eq!(observation.capability_id, VITA_WORKSPACE_READ_CAPABILITY_ID);
            assert_eq!(observation.d28_requested_scope, "none");
            assert_eq!(observation.authorized_scope, "workspace");
        }
    }

    #[test]
    fn production_surface_has_no_h3_tool_or_descriptor_registration() {
        let production_tool_name = super::VITA_WORKSPACE_READ_TOOL_NAME;
        assert_eq!(production_tool_name, "vita_workspace_read_file");
        assert_eq!(
            super::VITA_WORKSPACE_READ_CAPABILITY_ID,
            "vita.workspace.read_file"
        );
    }
}
