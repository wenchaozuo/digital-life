//! D29-H3's first governed bounded workspace read.
//!
//! The executable path in this module is deliberately crate-private and is
//! not installed by the normal Vita entrypoint.  The model can request a
//! relative resource, but it cannot select a capability, mint a grant, or
//! supply authority evidence.  A bounded Host-scoped evidence response is
//! required before the private local execution object can exist.
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
const MAX_SEEN_CALL_IDS: usize = 256;
const GRANT_LIFETIME: Duration = Duration::from_secs(30);
const MAX_HOST_CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct VitaWorkspaceReadRequest {
    tool_call_id: String,
    turn_id: String,
    context: Option<VitaExecutionContext>,
    relative_path: super::WorkspaceRelativePath,
    max_bytes: usize,
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
        Ok(Self {
            tool_call_id,
            turn_id,
            context: context.cloned(),
            relative_path,
            max_bytes,
        })
    }

    #[cfg(test)]
    fn synthetic(
        tool_call_id: &str,
        context: Option<VitaExecutionContext>,
        relative_path: &str,
        max_bytes: usize,
    ) -> Self {
        Self {
            tool_call_id: tool_call_id.to_string(),
            turn_id: "turn-d29h3".to_string(),
            context,
            relative_path: super::WorkspaceRelativePath::parse(std::path::Path::new(relative_path))
                .expect("synthetic H3 path must be valid"),
            max_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VitaWorkspaceReadArguments {
    relative_path: String,
    max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3RequestBuildError {
    UnmappedTool,
    InvalidCallId,
    InvalidTurnId,
    InvalidArguments,
    InvalidPath,
    InvalidLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3CanonicalOutcome {
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeRequired,
    Forbidden,
    Eligible,
    UnknownCapability,
    AuthorizationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3CanonicalDecisionCode {
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeNotAvailable,
    Forbidden,
    Eligible,
    AuthorizationUnavailable,
    UnknownCapability,
}

impl H3CanonicalDecisionCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "CAPABILITY_AUTHORIZATION_DENIED",
            Self::RootDisabled => "CAPABILITY_ROOT_DISABLED",
            Self::ExplicitConfirmationRequired => "CAPABILITY_CONFIRMATION_REQUIRED",
            Self::ScopeNotAvailable => "CAPABILITY_SCOPE_NOT_AVAILABLE",
            Self::Forbidden => "CAPABILITY_FORBIDDEN",
            Self::Eligible => "CAPABILITY_ELIGIBLE",
            Self::AuthorizationUnavailable => "CAPABILITY_AUTHORIZATION_UNAVAILABLE",
            Self::UnknownCapability => "CAPABILITY_UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3ScopeRequirement {
    None,
    WorkspaceRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3ApprovalFloor {
    RootEnabled,
    ExplicitPerAction,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3CanonicalDecision {
    life_id: String,
    capability_id: String,
    outcome: H3CanonicalOutcome,
    decision_code: H3CanonicalDecisionCode,
    scope_requirement: H3ScopeRequirement,
    approval_floor: H3ApprovalFloor,
    authorization_revision: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3HostScopedGrantEvidence {
    grant_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    authorization_revision: i64,
    scope: VitaRequestedScope,
    workspace_root_identity: super::WorkspaceRootIdentity,
    relative_path: super::WorkspaceRelativePath,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
    max_bytes: usize,
    tool_call_id: String,
    turn_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3HostAuthorityResponse {
    canonical: H3CanonicalDecision,
    scope_grant: Option<H3HostScopedGrantEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum H3AuthorityOperation {
    IssueScopeGrant,
    Revalidate {
        grant_id: String,
        authorization_revision: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H3AuthorityRequest {
    context: VitaExecutionContext,
    capability_id: String,
    operation: H3AuthorityOperation,
    tool_call_id: String,
    turn_id: String,
    relative_path: super::WorkspaceRelativePath,
    max_bytes: usize,
    workspace_root_identity: super::WorkspaceRootIdentity,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VitaH3AuthorityError {
    Unavailable,
    InvalidVerdict,
}

pub(crate) type VitaH3AuthorityFuture = Pin<
    Box<
        dyn Future<Output = Result<H3HostAuthorityResponse, VitaH3AuthorityError>> + Send + 'static,
    >,
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
    CallLimitExceeded,
    RootDisabled,
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
            Self::CallLimitExceeded => "h3_call_limit_exceeded",
            Self::RootDisabled => "root_disabled",
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
            "content_sha256": self
                .content
                .as_deref()
                .map(|content| super::sha256_hex(content.as_bytes())),
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
    call_limit_denials: AtomicUsize,
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
    pub call_limit_denials: usize,
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
/// constructor call and is not attached to the normal Vita entrypoint.  A
/// private executable object can only be imported from typed Host-scoped
/// evidence and the matching H2 prepared target.
pub(crate) struct VitaWorkspaceReadBroker {
    context: Option<VitaExecutionContext>,
    root: super::TrustedWorkspaceRoot,
    authority: Arc<dyn VitaH3AuthorityPort>,
    state: Mutex<H3BrokerState>,
    cancelled: AtomicBool,
    metrics: Arc<H3BrokerMetrics>,
}

impl VitaWorkspaceReadBroker {
    pub(crate) fn new(
        context: VitaExecutionContext,
        root: super::TrustedWorkspaceRoot,
        authority: Arc<dyn VitaH3AuthorityPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: Some(context),
            root,
            authority,
            state: Mutex::new(H3BrokerState::default()),
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(H3BrokerMetrics::default()),
        })
    }

    #[cfg(test)]
    fn without_context(
        root: super::TrustedWorkspaceRoot,
        authority: Arc<dyn VitaH3AuthorityPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: None,
            root,
            authority,
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
            call_limit_denials: self.metrics.call_limit_denials.load(Ordering::Acquire),
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

        let call_admission = {
            let mut state = lock_unpoisoned(&self.state);
            if state.seen_call_ids.contains(&request.tool_call_id) {
                Err(H3DenyClassification::DuplicateToolCall)
            } else if state.seen_call_ids.len() >= MAX_SEEN_CALL_IDS {
                Err(H3DenyClassification::CallLimitExceeded)
            } else {
                state.seen_call_ids.insert(request.tool_call_id.clone());
                Ok(())
            }
        };
        if let Err(classification) = call_admission {
            match classification {
                H3DenyClassification::DuplicateToolCall => {
                    self.metrics
                        .duplicate_denials
                        .fetch_add(1, Ordering::AcqRel);
                }
                H3DenyClassification::CallLimitExceeded => {
                    self.metrics
                        .call_limit_denials
                        .fetch_add(1, Ordering::AcqRel);
                }
                _ => {}
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

        let authority_request = H3AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            operation: H3AuthorityOperation::IssueScopeGrant,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            relative_path: request.relative_path.clone(),
            max_bytes: request.max_bytes,
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("existing H3 target has an identity"),
            target_kind: prepared.kind(),
        };
        let initial_authority = match self.evaluate_authority(authority_request.clone()).await {
            Ok(response) => response,
            Err(classification) => return VitaWorkspaceReadResult::denied(request, classification),
        };
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics.late_denials.fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReadResult::denied(
                request,
                H3DenyClassification::LateAfterCancellation,
            );
        }
        let host_evidence = match validate_scope_completion(&initial_authority, &authority_request)
        {
            Ok(evidence) => evidence,
            Err(classification) => {
                if classification == H3DenyClassification::StaleRevision {
                    self.metrics.stale_denials.fetch_add(1, Ordering::AcqRel);
                }
                return VitaWorkspaceReadResult::denied(request, classification);
            }
        };
        let grant = match VitaExecutableCapabilityGrant::from_host_evidence(
            host_evidence,
            &authority_request,
            &prepared,
        ) {
            Ok(grant) => grant,
            Err(_) => {
                return VitaWorkspaceReadResult::denied(
                    request,
                    H3DenyClassification::GrantRejected,
                )
            }
        };
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);

        // Execution-time D28 fence.  A grant never upgrades a stale or newly
        // disabled authorization row; the current canonical result must still
        // match the exact revision and H3 scope before the read begins.
        let current_authority_request = H3AuthorityRequest {
            operation: H3AuthorityOperation::Revalidate {
                grant_id: grant.grant_id.clone(),
                authorization_revision: grant.authorization_revision,
            },
            ..authority_request.clone()
        };
        let current_authority = match self
            .evaluate_authority(current_authority_request.clone())
            .await
        {
            Ok(response) => response,
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
        if let Err(classification) =
            validate_revalidation(&current_authority, &current_authority_request, &grant)
        {
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
    ) -> Result<H3HostAuthorityResponse, H3DenyClassification> {
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

fn validate_canonical_decision(
    decision: &H3CanonicalDecision,
    request: &H3AuthorityRequest,
) -> Result<i64, H3DenyClassification> {
    if decision.life_id != request.context.life_id()
        || decision.capability_id != request.capability_id
    {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    }
    match decision.outcome {
        H3CanonicalOutcome::ScopeRequired
            if decision.decision_code == H3CanonicalDecisionCode::ScopeNotAvailable
                && decision.scope_requirement == H3ScopeRequirement::WorkspaceRequired
                && decision.approval_floor == H3ApprovalFloor::RootEnabled => {}
        H3CanonicalOutcome::RootDisabled => return Err(H3DenyClassification::RootDisabled),
        H3CanonicalOutcome::Denied => return Err(H3DenyClassification::MissingAuthorization),
        H3CanonicalOutcome::AuthorizationUnavailable => {
            return Err(H3DenyClassification::AuthorityError)
        }
        H3CanonicalOutcome::UnknownCapability => {
            return Err(H3DenyClassification::AuthorityEvidenceMismatch)
        }
        H3CanonicalOutcome::ExplicitConfirmationRequired | H3CanonicalOutcome::Forbidden => {
            return Err(H3DenyClassification::AuthorityEvidenceMismatch)
        }
        H3CanonicalOutcome::Eligible => {
            return Err(H3DenyClassification::AuthorityEvidenceMismatch)
        }
        H3CanonicalOutcome::ScopeRequired => return Err(H3DenyClassification::ScopeUnavailable),
    }
    decision
        .authorization_revision
        .filter(|revision| *revision > 0)
        .ok_or(H3DenyClassification::StaleRevision)
}

fn validate_host_evidence(
    evidence: &H3HostScopedGrantEvidence,
    request: &H3AuthorityRequest,
    authorization_revision: i64,
) -> Result<(), H3DenyClassification> {
    if evidence.grant_id.is_empty()
        || bounded_text("grant id", &evidence.grant_id, MAX_CALL_ID_CHARS).is_none()
        || evidence.life_id != request.context.life_id()
        || evidence.task_id != request.context.task_id()
        || evidence.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
        || evidence.authorization_revision != authorization_revision
        || evidence.scope != VitaRequestedScope::Workspace
        || evidence.workspace_root_identity != request.workspace_root_identity
        || evidence.relative_path != request.relative_path
        || evidence.target_identity != request.target_identity
        || evidence.target_kind != request.target_kind
        || evidence.max_bytes != request.max_bytes
        || evidence.tool_call_id != request.tool_call_id
        || evidence.turn_id != request.turn_id
    {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    }
    let now = unix_millis();
    if evidence.issued_at_unix_ms > now.saturating_add(MAX_HOST_CLOCK_SKEW_MS)
        || evidence.expires_at_unix_ms <= evidence.issued_at_unix_ms
        || evidence
            .expires_at_unix_ms
            .saturating_sub(evidence.issued_at_unix_ms)
            > GRANT_LIFETIME.as_millis() as u64
        || evidence.expires_at_unix_ms <= now
    {
        return Err(H3DenyClassification::GrantRejected);
    }
    Ok(())
}

fn validate_scope_completion(
    response: &H3HostAuthorityResponse,
    request: &H3AuthorityRequest,
) -> Result<H3HostScopedGrantEvidence, H3DenyClassification> {
    let revision = validate_canonical_decision(&response.canonical, request)?;
    if !matches!(request.operation, H3AuthorityOperation::IssueScopeGrant) {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    }
    let evidence = response
        .scope_grant
        .as_ref()
        .ok_or(H3DenyClassification::ScopeUnavailable)?;
    validate_host_evidence(evidence, request, revision)?;
    Ok(evidence.clone())
}

fn validate_revalidation(
    response: &H3HostAuthorityResponse,
    request: &H3AuthorityRequest,
    grant: &VitaExecutableCapabilityGrant,
) -> Result<(), H3DenyClassification> {
    let revision = match validate_canonical_decision(&response.canonical, request) {
        Ok(revision) => revision,
        Err(H3DenyClassification::RootDisabled) => return Err(H3DenyClassification::RootDisabled),
        Err(error) => return Err(error),
    };
    let H3AuthorityOperation::Revalidate {
        grant_id,
        authorization_revision,
    } = &request.operation
    else {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    };
    if revision != *authorization_revision
        || grant.authorization_revision != *authorization_revision
    {
        return Err(H3DenyClassification::StaleRevision);
    }
    let evidence = response
        .scope_grant
        .as_ref()
        .ok_or(H3DenyClassification::ScopeUnavailable)?;
    validate_host_evidence(evidence, request, revision)?;
    if evidence.grant_id != *grant_id || evidence.grant_id != grant.grant_id {
        return Err(H3DenyClassification::AuthorityEvidenceMismatch);
    }
    Ok(())
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Immutable, single-use executable authority.  Its constructor is private
/// and accepts only validated Host-scoped evidence plus the matching H2
/// prepared target.
pub(crate) struct VitaExecutableCapabilityGrant {
    grant_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    authorization_revision: i64,
    scope: VitaRequestedScope,
    root_identity: super::WorkspaceRootIdentity,
    resource: super::WorkspaceRelativePath,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
    max_bytes: usize,
    tool_call_id: String,
    turn_id: String,
    issued_at: Instant,
    expires_at: Instant,
    single_use: bool,
    used: AtomicBool,
}

impl VitaExecutableCapabilityGrant {
    fn from_host_evidence(
        evidence: H3HostScopedGrantEvidence,
        request: &H3AuthorityRequest,
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<Self, H3GrantImportError> {
        validate_host_evidence(&evidence, request, evidence.authorization_revision)
            .map_err(|_| H3GrantImportError::EvidenceMismatch)?;
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.root().identity() != evidence.workspace_root_identity
            || prepared.target_identity() != Some(evidence.target_identity)
            || prepared.kind() != evidence.target_kind
        {
            return Err(H3GrantImportError::TargetMismatch);
        }
        let now = Instant::now();
        let remaining =
            Duration::from_millis(evidence.expires_at_unix_ms.saturating_sub(unix_millis()));
        Ok(Self {
            grant_id: evidence.grant_id,
            life_id: evidence.life_id,
            task_id: evidence.task_id,
            capability_id: evidence.capability_id,
            authorization_revision: evidence.authorization_revision,
            scope: evidence.scope,
            root_identity: evidence.workspace_root_identity,
            resource: evidence.relative_path,
            target_identity: evidence.target_identity,
            target_kind: evidence.target_kind,
            max_bytes: evidence.max_bytes,
            tool_call_id: evidence.tool_call_id,
            turn_id: evidence.turn_id,
            issued_at: now,
            expires_at: now + remaining,
            single_use: true,
            used: AtomicBool::new(false),
        })
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
            || self.scope != VitaRequestedScope::Workspace
            || self.root_identity != prepared.root().identity()
            || self.resource != request.relative_path
            || prepared.target_identity() != Some(self.target_identity)
            || self.target_kind != prepared.kind()
            || self.max_bytes != request.max_bytes
            || self.tool_call_id != request.tool_call_id
            || self.turn_id != request.turn_id
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
        prepared.read_existing_file_utf8_bounded(self.max_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3GrantImportError {
    EvidenceMismatch,
    TargetMismatch,
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
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": WORKSPACE_READ_HARD_MAX_BYTES}
            },
            "required": ["relative_path", "max_bytes"],
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

/// Test-only bridge used by the D29-H4-A real-kernel canary.  It keeps the
/// H3 authority implementation private while allowing the canary to install
/// the already-certified read contributor beside the H4-A contributor.
#[cfg(test)]
pub(crate) fn canary_read_broker(
    context: VitaExecutionContext,
    root: super::TrustedWorkspaceRoot,
) -> Arc<VitaWorkspaceReadBroker> {
    h3r1_tests::canary_read_broker(context, root)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod h3r1_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::thread;
    use std::time::{Duration, SystemTime};

    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tempfile::{tempdir, TempDir};

    use crate::provider_gateway::{VitaGatewayBinding, VitaProviderAuthority};
    use crate::{
        ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
        TrustedWorkspaceRoot, VitaAgentEntrypoint, VitaAgentRuntimeProfile, VitaExecutionContext,
    };

    const LIFE_ID: &str = "life-d29h3-r1";
    const TASK_ID: &str = "task-d29h3-r1";
    const REVISION: i64 = 2;
    const FILE_CONTENT: &str = "VITA_D29H3_FILE_OK";
    const H3_HOST_PROTOCOL_VERSION: u8 = 1;
    const H3_HOST_MAX_FRAME_BYTES: usize = 32 * 1024;
    const H3_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(10);
    const H3_HOST_GRANT_LIFETIME_MS: u64 = 30_000;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuthorityReplyKind {
        ScopeRequired,
        Denied,
        RootDisabled,
        ExplicitConfirmationRequired,
        Forbidden,
        UnknownCapability,
        AuthorizationUnavailable,
        ScopeMissing,
        BadEvidence,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct AuthorityReply {
        kind: AuthorityReplyKind,
        revision: Option<i64>,
    }

    impl AuthorityReply {
        fn scope_required() -> Self {
            Self {
                kind: AuthorityReplyKind::ScopeRequired,
                revision: Some(REVISION),
            }
        }

        fn canonical(&self) -> H3CanonicalDecision {
            match self.kind {
                AuthorityReplyKind::ScopeRequired
                | AuthorityReplyKind::ScopeMissing
                | AuthorityReplyKind::BadEvidence => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::ScopeRequired,
                    decision_code: H3CanonicalDecisionCode::ScopeNotAvailable,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::RootEnabled,
                    authorization_revision: self.revision,
                },
                AuthorityReplyKind::Denied => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::Denied,
                    decision_code: H3CanonicalDecisionCode::Denied,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::RootEnabled,
                    authorization_revision: self.revision,
                },
                AuthorityReplyKind::RootDisabled => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::RootDisabled,
                    decision_code: H3CanonicalDecisionCode::RootDisabled,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::RootEnabled,
                    authorization_revision: self.revision,
                },
                AuthorityReplyKind::ExplicitConfirmationRequired => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::ExplicitConfirmationRequired,
                    decision_code: H3CanonicalDecisionCode::ExplicitConfirmationRequired,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::ExplicitPerAction,
                    authorization_revision: self.revision,
                },
                AuthorityReplyKind::Forbidden => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::Forbidden,
                    decision_code: H3CanonicalDecisionCode::Forbidden,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::Forbidden,
                    authorization_revision: self.revision,
                },
                AuthorityReplyKind::UnknownCapability => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::UnknownCapability,
                    decision_code: H3CanonicalDecisionCode::UnknownCapability,
                    scope_requirement: H3ScopeRequirement::None,
                    approval_floor: H3ApprovalFloor::RootEnabled,
                    authorization_revision: None,
                },
                AuthorityReplyKind::AuthorizationUnavailable => H3CanonicalDecision {
                    life_id: String::new(),
                    capability_id: String::new(),
                    outcome: H3CanonicalOutcome::AuthorizationUnavailable,
                    decision_code: H3CanonicalDecisionCode::AuthorizationUnavailable,
                    scope_requirement: H3ScopeRequirement::WorkspaceRequired,
                    approval_floor: H3ApprovalFloor::RootEnabled,
                    authorization_revision: None,
                },
            }
        }
    }

    struct ScriptedAuthority {
        replies: Mutex<VecDeque<Result<AuthorityReply, VitaH3AuthorityError>>>,
        calls: AtomicUsize,
        requests: Mutex<Vec<H3AuthorityRequest>>,
        responses: Mutex<Vec<H3HostAuthorityResponse>>,
    }

    impl ScriptedAuthority {
        fn new(
            replies: impl IntoIterator<Item = Result<AuthorityReply, VitaH3AuthorityError>>,
        ) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into_iter().collect()),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }

        fn requests(&self) -> Vec<H3AuthorityRequest> {
            lock_unpoisoned(&self.requests).clone()
        }

        fn responses(&self) -> Vec<H3HostAuthorityResponse> {
            lock_unpoisoned(&self.responses).clone()
        }
    }

    impl VitaH3AuthorityPort for ScriptedAuthority {
        fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            self.calls.fetch_add(1, Ordering::AcqRel);
            lock_unpoisoned(&self.requests).push(request.clone());
            let reply = lock_unpoisoned(&self.replies)
                .pop_front()
                .unwrap_or(Ok(AuthorityReply::scope_required()));
            let response = reply.map(|reply| response_from_reply(&request, reply));
            if let Ok(response) = &response {
                lock_unpoisoned(&self.responses).push(response.clone());
            }
            Box::pin(async move { response })
        }
    }

    fn response_from_reply(
        request: &H3AuthorityRequest,
        reply: AuthorityReply,
    ) -> H3HostAuthorityResponse {
        let mut canonical = reply.canonical();
        canonical.life_id = request.context.life_id().to_string();
        canonical.capability_id = request.capability_id.clone();
        let scope_grant = match reply.kind {
            AuthorityReplyKind::ScopeRequired => Some(host_evidence_for(request, reply.revision)),
            AuthorityReplyKind::BadEvidence => {
                let mut evidence = host_evidence_for(request, reply.revision);
                evidence.target_kind = PreparedWorkspaceTargetKind::Missing;
                Some(evidence)
            }
            _ => None,
        };
        H3HostAuthorityResponse {
            canonical,
            scope_grant,
        }
    }

    fn host_evidence_for(
        request: &H3AuthorityRequest,
        revision: Option<i64>,
    ) -> H3HostScopedGrantEvidence {
        let grant_id = match &request.operation {
            H3AuthorityOperation::IssueScopeGrant => {
                format!("test-host-grant-{}", request.tool_call_id)
            }
            H3AuthorityOperation::Revalidate { grant_id, .. } => grant_id.clone(),
        };
        let issued_at_unix_ms = unix_millis();
        H3HostScopedGrantEvidence {
            grant_id,
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: request.capability_id.clone(),
            authorization_revision: revision.unwrap_or(REVISION),
            scope: VitaRequestedScope::Workspace,
            workspace_root_identity: request.workspace_root_identity,
            relative_path: request.relative_path.clone(),
            target_identity: request.target_identity,
            target_kind: request.target_kind,
            max_bytes: request.max_bytes,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms + H3_HOST_GRANT_LIFETIME_MS,
        }
    }

    struct Fixture {
        _root_dir: TempDir,
        root: TrustedWorkspaceRoot,
        path: PathBuf,
        context: VitaExecutionContext,
    }

    impl Fixture {
        fn new(content: &[u8]) -> Self {
            let root_dir = tempdir().expect("H3-R1 fixture root");
            let path = root_dir.path().join("read-me.txt");
            fs::write(&path, content).expect("H3-R1 fixture file");
            let root = TrustedWorkspaceRoot::acquire(root_dir.path()).expect("H3-R1 root acquire");
            let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap();
            Self {
                _root_dir: root_dir,
                root,
                path,
                context,
            }
        }

        fn request(&self, call_id: &str) -> VitaWorkspaceReadRequest {
            VitaWorkspaceReadRequest::synthetic(
                call_id,
                Some(self.context.clone()),
                "read-me.txt",
                WORKSPACE_READ_HARD_MAX_BYTES,
            )
        }

        fn authority_request(&self, operation: H3AuthorityOperation) -> H3AuthorityRequest {
            let request = self.request("call-authority");
            let prepared = self
                .root
                .prepare_target(request.relative_path.as_path())
                .expect("H3-R1 target preparation");
            H3AuthorityRequest {
                context: self.context.clone(),
                capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
                operation,
                tool_call_id: request.tool_call_id,
                turn_id: request.turn_id,
                relative_path: request.relative_path,
                max_bytes: request.max_bytes,
                workspace_root_identity: prepared.root().identity(),
                target_identity: prepared.target_identity().unwrap(),
                target_kind: prepared.kind(),
            }
        }

        fn broker(&self, authority: Arc<dyn VitaH3AuthorityPort>) -> Arc<VitaWorkspaceReadBroker> {
            VitaWorkspaceReadBroker::new(self.context.clone(), self.root.clone(), authority)
        }
    }

    pub(super) fn canary_read_broker(
        context: VitaExecutionContext,
        root: super::super::TrustedWorkspaceRoot,
    ) -> Arc<VitaWorkspaceReadBroker> {
        let authority = ScriptedAuthority::new([]);
        VitaWorkspaceReadBroker::new(context, root, authority)
    }

    fn run<'a>(
        broker: &'a VitaWorkspaceReadBroker,
        request: VitaWorkspaceReadRequest,
    ) -> impl Future<Output = VitaWorkspaceReadResult> + 'a {
        broker.execute_request(request)
    }

    #[tokio::test]
    async fn canonical_scope_floor_is_workspace_required_and_revision_is_not_model_input() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([
            Ok(AuthorityReply::scope_required()),
            Ok(AuthorityReply::scope_required()),
        ]);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
        let result = run(&broker, fixture.request("call-scope-floor")).await;
        assert_eq!(result.classification, None);
        let responses = authority.responses();
        assert_eq!(
            responses[0].canonical.outcome,
            H3CanonicalOutcome::ScopeRequired
        );
        assert_eq!(
            responses[0].canonical.decision_code,
            H3CanonicalDecisionCode::ScopeNotAvailable
        );
        assert_eq!(
            responses[0].canonical.scope_requirement,
            H3ScopeRequirement::WorkspaceRequired
        );
        assert_eq!(
            responses[0].canonical.approval_floor,
            H3ApprovalFloor::RootEnabled
        );
        assert_eq!(
            responses[0].canonical.authorization_revision,
            Some(REVISION)
        );
        assert!(serde_json::from_str::<VitaWorkspaceReadArguments>(
            r#"{"relative_path":"read-me.txt","max_bytes":65536,"expected_authorization_revision":2}"#
        )
        .is_err());
        let requests = authority.requests();
        assert!(matches!(
            requests[0].operation,
            H3AuthorityOperation::IssueScopeGrant
        ));
        assert!(matches!(
            requests[1].operation,
            H3AuthorityOperation::Revalidate {
                authorization_revision: REVISION,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn h3_success_adds_exact_content_sha256() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([
            Ok(AuthorityReply::scope_required()),
            Ok(AuthorityReply::scope_required()),
        ]);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
        let result = run(&broker, fixture.request("call-success")).await;
        assert_eq!(result.content.as_deref(), Some(FILE_CONTENT));
        assert_eq!(
            result.model_value()["content_sha256"],
            json!(super::super::sha256_hex(FILE_CONTENT.as_bytes()))
        );
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
    async fn duplicate_and_excess_call_ids_are_bounded_and_never_read_twice() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([]);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
        assert_eq!(
            run(&broker, fixture.request("call-replay"))
                .await
                .classification,
            None
        );
        assert_eq!(
            run(&broker, fixture.request("call-replay"))
                .await
                .classification,
            Some(H3DenyClassification::DuplicateToolCall)
        );
        for id in 0..MAX_SEEN_CALL_IDS - 1 {
            let request = fixture.request(&format!("call-limit-{id}"));
            let _ = run(&broker, request).await;
        }
        let result = run(&broker, fixture.request("call-limit-overflow")).await;
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::CallLimitExceeded)
        );
        assert_eq!(broker.snapshot().call_limit_denials, 1);
        assert_eq!(broker.snapshot().authorized_file_reads, MAX_SEEN_CALL_IDS);
    }

    #[tokio::test]
    async fn canonical_denials_and_scope_completion_fail_closed() {
        for (kind, expected) in [
            (
                AuthorityReplyKind::Denied,
                H3DenyClassification::MissingAuthorization,
            ),
            (
                AuthorityReplyKind::RootDisabled,
                H3DenyClassification::RootDisabled,
            ),
            (
                AuthorityReplyKind::ExplicitConfirmationRequired,
                H3DenyClassification::AuthorityEvidenceMismatch,
            ),
            (
                AuthorityReplyKind::Forbidden,
                H3DenyClassification::AuthorityEvidenceMismatch,
            ),
            (
                AuthorityReplyKind::UnknownCapability,
                H3DenyClassification::AuthorityEvidenceMismatch,
            ),
            (
                AuthorityReplyKind::AuthorizationUnavailable,
                H3DenyClassification::AuthorityError,
            ),
            (
                AuthorityReplyKind::ScopeMissing,
                H3DenyClassification::ScopeUnavailable,
            ),
        ] {
            let fixture = Fixture::new(FILE_CONTENT.as_bytes());
            let authority = ScriptedAuthority::new([Ok(AuthorityReply {
                kind,
                revision: Some(REVISION),
            })]);
            let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
            let result = run(&broker, fixture.request("call-denied")).await;
            assert_eq!(result.classification, Some(expected), "kind={kind:?}");
            assert_eq!(broker.snapshot().authorized_file_reads, 0);
            assert_eq!(broker.snapshot().grants_issued, 0);
        }
    }

    #[tokio::test]
    async fn trusted_h2_facts_and_all_grant_bindings_are_exact() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([Ok(AuthorityReply {
            kind: AuthorityReplyKind::BadEvidence,
            revision: Some(REVISION),
        })]);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
        let result = run(&broker, fixture.request("call-bad-evidence")).await;
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::AuthorityEvidenceMismatch)
        );

        let request = fixture.request("call-direct-grant");
        let prepared = fixture
            .root
            .prepare_target(request.relative_path.as_path())
            .unwrap();
        let mut authority_request =
            fixture.authority_request(H3AuthorityOperation::IssueScopeGrant);
        authority_request.tool_call_id = request.tool_call_id.clone();
        authority_request.turn_id = request.turn_id.clone();
        let evidence = host_evidence_for(&authority_request, Some(REVISION));
        let grant = VitaExecutableCapabilityGrant::from_host_evidence(
            evidence,
            &authority_request,
            &prepared,
        )
        .unwrap();
        let mut wrong_call = request.clone();
        wrong_call.tool_call_id = "call-other".to_string();
        assert!(grant
            .execute_once(&fixture.context, &wrong_call, &prepared)
            .is_err());
        let mut wrong_turn = request.clone();
        wrong_turn.turn_id = "turn-other".to_string();
        assert!(grant
            .execute_once(&fixture.context, &wrong_turn, &prepared)
            .is_err());
        let mut wrong_limit = request.clone();
        wrong_limit.max_bytes = request.max_bytes - 1;
        assert!(grant
            .execute_once(&fixture.context, &wrong_limit, &prepared)
            .is_err());
        assert_eq!(
            grant
                .execute_once(&fixture.context, &request, &prepared)
                .unwrap(),
            FILE_CONTENT
        );
        assert!(grant
            .execute_once(&fixture.context, &request, &prepared)
            .is_err());
    }

    #[tokio::test]
    async fn target_and_request_negative_paths_do_not_create_execution() {
        for label in ["missing", "directory", "oversized", "binary"] {
            let fixture = match label {
                "oversized" => Fixture::new(&vec![b'x'; WORKSPACE_READ_HARD_MAX_BYTES + 1]),
                "binary" => Fixture::new(&[0xff, 0xfe, 0xfd]),
                _ => Fixture::new(FILE_CONTENT.as_bytes()),
            };
            if label == "missing" {
                fs::remove_file(&fixture.path).unwrap();
            } else if label == "directory" {
                fs::remove_file(&fixture.path).unwrap();
                fs::create_dir(&fixture.path).unwrap();
            }
            let authority = ScriptedAuthority::new([]);
            let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
            let result = run(&broker, fixture.request(&format!("call-{label}"))).await;
            let expected = match label {
                "missing" => H3DenyClassification::TargetMissing,
                "directory" => H3DenyClassification::TargetRejected,
                "oversized" => H3DenyClassification::Oversized,
                "binary" => H3DenyClassification::InvalidUtf8,
                _ => unreachable!(),
            };
            if label == "oversized" || label == "binary" {
                // These cases reach the bounded read probe, but never count a
                // successful authorized UTF-8 read or return content.
                assert_eq!(result.classification, Some(expected));
            } else {
                assert_eq!(result.classification, Some(expected));
            }
            assert_eq!(result.content, None);
            assert_eq!(broker.snapshot().authorized_file_reads, 0);
        }
    }

    #[tokio::test]
    async fn cancellation_before_and_after_authority_is_deny_only() {
        struct Gate {
            released: AtomicBool,
            waker: Mutex<Option<std::task::Waker>>,
        }
        struct GateFuture {
            gate: Arc<Gate>,
            result: Option<Result<H3HostAuthorityResponse, VitaH3AuthorityError>>,
        }
        impl Future for GateFuture {
            type Output = Result<H3HostAuthorityResponse, VitaH3AuthorityError>;
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = unsafe { self.get_unchecked_mut() };
                if this.gate.released.load(Ordering::Acquire) {
                    Poll::Ready(this.result.take().unwrap())
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
                let gate = Arc::clone(&self.gate);
                Box::pin(GateFuture {
                    gate,
                    result: Some(Ok(response_from_reply(
                        &request,
                        AuthorityReply::scope_required(),
                    ))),
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

        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ScriptedAuthority::new([]);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);
        broker.cancel();
        assert_eq!(
            run(&broker, fixture.request("call-cancelled"))
                .await
                .classification,
            Some(H3DenyClassification::TurnCancelled)
        );
        assert_eq!(authority.calls(), 0);
    }

    #[test]
    fn h3_request_namespace_and_model_schema_reject_revision_or_path_escape() {
        for path in [
            "../read-me.txt",
            "C:\\read-me.txt",
            "\\\\server\\share\\read-me.txt",
            "\\\\?\\C:\\read-me.txt",
            "\\\\.\\PIPE\\named",
            "read-me.txt:secret",
            "read-me.txt/../other",
        ] {
            assert!(super::super::WorkspaceRelativePath::parse(Path::new(path)).is_err());
        }
        assert!(serde_json::from_str::<VitaWorkspaceReadArguments>(
            r#"{"relative_path":"read-me.txt","max_bytes":65536,"expected_authorization_revision":2}"#
        )
        .is_err());
    }

    #[derive(Clone, Debug, Serialize)]
    #[serde(tag = "operation", rename_all = "snake_case")]
    enum H3HostWireRequest {
        Initialize {
            protocol_version: u8,
            life_id: String,
            task_id: String,
            capability_id: String,
            allowed_workspace_root_identity: String,
        },
        EvaluateAndIssueScopeGrant {
            life_id: String,
            task_id: String,
            capability_id: String,
            tool_call_id: String,
            turn_id: String,
            relative_path: String,
            max_bytes: u64,
            workspace_root_identity: String,
            target_identity: String,
            target_kind: String,
        },
        RevalidateGrant {
            grant_id: String,
            life_id: String,
            task_id: String,
            capability_id: String,
            tool_call_id: String,
            turn_id: String,
            relative_path: String,
            max_bytes: u64,
            workspace_root_identity: String,
            target_identity: String,
            target_kind: String,
            authorization_revision: i64,
        },
        DisableAuthorizationForTest {
            life_id: String,
            capability_id: String,
            expected_revision: i64,
        },
        Shutdown {},
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H3HostResponse {
        operation: String,
        status: String,
        canonical: Option<H3CanonicalWire>,
        scope_grant: Option<H3ScopedGrantWire>,
        authorization_revision: Option<i64>,
        error_code: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H3CanonicalWire {
        canonical_evaluations: usize,
        production_registry_size: usize,
        test_registry_size: usize,
        authorization_row_reads: usize,
        host_scope_authority_present: bool,
        requested_root_matched_authorized_root: bool,
        life_id: String,
        capability_id: String,
        outcome: String,
        decision_code: String,
        scope_requirement: String,
        approval_floor: String,
        authorization_revision: Option<i64>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H3ScopedGrantWire {
        grant_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        scope: String,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        target_kind: String,
        max_bytes: u64,
        tool_call_id: String,
        turn_id: String,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    struct PersistentHostProcess {
        io: Mutex<Option<HostProcessIo>>,
        child: Arc<Mutex<Child>>,
    }

    struct HostProcessIo {
        stdin: ChildStdin,
        stdout: ChildStdout,
    }

    impl PersistentHostProcess {
        fn start(
            repo_root: &Path,
            allowed_workspace_root_identity: String,
        ) -> Result<Arc<Self>, String> {
            let executable = host_fixture_executable(repo_root)?;
            let mut child = Command::new(executable)
                .current_dir(repo_root)
                .env("CARGO_TERM_COLOR", "never")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn persistent H3 Host fixture: {error}"))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "persistent H3 Host fixture stdin unavailable".to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "persistent H3 Host fixture stdout unavailable".to_string())?;
            let process = Arc::new(Self {
                io: Mutex::new(Some(HostProcessIo { stdin, stdout })),
                child: Arc::new(Mutex::new(child)),
            });
            let response = process
                .roundtrip_blocking(&H3HostWireRequest::Initialize {
                    protocol_version: H3_HOST_PROTOCOL_VERSION,
                    life_id: LIFE_ID.to_string(),
                    task_id: TASK_ID.to_string(),
                    capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
                    allowed_workspace_root_identity,
                })
                .map_err(|error| {
                    process.abort();
                    error
                })?;
            let response: H3HostResponse = serde_json::from_slice(&response)
                .map_err(|_| "persistent H3 Host initialize response malformed".to_string())?;
            if response.operation != "initialize"
                || response.status != "ok"
                || response.authorization_revision != Some(REVISION)
                || response.canonical.is_some()
                || response.scope_grant.is_some()
            {
                process.abort();
                return Err("persistent H3 Host initialize response invalid".to_string());
            }
            Ok(process)
        }

        fn roundtrip_blocking(&self, request: &H3HostWireRequest) -> Result<Vec<u8>, String> {
            let body = serde_json::to_vec(request)
                .map_err(|_| "H3 Host request serialization failed".to_string())?;
            if body.is_empty() || body.len() > H3_HOST_MAX_FRAME_BYTES {
                return Err("H3 Host request exceeded bounded frame size".to_string());
            }
            let mut io = lock_unpoisoned(&self.io);
            let io = io
                .as_mut()
                .ok_or_else(|| "H3 Host process is closed".to_string())?;
            io.stdin
                .write_all(&(body.len() as u32).to_be_bytes())
                .and_then(|_| io.stdin.write_all(&body))
                .and_then(|_| io.stdin.flush())
                .map_err(|_| "H3 Host request write failed".to_string())?;
            let mut length = [0_u8; 4];
            io.stdout
                .read_exact(&mut length)
                .map_err(|_| "H3 Host response frame length read failed".to_string())?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > H3_HOST_MAX_FRAME_BYTES {
                return Err("H3 Host response exceeded bounded frame size".to_string());
            }
            let mut response = vec![0_u8; length];
            io.stdout
                .read_exact(&mut response)
                .map_err(|_| "H3 Host response frame body read failed".to_string())?;
            Ok(response)
        }

        fn abort(&self) {
            {
                let mut child = lock_unpoisoned(&self.child);
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
            *lock_unpoisoned(&self.io) = None;
        }

        fn shutdown(&self) -> bool {
            let response = self
                .roundtrip_blocking(&H3HostWireRequest::Shutdown {})
                .ok()
                .and_then(|body| serde_json::from_slice::<H3HostResponse>(&body).ok());
            let valid_response = response.as_ref().is_some_and(|response| {
                response.operation == "shutdown"
                    && response.status == "ok"
                    && response.canonical.is_none()
                    && response.scope_grant.is_none()
            });
            let mut child = lock_unpoisoned(&self.child);
            let exited = match child.try_wait() {
                Ok(Some(status)) => status.success(),
                Ok(None) if valid_response => {
                    child.wait().map(|status| status.success()).unwrap_or(false)
                }
                Ok(None) => {
                    let _ = child.kill();
                    child.wait().map(|status| status.success()).unwrap_or(false)
                }
                Err(_) => false,
            };
            *lock_unpoisoned(&self.io) = None;
            valid_response && exited
        }
    }

    impl Drop for PersistentHostProcess {
        fn drop(&mut self) {
            self.abort();
        }
    }

    fn host_fixture_executable(repo_root: &Path) -> Result<PathBuf, String> {
        let executable = repo_root
            .join("src-tauri")
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "d29h3-authority-fixture.exe"
            } else {
                "d29h3-authority-fixture"
            });
        if executable.is_file() {
            return Ok(executable);
        }
        let status = Command::new("cargo")
            .current_dir(repo_root)
            .args(["build", "--quiet", "--locked", "--manifest-path"])
            .arg(repo_root.join("src-tauri").join("Cargo.toml"))
            .args([
                "--bin",
                "d29h3-authority-fixture",
                "--features",
                "d29-h3-host-fixture",
            ])
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .status()
            .map_err(|error| format!("build persistent H3 Host fixture: {error}"))?;
        if !status.success() || !executable.is_file() {
            return Err("persistent H3 Host fixture executable was not produced".to_string());
        }
        Ok(executable)
    }

    struct ProcessIsolatedH3Authority {
        process: Arc<PersistentHostProcess>,
        repo_root: PathBuf,
        observations: Arc<Mutex<Vec<H3HostResponse>>>,
    }

    impl ProcessIsolatedH3Authority {
        fn new(
            allowed_workspace_root_identity: super::super::WorkspaceRootIdentity,
        ) -> Result<Arc<Self>, String> {
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or_else(|| "D29-H3-R1 manifest has no repository parent".to_string())?
                .to_path_buf();
            let process = PersistentHostProcess::start(
                &repo_root,
                identity_wire(allowed_workspace_root_identity),
            )?;
            Ok(Arc::new(Self {
                process,
                repo_root,
                observations: Arc::new(Mutex::new(Vec::new())),
            }))
        }

        fn snapshot(&self) -> Vec<H3HostResponse> {
            lock_unpoisoned(&self.observations).clone()
        }

        fn disable_for_test(&self, expected_revision: i64) -> Result<i64, String> {
            let body = self.process.roundtrip_blocking(
                &H3HostWireRequest::DisableAuthorizationForTest {
                    life_id: LIFE_ID.to_string(),
                    capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
                    expected_revision,
                },
            )?;
            let response: H3HostResponse = serde_json::from_slice(&body)
                .map_err(|_| "H3 Host disable response malformed".to_string())?;
            if response.operation != "disable_authorization_for_test"
                || response.status != "ok"
                || response.authorization_revision != Some(expected_revision + 1)
                || response.canonical.is_some()
                || response.scope_grant.is_some()
            {
                return Err("H3 Host disable response invalid".to_string());
            }
            Ok(response.authorization_revision.unwrap())
        }

        fn shutdown(&self) -> bool {
            self.process.shutdown()
        }
    }

    impl VitaH3AuthorityPort for ProcessIsolatedH3Authority {
        fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            let process = Arc::clone(&self.process);
            let observations = Arc::clone(&self.observations);
            let wire = wire_request(&request);
            Box::pin(async move {
                let process_for_roundtrip = Arc::clone(&process);
                let join = tokio::task::spawn_blocking(move || {
                    process_for_roundtrip.roundtrip_blocking(&wire)
                });
                let raw = match tokio::time::timeout(H3_HOST_IPC_TIMEOUT, join).await {
                    Ok(Ok(Ok(raw))) => raw,
                    _ => {
                        process.abort();
                        return Err(VitaH3AuthorityError::Unavailable);
                    }
                };
                let response: H3HostResponse = match serde_json::from_slice(&raw) {
                    Ok(response) => response,
                    Err(_) => {
                        process.abort();
                        return Err(VitaH3AuthorityError::InvalidVerdict);
                    }
                };
                let typed = match parse_host_response(&request, &response) {
                    Ok(typed) => typed,
                    Err(error) => {
                        process.abort();
                        return Err(error);
                    }
                };
                lock_unpoisoned(&observations).push(response);
                Ok(typed)
            })
        }
    }

    struct RootMutatingAuthority {
        host: Arc<ProcessIsolatedH3Authority>,
        replacement_root: super::super::WorkspaceRootIdentity,
    }

    impl VitaH3AuthorityPort for RootMutatingAuthority {
        fn evaluate(&self, mut request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            if matches!(request.operation, H3AuthorityOperation::Revalidate { .. }) {
                request.workspace_root_identity = self.replacement_root;
            }
            self.host.evaluate(request)
        }
    }

    fn wire_request(request: &H3AuthorityRequest) -> H3HostWireRequest {
        let common = (
            request.context.life_id().to_string(),
            request.context.task_id().to_string(),
            request.capability_id.clone(),
            request.tool_call_id.clone(),
            request.turn_id.clone(),
            request
                .relative_path
                .as_path()
                .to_string_lossy()
                .into_owned(),
            request.max_bytes as u64,
            identity_wire(request.workspace_root_identity),
            identity_wire(request.target_identity),
            target_kind_wire(request.target_kind).to_string(),
        );
        match &request.operation {
            H3AuthorityOperation::IssueScopeGrant => {
                H3HostWireRequest::EvaluateAndIssueScopeGrant {
                    life_id: common.0,
                    task_id: common.1,
                    capability_id: common.2,
                    tool_call_id: common.3,
                    turn_id: common.4,
                    relative_path: common.5,
                    max_bytes: common.6,
                    workspace_root_identity: common.7,
                    target_identity: common.8,
                    target_kind: common.9,
                }
            }
            H3AuthorityOperation::Revalidate {
                grant_id,
                authorization_revision,
            } => H3HostWireRequest::RevalidateGrant {
                grant_id: grant_id.clone(),
                life_id: common.0,
                task_id: common.1,
                capability_id: common.2,
                tool_call_id: common.3,
                turn_id: common.4,
                relative_path: common.5,
                max_bytes: common.6,
                workspace_root_identity: common.7,
                target_identity: common.8,
                target_kind: common.9,
                authorization_revision: *authorization_revision,
            },
        }
    }

    fn parse_host_response(
        request: &H3AuthorityRequest,
        response: &H3HostResponse,
    ) -> Result<H3HostAuthorityResponse, VitaH3AuthorityError> {
        let expected_operation = match request.operation {
            H3AuthorityOperation::IssueScopeGrant => "evaluate_and_issue_scope_grant",
            H3AuthorityOperation::Revalidate { .. } => "revalidate_grant",
        };
        if response.operation != expected_operation
            || response.error_code.is_some()
            || response.canonical.is_none()
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let canonical = response.canonical.as_ref().unwrap();
        if canonical.canonical_evaluations != 1
            || canonical.production_registry_size != 0
            || canonical.test_registry_size != 1
            || canonical.authorization_row_reads != 1
            || !canonical.host_scope_authority_present
            || canonical.life_id != request.context.life_id()
            || canonical.capability_id != request.capability_id
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let canonical = H3CanonicalDecision {
            life_id: canonical.life_id.clone(),
            capability_id: canonical.capability_id.clone(),
            outcome: parse_outcome(&canonical.outcome)?,
            decision_code: parse_decision_code(&canonical.decision_code)?,
            scope_requirement: parse_scope_requirement(&canonical.scope_requirement)?,
            approval_floor: parse_approval_floor(&canonical.approval_floor)?,
            authorization_revision: canonical.authorization_revision,
        };
        let scope_grant = response
            .scope_grant
            .as_ref()
            .map(|evidence| parse_host_evidence(request, evidence))
            .transpose()?;
        if response.status != "ok" && response.status != "denied" {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        Ok(H3HostAuthorityResponse {
            canonical,
            scope_grant,
        })
    }

    fn parse_host_evidence(
        request: &H3AuthorityRequest,
        evidence: &H3ScopedGrantWire,
    ) -> Result<H3HostScopedGrantEvidence, VitaH3AuthorityError> {
        let relative_path =
            super::super::WorkspaceRelativePath::parse(Path::new(&evidence.relative_path))
                .map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
        let max_bytes = usize::try_from(evidence.max_bytes)
            .ok()
            .filter(|max_bytes| (1..=WORKSPACE_READ_HARD_MAX_BYTES).contains(max_bytes))
            .ok_or(VitaH3AuthorityError::InvalidVerdict)?;
        if evidence.grant_id.is_empty()
            || evidence.grant_id.chars().count() > MAX_CALL_ID_CHARS
            || evidence.scope != "workspace"
            || evidence.life_id != request.context.life_id()
            || evidence.task_id != request.context.task_id()
            || evidence.capability_id != request.capability_id
            || evidence.authorization_revision < 1
            || evidence.workspace_root_identity != identity_wire(request.workspace_root_identity)
            || relative_path != request.relative_path
            || evidence.target_identity != identity_wire(request.target_identity)
            || evidence.target_kind != target_kind_wire(request.target_kind)
            || max_bytes != request.max_bytes
            || evidence.tool_call_id != request.tool_call_id
            || evidence.turn_id != request.turn_id
            || evidence.expires_at_unix_ms <= evidence.issued_at_unix_ms
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        if let H3AuthorityOperation::Revalidate {
            grant_id,
            authorization_revision,
        } = &request.operation
        {
            if evidence.grant_id != *grant_id
                || evidence.authorization_revision != *authorization_revision
            {
                return Err(VitaH3AuthorityError::InvalidVerdict);
            }
        }
        Ok(H3HostScopedGrantEvidence {
            grant_id: evidence.grant_id.clone(),
            life_id: evidence.life_id.clone(),
            task_id: evidence.task_id.clone(),
            capability_id: evidence.capability_id.clone(),
            authorization_revision: evidence.authorization_revision,
            scope: VitaRequestedScope::Workspace,
            workspace_root_identity: request.workspace_root_identity,
            relative_path,
            target_identity: request.target_identity,
            target_kind: request.target_kind,
            max_bytes,
            tool_call_id: evidence.tool_call_id.clone(),
            turn_id: evidence.turn_id.clone(),
            issued_at_unix_ms: evidence.issued_at_unix_ms,
            expires_at_unix_ms: evidence.expires_at_unix_ms,
        })
    }

    fn parse_outcome(value: &str) -> Result<H3CanonicalOutcome, VitaH3AuthorityError> {
        Ok(match value {
            "Denied" => H3CanonicalOutcome::Denied,
            "RootDisabled" => H3CanonicalOutcome::RootDisabled,
            "ExplicitConfirmationRequired" => H3CanonicalOutcome::ExplicitConfirmationRequired,
            "ScopeRequired" => H3CanonicalOutcome::ScopeRequired,
            "Forbidden" => H3CanonicalOutcome::Forbidden,
            "Eligible" => H3CanonicalOutcome::Eligible,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        })
    }

    fn parse_decision_code(value: &str) -> Result<H3CanonicalDecisionCode, VitaH3AuthorityError> {
        Ok(match value {
            "CAPABILITY_AUTHORIZATION_DENIED" => H3CanonicalDecisionCode::Denied,
            "CAPABILITY_ROOT_DISABLED" => H3CanonicalDecisionCode::RootDisabled,
            "CAPABILITY_CONFIRMATION_REQUIRED" => {
                H3CanonicalDecisionCode::ExplicitConfirmationRequired
            }
            "CAPABILITY_SCOPE_NOT_AVAILABLE" => H3CanonicalDecisionCode::ScopeNotAvailable,
            "CAPABILITY_FORBIDDEN" => H3CanonicalDecisionCode::Forbidden,
            "CAPABILITY_ELIGIBLE" => H3CanonicalDecisionCode::Eligible,
            "CAPABILITY_AUTHORIZATION_UNAVAILABLE" => {
                H3CanonicalDecisionCode::AuthorizationUnavailable
            }
            "CAPABILITY_UNKNOWN" => H3CanonicalDecisionCode::UnknownCapability,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        })
    }

    fn parse_scope_requirement(value: &str) -> Result<H3ScopeRequirement, VitaH3AuthorityError> {
        Ok(match value {
            "None" => H3ScopeRequirement::None,
            "WorkspaceRequired" => H3ScopeRequirement::WorkspaceRequired,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        })
    }

    fn parse_approval_floor(value: &str) -> Result<H3ApprovalFloor, VitaH3AuthorityError> {
        Ok(match value {
            "RootEnabled" => H3ApprovalFloor::RootEnabled,
            "ExplicitPerAction" => H3ApprovalFloor::ExplicitPerAction,
            "Forbidden" => H3ApprovalFloor::Forbidden,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        })
    }

    fn identity_wire(identity: super::super::WorkspaceRootIdentity) -> String {
        let volume = identity.volume_serial_number().unwrap_or_default();
        let file_id = identity
            .file_id()
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .unwrap_or_else(|| "none".to_string());
        format!("v{volume:x}f{file_id}")
    }

    fn target_kind_wire(kind: PreparedWorkspaceTargetKind) -> &'static str {
        match kind {
            PreparedWorkspaceTargetKind::ExistingFile => "existing_file",
            PreparedWorkspaceTargetKind::ExistingDirectory => "existing_directory",
            PreparedWorkspaceTargetKind::Missing => "missing",
        }
    }

    #[tokio::test]
    async fn requester_root_cannot_self_authorize_against_host_owned_scope() {
        let requester = Fixture::new(FILE_CONTENT.as_bytes());
        let allowed = Fixture::new(FILE_CONTENT.as_bytes());
        assert_ne!(requester.root.identity(), allowed.root.identity());
        let authority = ProcessIsolatedH3Authority::new(allowed.root.identity())
            .expect("persistent H3 Host authority");
        let broker = requester.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);

        let result = run(&broker, requester.request("call-root-self-authorize")).await;
        assert_eq!(result.content, None);
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::ScopeUnavailable)
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 0);
        assert_eq!(snapshot.execution_started, 0);
        assert_eq!(snapshot.authorized_file_reads, 0);

        let observations = authority.snapshot();
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        let canonical = observation.canonical.as_ref().expect("Host D28 result");
        assert!(canonical.host_scope_authority_present);
        assert!(!canonical.requested_root_matched_authorized_root);
        assert_eq!(canonical.outcome, "ScopeRequired");
        assert_eq!(canonical.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
        assert_eq!(canonical.scope_requirement, "WorkspaceRequired");
        assert_eq!(canonical.authorization_revision, Some(REVISION));
        assert!(observation.scope_grant.is_none());
        assert!(authority.shutdown());
    }

    #[tokio::test]
    async fn correct_host_owned_root_completes_scope_and_read() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ProcessIsolatedH3Authority::new(fixture.root.identity())
            .expect("persistent H3 Host authority");
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH3AuthorityPort>);

        let result = run(&broker, fixture.request("call-root-authorized")).await;
        assert_eq!(result.content.as_deref(), Some(FILE_CONTENT));
        assert_eq!(result.classification, None);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.execution_started, 1);
        assert_eq!(snapshot.authorized_file_reads, 1);

        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        for observation in observations {
            let canonical = observation.canonical.expect("Host D28 result");
            assert!(canonical.host_scope_authority_present);
            assert!(canonical.requested_root_matched_authorized_root);
            assert_eq!(canonical.outcome, "ScopeRequired");
            assert_eq!(canonical.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
            assert_eq!(canonical.scope_requirement, "WorkspaceRequired");
            assert_eq!(canonical.authorization_revision, Some(REVISION));
            assert!(observation.scope_grant.is_some());
        }
        assert!(authority.shutdown());
    }

    #[tokio::test]
    async fn altered_root_on_revalidation_is_denied_by_retained_host_scope() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let altered = Fixture::new(FILE_CONTENT.as_bytes());
        assert_ne!(fixture.root.identity(), altered.root.identity());
        let host = ProcessIsolatedH3Authority::new(fixture.root.identity())
            .expect("persistent H3 Host authority");
        let authority = Arc::new(RootMutatingAuthority {
            host: Arc::clone(&host),
            replacement_root: altered.root.identity(),
        });
        let broker = fixture.broker(authority as Arc<dyn VitaH3AuthorityPort>);

        let result = run(&broker, fixture.request("call-root-revalidation-mutation")).await;
        assert_eq!(result.content, None);
        assert_eq!(
            result.classification,
            Some(H3DenyClassification::ScopeUnavailable)
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.execution_started, 0);
        assert_eq!(snapshot.authorized_file_reads, 0);

        let observations = host.snapshot();
        assert_eq!(observations.len(), 2);
        let initial = observations[0]
            .canonical
            .as_ref()
            .expect("issue D28 result");
        assert!(initial.host_scope_authority_present);
        assert!(initial.requested_root_matched_authorized_root);
        assert!(observations[0].scope_grant.is_some());
        let revalidation = observations[1]
            .canonical
            .as_ref()
            .expect("revalidation D28 result");
        assert!(revalidation.host_scope_authority_present);
        assert!(!revalidation.requested_root_matched_authorized_root);
        assert_eq!(revalidation.outcome, "ScopeRequired");
        assert_eq!(revalidation.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
        assert!(observations[1].scope_grant.is_none());
        assert!(host.shutdown());
    }

    struct RevokingAuthority {
        host: Arc<ProcessIsolatedH3Authority>,
        calls: AtomicUsize,
    }

    impl VitaH3AuthorityPort for RevokingAuthority {
        fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            let host = Arc::clone(&self.host);
            Box::pin(async move {
                if call == 1 && matches!(request.operation, H3AuthorityOperation::Revalidate { .. })
                {
                    let host_for_disable = Arc::clone(&host);
                    let disabled = tokio::task::spawn_blocking(move || {
                        host_for_disable.disable_for_test(REVISION)
                    })
                    .await
                    .map_err(|_| VitaH3AuthorityError::Unavailable)?
                    .map_err(|_| VitaH3AuthorityError::Unavailable)?;
                    assert_eq!(disabled, REVISION + 1);
                    return host.evaluate(request).await;
                }
                host.evaluate(request).await
            })
        }
    }

    #[tokio::test]
    async fn same_sqlite_state_revocation_fence_denies_before_read() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ProcessIsolatedH3Authority::new(fixture.root.identity())
            .expect("persistent H3 Host authority");
        let broker = fixture.broker(Arc::new(RevokingAuthority {
            host: Arc::clone(&authority),
            calls: AtomicUsize::new(0),
        }));
        let result = run(&broker, fixture.request("call-revocation")).await;
        assert!(matches!(
            result.classification,
            Some(H3DenyClassification::RootDisabled | H3DenyClassification::StaleRevision)
        ));
        assert_eq!(broker.snapshot().authorized_file_reads, 0);
        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].canonical.as_ref().unwrap().outcome,
            "ScopeRequired"
        );
        assert_eq!(
            observations[0]
                .canonical
                .as_ref()
                .unwrap()
                .authorization_revision,
            Some(REVISION)
        );
        assert_eq!(
            observations[1].canonical.as_ref().unwrap().outcome,
            "RootDisabled"
        );
        assert_eq!(
            observations[1]
                .canonical
                .as_ref()
                .unwrap()
                .authorization_revision,
            Some(REVISION + 1)
        );
        assert!(authority.shutdown());
    }

    #[tokio::test]
    async fn same_sqlite_state_unchanged_revalidation_preserves_scope_evidence() {
        let fixture = Fixture::new(FILE_CONTENT.as_bytes());
        let authority = ProcessIsolatedH3Authority::new(fixture.root.identity())
            .expect("persistent H3 Host authority");
        let issue = fixture.authority_request(H3AuthorityOperation::IssueScopeGrant);
        let issued = authority.evaluate(issue.clone()).await.unwrap();
        assert_eq!(issued.canonical.outcome, H3CanonicalOutcome::ScopeRequired);
        assert_eq!(
            issued.canonical.decision_code,
            H3CanonicalDecisionCode::ScopeNotAvailable
        );
        assert_eq!(
            issued.canonical.scope_requirement,
            H3ScopeRequirement::WorkspaceRequired
        );
        let evidence = issued.scope_grant.clone().unwrap();
        let revalidated = authority
            .evaluate(H3AuthorityRequest {
                operation: H3AuthorityOperation::Revalidate {
                    grant_id: evidence.grant_id.clone(),
                    authorization_revision: evidence.authorization_revision,
                },
                ..issue
            })
            .await
            .unwrap();
        assert_eq!(revalidated.canonical.authorization_revision, Some(REVISION));
        assert_eq!(revalidated.scope_grant.unwrap().grant_id, evidence.grant_id);
        assert!(authority.shutdown());
    }

    #[test]
    fn production_surface_stays_closed_and_h3_tool_is_not_registered_in_tauri() {
        assert_eq!(VITA_WORKSPACE_READ_TOOL_NAME, "vita_workspace_read_file");
        assert_eq!(
            VITA_WORKSPACE_READ_CAPABILITY_ID,
            "vita.workspace.read_file"
        );
        let source =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
                .expect("read Vita entrypoint");
        assert!(!source.contains("VitaWorkspaceReadToolContributor"));
    }

    #[derive(Clone, Debug, Default)]
    struct H3FixtureObservation {
        request_count: usize,
        first_request_had_h3_tool: bool,
        first_request_excluded_revision: bool,
        tool_result_delivered: bool,
        success_content_delivered: bool,
        observed_call_id: Option<String>,
        error: Option<String>,
    }

    struct H3ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H3FixtureObservation>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl H3ResponsesFixture {
        fn start() -> Self {
            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("bind H3-R1 loopback fixture");
            let address = listener.local_addr().expect("H3-R1 fixture address");
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
                                Some(error.to_string());
                            return;
                        }
                    };
                    let result = handle_h3_fixture_request(&mut stream, peer, response_index);
                    let mut observed = lock_unpoisoned(&observation_for_thread);
                    observed.request_count += 1;
                    if response_index == 0 {
                        if let Ok(body) = &result {
                            observed.first_request_had_h3_tool = request_has_h3_tool(body);
                            observed.first_request_excluded_revision =
                                !String::from_utf8_lossy(body)
                                    .contains("expected_authorization_revision");
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

    const H3_MODEL: &str = "d29h3-r1-local-responses-model";
    const H3_PROMPT: &str = "Read the bounded Vita workspace file.";
    const H3_REPLY: &str = "VITA_D29H3_READ_OK";
    const H3_CALL_ID: &str = "call-d29h3-r1-read";
    const H3_PROVIDER_ID: &str = "d29h3-r1-loopback-responses";
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
            return Err("H3-R1 fixture received a non-loopback peer".to_string());
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
                "response": {"id": "resp-d29h3-r1-1", "object": "response", "status": "in_progress", "model": H3_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": H3_CALL_ID, "name": VITA_WORKSPACE_READ_TOOL_NAME, "arguments": "{\"relative_path\":\"read-me.txt\",\"max_bytes\":65536}"}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h3-r1-1", "object": "response", "status": "completed", "model": H3_MODEL}
            }),
        ]
    }

    fn h3_completion_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h3-r1-2", "object": "response", "status": "in_progress", "model": H3_MODEL}
            }),
            json!({
                "type": "response.output_item.added",
                "item": {"type": "message", "id": "msg-d29h3-r1", "role": "assistant", "status": "in_progress", "content": []}
            }),
            json!({"type": "response.content_part.added"}),
            json!({"type": "response.output_text.delta", "delta": H3_REPLY}),
            json!({"type": "response.output_text.done", "text": H3_REPLY}),
            json!({"type": "response.content_part.done"}),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "message", "id": "msg-d29h3-r1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": H3_REPLY}]}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h3-r1-2", "object": "response", "status": "completed", "model": H3_MODEL}
            }),
        ]
    }

    fn write_h3_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
        let mut body = String::new();
        for event in events {
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "H3-R1 fixture event omitted type".to_string())?;
            body.push_str("event: ");
            body.push_str(event_type);
            body.push_str("\ndata: ");
            body.push_str(
                &serde_json::to_string(&event)
                    .map_err(|_| "H3-R1 fixture event serialization failed".to_string())?,
            );
            body.push_str("\n\n");
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .set_write_timeout(Some(H3_HTTP_TIMEOUT))
            .map_err(|_| "H3-R1 fixture write timeout setup failed".to_string())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| "H3-R1 fixture response write failed".to_string())
    }

    fn read_h3_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        stream
            .set_read_timeout(Some(H3_HTTP_TIMEOUT))
            .map_err(|_| "H3-R1 fixture read timeout setup failed".to_string())?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "H3-R1 fixture request read failed".to_string())?;
            if read == 0 {
                return Err("H3-R1 fixture request closed before headers".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > H3_HTTP_MAX_BODY {
                return Err("H3-R1 fixture request exceeded bounded size".to_string());
            }
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let header = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| "H3-R1 fixture headers were not UTF-8".to_string())?;
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| "H3-R1 fixture omitted content length".to_string())?;
        if content_length > H3_HTTP_MAX_BODY {
            return Err("H3-R1 fixture content length exceeded bounded size".to_string());
        }
        while bytes.len() < header_end + content_length {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "H3-R1 fixture request body read failed".to_string())?;
            if read == 0 {
                return Err("H3-R1 fixture request closed before body".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        Ok(bytes[header_end..header_end + content_length].to_vec())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CodexStateCanary {
        files: [Option<(u64, Option<SystemTime>)>; 3],
    }

    fn codex_state_canary() -> CodexStateCanary {
        let root = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
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
        let app_data = tempdir().map_err(|_| "create H3-R1 app data failed".to_string())?;
        let workspace = tempdir().map_err(|_| "create H3-R1 workspace failed".to_string())?;
        fs::write(
            workspace.path().join("read-me.txt"),
            FILE_CONTENT.as_bytes(),
        )
        .map_err(|_| "create H3-R1 read fixture failed".to_string())?;
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
        )
        .map_err(|error| format!("create H3-R1 profile: {error}"))?;
        let fixture = H3ResponsesFixture::start();
        let provider = ProviderProfile::new_for_test_localhost(
            H3_PROVIDER_ID,
            "D29-H3-R1 loopback Responses fixture",
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
        .map_err(|error| format!("create H3-R1 provider: {error}"))?;
        let authority = VitaProviderAuthority::configure(provider)
            .map_err(|error| format!("configure H3-R1 provider: {error}"))?;
        let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
            .map_err(|error| format!("create H3-R1 private binding: {error}"))?;
        let ready = authority
            .prepare_gateway(binding)
            .map_err(|error| format!("prepare H3-R1 gateway: {error}"))?;
        let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
            .await
            .map_err(|error| format!("compile H3-R1 Codex config: {error}"))?;
        let config = entrypoint.config().clone();
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .map_err(|error| format!("create H3-R1 context: {error:?}"))?;
        let root = entrypoint
            .profile()
            .workspace_authority()
            .cloned()
            .ok_or_else(|| "H3-R1 requires the Windows workspace authority".to_string())?;
        let canonical_authority = ProcessIsolatedH3Authority::new(root.identity())?;
        let broker = VitaWorkspaceReadBroker::new(
            context,
            root,
            Arc::clone(&canonical_authority) as Arc<dyn VitaH3AuthorityPort>,
        );
        let mut extensions =
            codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extensions.tool_contributor(Arc::new(VitaWorkspaceReadToolContributor::new(Arc::clone(
            &broker,
        ))));
        let extensions = Arc::new(extensions.build());
        let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
            codex_core_api::CodexAuth::from_api_key("d29h3-r1-in-memory-kernel-auth"),
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
            "d29h3-r1-local-installation".to_string(),
            None,
            None,
        ));
        let new_thread = tokio::time::timeout(
            H3_TURN_TIMEOUT,
            manager.start_thread(codex_core_api::StartThreadOptions::new(config)),
        )
        .await
        .map_err(|_| "H3-R1 thread startup timed out".to_string())?
        .map_err(|error| format!("H3-R1 thread startup failed: {error}"))?;
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
        .map_err(|_| "H3-R1 turn submission timed out".to_string())?
        .map_err(|error| format!("H3-R1 turn submission failed: {error}"))?;
        let deadline = Instant::now() + H3_TURN_TIMEOUT;
        let mut event_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("H3-R1 turn did not reach a terminal event".to_string());
            }
            let event = tokio::time::timeout(remaining, thread.next_event())
                .await
                .map_err(|_| "H3-R1 event wait timed out".to_string())?
                .map_err(|error| format!("H3-R1 event stream failed: {error}"))?;
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
    fn d29h3_r1_real_codex_turn_uses_persistent_host_scope_and_same_state_fence() {
        thread::Builder::new()
            .name("d29h3-r1-real-codex-tool".to_string())
            .stack_size(H3_TEST_STACK_SIZE)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("H3-R1 test runtime should build");
                runtime.block_on(d29h3_r1_real_codex_turn_body());
            })
            .expect("H3-R1 test thread should start")
            .join()
            .expect("H3-R1 test thread should finish");
    }

    async fn d29h3_r1_real_codex_turn_body() {
        let (runtime, broker, authority, before) = start_h3_runtime()
            .await
            .expect("H3-R1 runtime should start");
        let turn = run_h3_turn(runtime.thread.as_ref().unwrap()).await;
        let (cleanup, fixture_observation) = runtime.shutdown().await;
        let host_shutdown = authority.shutdown();
        let turn = turn.unwrap_or_else(|error| {
            panic!("H3-R1 turn should complete: {error}; fixture={fixture_observation:?}; cleanup={cleanup:?}")
        });
        assert_eq!(
            before,
            codex_state_canary(),
            "H3-R1 user Codex state changed"
        );
        assert_eq!(turn.1, None);
        assert_eq!(turn.0.as_deref(), Some(H3_REPLY));
        assert!(turn.2 > 0);
        assert_eq!(cleanup.initial_shutdown, H3ShutdownStatus::Success);
        assert_eq!(cleanup.final_shutdown, H3ShutdownStatus::Success);
        assert_eq!(cleanup.manager_thread_count, 0);
        assert!(cleanup.fixture_listener_joined);
        assert!(host_shutdown);
        assert_eq!(fixture_observation.request_count, 2);
        assert!(fixture_observation.first_request_had_h3_tool);
        assert!(fixture_observation.first_request_excluded_revision);
        assert!(fixture_observation.tool_result_delivered);
        assert!(fixture_observation.success_content_delivered);
        assert_eq!(
            fixture_observation.observed_call_id.as_deref(),
            Some(H3_CALL_ID)
        );

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
            let canonical = observation.canonical.expect("Host canonical D28 result");
            assert_eq!(canonical.canonical_evaluations, 1);
            assert!(canonical.host_scope_authority_present);
            assert!(canonical.requested_root_matched_authorized_root);
            assert_eq!(canonical.production_registry_size, 0);
            assert_eq!(canonical.test_registry_size, 1);
            assert_eq!(canonical.authorization_row_reads, 1);
            assert_eq!(canonical.outcome, "ScopeRequired");
            assert_eq!(canonical.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
            assert_eq!(canonical.scope_requirement, "WorkspaceRequired");
            assert_eq!(canonical.approval_floor, "RootEnabled");
            assert_eq!(canonical.authorization_revision, Some(REVISION));
            let evidence = observation.scope_grant.expect("Host scope evidence");
            assert_eq!(evidence.scope, "workspace");
            assert_eq!(evidence.max_bytes, WORKSPACE_READ_HARD_MAX_BYTES as u64);
            assert_eq!(evidence.tool_call_id, H3_CALL_ID);
        }
    }

    fn unix_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}
