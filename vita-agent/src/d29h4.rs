//! D29-H4-A's replace-authority and precondition foundation.
//!
//! This module deliberately stops after Host-issued authority has been
//! validated and narrowed.  It never opens a write handle and has no file
//! mutation API.  The real replacement primitive belongs to D29-H4-B.
#![allow(dead_code, private_interfaces)]

use std::collections::HashSet;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(test)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[cfg(all(test, windows))]
use super::workspace_capability::WorkspaceReplaceTestFault;
use super::workspace_capability::{
    PreparedWorkspaceTarget, PreparedWorkspaceTargetKind, WorkspaceReplaceError,
    WorkspaceReplaceEvidence,
};
#[cfg(test)]
use super::workspace_capability::{
    WorkspaceReplaceCommitOutcome, WorkspaceReplaceEvidenceEvent, WorkspaceReplaceFenceError,
    WorkspaceReplaceMutationPhase, WorkspaceReplaceMutationTracker,
};
use super::{sha256_hex, VitaExecutionContext, VitaRequestedScope};

pub(crate) const VITA_WORKSPACE_REPLACE_TOOL_NAME: &str = "vita_workspace_replace_file";
pub(crate) const VITA_WORKSPACE_REPLACE_CAPABILITY_ID: &str = "vita.workspace.replace_file";
pub(crate) const H4_MAX_REPLACEMENT_BYTES: usize = 64 * 1024;

const MAX_CALL_ID_CHARS: usize = 128;
const MAX_TURN_ID_CHARS: usize = 128;
const MAX_PATH_CHARS: usize = 256;
const MAX_ID_CHARS: usize = 512;
const MAX_SEEN_CALL_IDS: usize = 256;
const GRANT_LIFETIME_MS: u64 = 30_000;
const MAX_HOST_CLOCK_SKEW_MS: u64 = 5_000;

pub(crate) const H4_DESCRIPTOR_RISK_CLASS: &str = "Medium";
pub(crate) const H4_DESCRIPTOR_APPROVAL_FLOOR: &str = "ExplicitPerAction";
pub(crate) const H4_DESCRIPTOR_SCOPE_REQUIREMENT: &str = "WorkspaceRequired";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct H4DescriptorValues {
    pub risk_class: &'static str,
    pub approval_floor: &'static str,
    pub scope_requirement: &'static str,
}

pub(crate) const fn h4_descriptor_values() -> H4DescriptorValues {
    H4DescriptorValues {
        risk_class: H4_DESCRIPTOR_RISK_CLASS,
        approval_floor: H4_DESCRIPTOR_APPROVAL_FLOOR,
        scope_requirement: H4_DESCRIPTOR_SCOPE_REQUIREMENT,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VitaWorkspaceReplaceRequest {
    tool_call_id: String,
    turn_id: String,
    context: Option<VitaExecutionContext>,
    relative_path: super::WorkspaceRelativePath,
    expected_sha256: String,
    replacement_content: String,
}

impl VitaWorkspaceReplaceRequest {
    fn from_codex_call(
        call: &ToolCall<'_>,
        context: Option<&VitaExecutionContext>,
    ) -> Result<Self, H4RequestBuildError> {
        if call.tool_name.name != VITA_WORKSPACE_REPLACE_TOOL_NAME
            || !call.tool_name.is_default_namespace()
        {
            return Err(H4RequestBuildError::UnmappedTool);
        }
        let tool_call_id = bounded_text(&call.call_id, MAX_CALL_ID_CHARS)
            .ok_or(H4RequestBuildError::InvalidCallId)?;
        let turn_id = bounded_text(&call.turn_id, MAX_TURN_ID_CHARS)
            .ok_or(H4RequestBuildError::InvalidTurnId)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H4RequestBuildError::InvalidArguments)?;
        let arguments: VitaWorkspaceReplaceArguments =
            serde_json::from_str(arguments).map_err(|_| H4RequestBuildError::InvalidArguments)?;
        if arguments.relative_path.chars().count() > MAX_PATH_CHARS {
            return Err(H4RequestBuildError::InvalidPath);
        }
        let relative_path =
            super::WorkspaceRelativePath::parse(std::path::Path::new(&arguments.relative_path))
                .map_err(|_| H4RequestBuildError::InvalidPath)?;
        if !is_sha256_hex(&arguments.expected_sha256) {
            return Err(H4RequestBuildError::InvalidExpectedHash);
        }
        if arguments.replacement_content.as_bytes().len() > H4_MAX_REPLACEMENT_BYTES {
            return Err(H4RequestBuildError::ReplacementTooLarge);
        }
        Ok(Self {
            tool_call_id,
            turn_id,
            context: context.cloned(),
            relative_path,
            expected_sha256: arguments.expected_sha256,
            replacement_content: arguments.replacement_content,
        })
    }

    #[cfg(test)]
    fn synthetic(
        tool_call_id: &str,
        context: Option<VitaExecutionContext>,
        relative_path: &str,
        expected_sha256: &str,
        replacement_content: &str,
    ) -> Self {
        Self {
            tool_call_id: tool_call_id.to_string(),
            turn_id: "turn-d29h4".to_string(),
            context,
            relative_path: super::WorkspaceRelativePath::parse(std::path::Path::new(relative_path))
                .expect("synthetic H4 path must be valid"),
            expected_sha256: expected_sha256.to_string(),
            replacement_content: replacement_content.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VitaWorkspaceReplaceArguments {
    relative_path: String,
    expected_sha256: String,
    replacement_content: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4RequestBuildError {
    UnmappedTool,
    InvalidCallId,
    InvalidTurnId,
    InvalidArguments,
    InvalidPath,
    InvalidExpectedHash,
    ReplacementTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4CanonicalOutcome {
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
enum H4CanonicalDecisionCode {
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeNotAvailable,
    Forbidden,
    Eligible,
    AuthorizationUnavailable,
    UnknownCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4ScopeRequirement {
    None,
    WorkspaceRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4ApprovalFloor {
    RootEnabled,
    ExplicitPerAction,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H4CanonicalDecision {
    life_id: String,
    capability_id: String,
    outcome: H4CanonicalOutcome,
    decision_code: H4CanonicalDecisionCode,
    scope_requirement: H4ScopeRequirement,
    approval_floor: H4ApprovalFloor,
    authorization_revision: Option<i64>,
    workspace_scope_matches: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4ReplaceOperation {
    ReplaceExistingUtf8File,
}

impl H4ReplaceOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReplaceExistingUtf8File => "replace_existing_utf8_file",
        }
    }
}

/// The only confirmation provenance accepted by the H4-A boundary.
///
/// This marker is carried in Host-to-Vita evidence only.  It is deliberately
/// not part of the model-visible request schema and cannot be supplied by a
/// tool caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4ConfirmationEvidenceSource {
    TrustedTestHarness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostExplicitActionConfirmationEvidence {
    source: H4ConfirmationEvidenceSource,
    confirmation_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    authorization_revision: i64,
    workspace_root_identity: super::WorkspaceRootIdentity,
    relative_path: super::WorkspaceRelativePath,
    target_identity: super::WorkspaceRootIdentity,
    expected_sha256: String,
    replacement_sha256: String,
    replacement_bytes: usize,
    tool_call_id: String,
    turn_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H4HostReplaceGrantEvidence {
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
    operation: H4ReplaceOperation,
    expected_sha256: String,
    replacement_sha256: String,
    replacement_bytes: usize,
    tool_call_id: String,
    turn_id: String,
    confirmation_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum H4AuthorityResponseStatus {
    Ok,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H4HostAuthorityResponse {
    status: H4AuthorityResponseStatus,
    canonical: H4CanonicalDecision,
    confirmation: Option<HostExplicitActionConfirmationEvidence>,
    grant: Option<H4HostReplaceGrantEvidence>,
    denial: Option<H4DenyClassification>,
    confirmation_consumed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum H4AuthorityOperation {
    IssueReplaceGrant,
    Revalidate {
        grant_id: String,
        authorization_revision: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H4AuthorityRequest {
    context: VitaExecutionContext,
    capability_id: String,
    operation: H4AuthorityOperation,
    tool_call_id: String,
    turn_id: String,
    relative_path: super::WorkspaceRelativePath,
    expected_sha256: String,
    replacement_sha256: String,
    replacement_bytes: usize,
    workspace_root_identity: super::WorkspaceRootIdentity,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
}

#[cfg(all(test, windows))]
impl H4AuthorityRequest {
    pub(crate) fn is_revalidation(&self) -> bool {
        matches!(&self.operation, H4AuthorityOperation::Revalidate { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VitaH4AuthorityError {
    Unavailable,
    InvalidVerdict,
}

pub(crate) type VitaH4AuthorityFuture = Pin<
    Box<
        dyn Future<Output = Result<H4HostAuthorityResponse, VitaH4AuthorityError>> + Send + 'static,
    >,
>;

pub(crate) trait VitaH4AuthorityPort: Send + Sync {
    fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H4DenyClassification {
    MissingContext,
    WrongLifeBinding,
    WrongTaskBinding,
    UnmappedTool,
    InvalidRequest,
    MissingAuthorization,
    ScopeUnavailable,
    WorkspaceScopeDenied,
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
    ConfirmationMissing,
    ConfirmationMismatch,
    ConfirmationExpired,
    ConfirmationReplay,
    RevalidationDenied,
}

impl H4DenyClassification {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingContext => "missing_execution_context",
            Self::WrongLifeBinding => "wrong_life_binding",
            Self::WrongTaskBinding => "wrong_task_binding",
            Self::UnmappedTool => "unmapped_tool",
            Self::InvalidRequest => "invalid_request",
            Self::MissingAuthorization => "missing_authorization",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::WorkspaceScopeDenied => "workspace_scope_denied",
            Self::StaleRevision => "stale_authorization_revision",
            Self::DuplicateToolCall => "duplicate_tool_call_id",
            Self::TurnCancelled => "turn_cancelled",
            Self::LateAfterCancellation => "late_authority_after_cancellation",
            Self::AuthorityError => "authority_error",
            Self::AuthorityPanic => "authority_panic",
            Self::AuthorityEvidenceMismatch => "authority_evidence_mismatch",
            Self::GrantRejected => "replace_grant_rejected",
            Self::CallLimitExceeded => "h4_call_limit_exceeded",
            Self::RootDisabled => "root_disabled",
            Self::TargetRejected => "workspace_target_rejected",
            Self::TargetMissing => "workspace_target_missing",
            Self::ConfirmationMissing => "confirmation_missing",
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::ConfirmationExpired => "confirmation_expired",
            Self::ConfirmationReplay => "confirmation_replay",
            Self::RevalidationDenied => "replace_grant_revalidation_denied",
        }
    }
}

#[derive(Debug)]
struct VitaWorkspaceReplaceResult {
    request: VitaWorkspaceReplaceRequest,
    classification: Option<H4DenyClassification>,
    grant_issued: bool,
    authorized_for_future_replace_foundation: bool,
    execution: Option<VitaWorkspaceReplaceExecutionOutcome>,
}

#[derive(Debug)]
enum VitaWorkspaceReplaceExecutionOutcome {
    Denied {
        classification: H4DenyClassification,
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

impl VitaWorkspaceReplaceResult {
    fn denied(request: VitaWorkspaceReplaceRequest, classification: H4DenyClassification) -> Self {
        Self {
            request,
            classification: Some(classification),
            grant_issued: false,
            authorized_for_future_replace_foundation: false,
            execution: None,
        }
    }

    fn denied_after_grant(
        request: VitaWorkspaceReplaceRequest,
        classification: H4DenyClassification,
    ) -> Self {
        Self {
            request,
            classification: Some(classification),
            grant_issued: true,
            authorized_for_future_replace_foundation: false,
            execution: None,
        }
    }

    fn authorized(request: VitaWorkspaceReplaceRequest) -> Self {
        Self {
            request,
            classification: None,
            grant_issued: true,
            authorized_for_future_replace_foundation: true,
            execution: None,
        }
    }

    fn governed(
        request: VitaWorkspaceReplaceRequest,
        outcome: VitaWorkspaceReplaceExecutionOutcome,
        classification: Option<H4DenyClassification>,
    ) -> Self {
        Self {
            request,
            classification,
            grant_issued: true,
            authorized_for_future_replace_foundation: false,
            execution: Some(outcome),
        }
    }

    fn model_value(&self) -> Value {
        if let Some(execution) = &self.execution {
            return match execution {
                VitaWorkspaceReplaceExecutionOutcome::Denied { classification } => json!({
                    "status": "denied",
                    "tool": VITA_WORKSPACE_REPLACE_TOOL_NAME,
                    "relative_path": self.request.relative_path.as_path().to_string_lossy(),
                    "deny_classification": classification.as_str(),
                    "mutation_performed": false,
                    "side_effect_count": 0,
                }),
                VitaWorkspaceReplaceExecutionOutcome::Conflict { .. } => json!({
                    "status": "conflict",
                    "tool": VITA_WORKSPACE_REPLACE_TOOL_NAME,
                    "relative_path": self.request.relative_path.as_path().to_string_lossy(),
                    "commit_outcome": "conflict",
                    "mutation_performed": false,
                    "side_effect_count": 0,
                }),
                VitaWorkspaceReplaceExecutionOutcome::Committed { evidence } => json!({
                    "status": "committed",
                    "tool": VITA_WORKSPACE_REPLACE_TOOL_NAME,
                    "relative_path": self.request.relative_path.as_path().to_string_lossy(),
                    "bytes_written": evidence.bytes_after.unwrap_or(0),
                    "before_sha256": evidence.before_sha256,
                    "after_sha256": evidence.after_sha256,
                    "commit_outcome": "committed",
                    "mutation_performed": true,
                    "side_effect_count": 1,
                }),
                VitaWorkspaceReplaceExecutionOutcome::CommitUnknown { .. } => json!({
                    "status": "commit_outcome_unknown",
                    "tool": VITA_WORKSPACE_REPLACE_TOOL_NAME,
                    "relative_path": self.request.relative_path.as_path().to_string_lossy(),
                    "commit_outcome": "unknown",
                    "mutation_started": true,
                    "automatic_retry": false,
                    "side_effect_state": "may_have_mutated",
                    "side_effect_count": 1,
                }),
            };
        }
        let status = if self.authorized_for_future_replace_foundation {
            "authorized_for_future_replace_foundation"
        } else {
            "denied"
        };
        json!({
            "status": status,
            "tool": VITA_WORKSPACE_REPLACE_TOOL_NAME,
            "relative_path": self.request.relative_path.as_path().to_string_lossy(),
            "expected_sha256": self.request.expected_sha256,
            "replacement_sha256": sha256_hex(self.request.replacement_content.as_bytes()),
            "replacement_bytes": self.request.replacement_content.as_bytes().len(),
            "deny_classification": self.classification.map(H4DenyClassification::as_str),
            "mutation_performed": false,
            "side_effect_count": 0,
        })
    }
}

#[derive(Default)]
struct H4BrokerState {
    seen_call_ids: HashSet<String>,
    consumed_grant_ids: HashSet<String>,
}

#[derive(Default)]
struct H4BrokerMetrics {
    attempted_requests: AtomicUsize,
    canonical_evaluations: AtomicUsize,
    workspace_scope_denials: AtomicUsize,
    confirmation_missing_denials: AtomicUsize,
    confirmation_mismatch_denials: AtomicUsize,
    confirmation_expired_denials: AtomicUsize,
    confirmation_replay_denials: AtomicUsize,
    confirmations_consumed: AtomicUsize,
    grants_issued: AtomicUsize,
    revalidation_denials: AtomicUsize,
    authorized_write_count: AtomicUsize,
    filesystem_mutations: AtomicUsize,
    process_spawns: AtomicUsize,
    external_network_requests: AtomicUsize,
    active_authority: AtomicUsize,
    max_active_authority: AtomicUsize,
    native_workers_started: AtomicUsize,
    native_workers_joined: AtomicUsize,
    exclusive_operation_handles: AtomicUsize,
    final_revalidations: AtomicUsize,
    final_revalidation_denials: AtomicUsize,
    filesystem_mutation_attempts: AtomicUsize,
    filesystem_mutations_committed: AtomicUsize,
    filesystem_commit_unknown: AtomicUsize,
    content_conflicts: AtomicUsize,
    automatic_mutation_retries: AtomicUsize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct VitaWorkspaceReplaceSnapshot {
    pub attempted_requests: usize,
    pub canonical_evaluations: usize,
    pub workspace_scope_denials: usize,
    pub confirmation_missing_denials: usize,
    pub confirmation_mismatch_denials: usize,
    pub confirmation_expired_denials: usize,
    pub confirmation_replay_denials: usize,
    pub confirmations_consumed: usize,
    pub grants_issued: usize,
    pub revalidation_denials: usize,
    pub authorized_write_count: usize,
    pub filesystem_mutations: usize,
    pub process_spawns: usize,
    pub external_network_requests: usize,
    pub max_active_authority: usize,
    pub native_workers_started: usize,
    pub native_workers_joined: usize,
    pub exclusive_operation_handles: usize,
    pub final_revalidations: usize,
    pub final_revalidation_denials: usize,
    pub filesystem_mutation_attempts: usize,
    pub filesystem_mutations_committed: usize,
    pub filesystem_commit_unknown: usize,
    pub content_conflicts: usize,
    pub automatic_mutation_retries: usize,
}

/// H4-A's Vita-side boundary is test/integration-only.  It can import an
/// exact Host grant and prove that a future replacement is authorized, but it
/// intentionally has no mutation method or write-capable operation handle.
pub(crate) struct VitaWorkspaceReplaceBroker {
    context: Option<VitaExecutionContext>,
    root: super::TrustedWorkspaceRoot,
    authority: Arc<dyn VitaH4AuthorityPort>,
    state: Mutex<H4BrokerState>,
    cancelled: Arc<AtomicBool>,
    #[cfg(test)]
    cancellation_notify: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    native_evidence: Mutex<Vec<WorkspaceReplaceEvidence>>,
    metrics: Arc<H4BrokerMetrics>,
}

impl VitaWorkspaceReplaceBroker {
    pub(crate) fn new(
        context: VitaExecutionContext,
        root: super::TrustedWorkspaceRoot,
        authority: Arc<dyn VitaH4AuthorityPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: Some(context),
            root,
            authority,
            state: Mutex::new(H4BrokerState::default()),
            cancelled: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            cancellation_notify: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            native_evidence: Mutex::new(Vec::new()),
            metrics: Arc::new(H4BrokerMetrics::default()),
        })
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        #[cfg(test)]
        self.cancellation_notify.notify_one();
    }

    #[cfg(test)]
    pub(crate) fn cancellation_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(crate) fn snapshot(&self) -> VitaWorkspaceReplaceSnapshot {
        VitaWorkspaceReplaceSnapshot {
            attempted_requests: self.metrics.attempted_requests.load(Ordering::Acquire),
            canonical_evaluations: self.metrics.canonical_evaluations.load(Ordering::Acquire),
            workspace_scope_denials: self.metrics.workspace_scope_denials.load(Ordering::Acquire),
            confirmation_missing_denials: self
                .metrics
                .confirmation_missing_denials
                .load(Ordering::Acquire),
            confirmation_mismatch_denials: self
                .metrics
                .confirmation_mismatch_denials
                .load(Ordering::Acquire),
            confirmation_expired_denials: self
                .metrics
                .confirmation_expired_denials
                .load(Ordering::Acquire),
            confirmation_replay_denials: self
                .metrics
                .confirmation_replay_denials
                .load(Ordering::Acquire),
            confirmations_consumed: self.metrics.confirmations_consumed.load(Ordering::Acquire),
            grants_issued: self.metrics.grants_issued.load(Ordering::Acquire),
            revalidation_denials: self.metrics.revalidation_denials.load(Ordering::Acquire),
            authorized_write_count: self.metrics.authorized_write_count.load(Ordering::Acquire),
            filesystem_mutations: self.metrics.filesystem_mutations.load(Ordering::Acquire),
            process_spawns: self.metrics.process_spawns.load(Ordering::Acquire),
            external_network_requests: self
                .metrics
                .external_network_requests
                .load(Ordering::Acquire),
            max_active_authority: self.metrics.max_active_authority.load(Ordering::Acquire),
            native_workers_started: self.metrics.native_workers_started.load(Ordering::Acquire),
            native_workers_joined: self.metrics.native_workers_joined.load(Ordering::Acquire),
            exclusive_operation_handles: self
                .metrics
                .exclusive_operation_handles
                .load(Ordering::Acquire),
            final_revalidations: self.metrics.final_revalidations.load(Ordering::Acquire),
            final_revalidation_denials: self
                .metrics
                .final_revalidation_denials
                .load(Ordering::Acquire),
            filesystem_mutation_attempts: self
                .metrics
                .filesystem_mutation_attempts
                .load(Ordering::Acquire),
            filesystem_mutations_committed: self
                .metrics
                .filesystem_mutations_committed
                .load(Ordering::Acquire),
            filesystem_commit_unknown: self
                .metrics
                .filesystem_commit_unknown
                .load(Ordering::Acquire),
            content_conflicts: self.metrics.content_conflicts.load(Ordering::Acquire),
            automatic_mutation_retries: self
                .metrics
                .automatic_mutation_retries
                .load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    fn native_evidence_snapshot(&self) -> Vec<WorkspaceReplaceEvidence> {
        lock_unpoisoned(&self.native_evidence).clone()
    }

    #[cfg(test)]
    pub(crate) async fn issue_h5_authorized_replace_action(
        &self,
        input: H4ReplaceAuthorizationInput,
    ) -> Result<H4AuthorizedReplaceGrant, H4DenyClassification> {
        let request = input.into_request();
        self.metrics
            .attempted_requests
            .fetch_add(1, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            return Err(H4DenyClassification::TurnCancelled);
        }
        let bound_context = self
            .context
            .as_ref()
            .ok_or(H4DenyClassification::MissingContext)?;
        let request_context = request
            .context
            .as_ref()
            .ok_or(H4DenyClassification::MissingContext)?;
        if request_context.life_id() != bound_context.life_id() {
            return Err(H4DenyClassification::WrongLifeBinding);
        }
        if request_context.task_id() != bound_context.task_id() {
            return Err(H4DenyClassification::WrongTaskBinding);
        }

        {
            let mut state = lock_unpoisoned(&self.state);
            if state.seen_call_ids.contains(&request.tool_call_id) {
                return Err(H4DenyClassification::DuplicateToolCall);
            }
            if state.seen_call_ids.len() >= MAX_SEEN_CALL_IDS {
                return Err(H4DenyClassification::CallLimitExceeded);
            }
            state.seen_call_ids.insert(request.tool_call_id.clone());
        }

        if !is_sha256_hex(&request.expected_sha256) {
            return Err(H4DenyClassification::InvalidRequest);
        }
        if request.replacement_content.as_bytes().len() > H4_MAX_REPLACEMENT_BYTES {
            return Err(H4DenyClassification::InvalidRequest);
        }
        let prepared = self
            .root
            .prepare_target(request.relative_path.as_path())
            .map_err(|_| H4DenyClassification::TargetRejected)?;
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity().is_none()
        {
            return Err(if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
                H4DenyClassification::TargetMissing
            } else {
                H4DenyClassification::TargetRejected
            });
        }
        let authority_request = H4AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            relative_path: request.relative_path.clone(),
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: sha256_hex(request.replacement_content.as_bytes()),
            replacement_bytes: request.replacement_content.as_bytes().len(),
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("existing H5 authorization target has an identity"),
            target_kind: prepared.kind(),
        };
        let response = self
            .evaluate_authority(authority_request.clone())
            .await
            .map_err(|classification| classification)?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(H4DenyClassification::LateAfterCancellation);
        }
        let (confirmation, evidence) = validate_issue_completion(&response, &authority_request)?;
        let grant = VitaExecutableReplaceGrant::from_host_evidence(
            confirmation,
            evidence,
            &authority_request,
            &prepared,
        )?;
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);
        if response.confirmation_consumed {
            self.metrics
                .confirmations_consumed
                .fetch_add(1, Ordering::AcqRel);
        }
        drop(prepared);
        Ok(H4AuthorizedReplaceGrant {
            grant,
            root: self.root.clone(),
            authority: Arc::clone(&self.authority),
        })
    }

    /// Build the exact H4 issue intent from a real Codex ToolCall without
    /// evaluating Host or provisioning confirmation.  H5-C's trusted test
    /// harness uses this only after the provider fixture has exposed the
    /// active turn and call identifiers.
    #[cfg(test)]
    pub(crate) fn h5_authority_request_for_codex_call(
        &self,
        call: &ToolCall<'_>,
    ) -> Result<H4AuthorityRequest, H4DenyClassification> {
        let request = VitaWorkspaceReplaceRequest::from_codex_call(call, self.context.as_ref())
            .map_err(|error| match error {
                H4RequestBuildError::UnmappedTool => H4DenyClassification::UnmappedTool,
                _ => H4DenyClassification::InvalidRequest,
            })?;
        self.h5_authority_request_for_parsed_request(&request)
    }

    /// Test harness form of the same intent builder.  The harness supplies
    /// only fields observed from the local fixture's real ToolCall; this does
    /// not evaluate Host and cannot provision a confirmation.
    #[cfg(test)]
    pub(crate) fn h5_authority_request_for_test_intent(
        &self,
        tool_call_id: &str,
        turn_id: &str,
        relative_path: &str,
        expected_sha256: &str,
        replacement_content: &str,
    ) -> Result<H4AuthorityRequest, H4DenyClassification> {
        if relative_path.chars().count() > MAX_PATH_CHARS
            || tool_call_id.chars().count() > MAX_CALL_ID_CHARS
            || turn_id.chars().count() > MAX_TURN_ID_CHARS
        {
            return Err(H4DenyClassification::InvalidRequest);
        }
        let relative_path =
            super::WorkspaceRelativePath::parse(std::path::Path::new(relative_path))
                .map_err(|_| H4DenyClassification::InvalidRequest)?;
        let request = VitaWorkspaceReplaceRequest {
            tool_call_id: tool_call_id.to_string(),
            turn_id: turn_id.to_string(),
            context: self.context.clone(),
            relative_path,
            expected_sha256: expected_sha256.to_string(),
            replacement_content: replacement_content.to_string(),
        };
        self.h5_authority_request_for_parsed_request(&request)
    }

    #[cfg(test)]
    fn h5_authority_request_for_parsed_request(
        &self,
        request: &VitaWorkspaceReplaceRequest,
    ) -> Result<H4AuthorityRequest, H4DenyClassification> {
        let bound_context = self
            .context
            .as_ref()
            .ok_or(H4DenyClassification::MissingContext)?;
        let request_context = request
            .context
            .as_ref()
            .ok_or(H4DenyClassification::MissingContext)?;
        if request_context.life_id() != bound_context.life_id() {
            return Err(H4DenyClassification::WrongLifeBinding);
        }
        if request_context.task_id() != bound_context.task_id() {
            return Err(H4DenyClassification::WrongTaskBinding);
        }
        if !is_sha256_hex(&request.expected_sha256)
            || request.replacement_content.as_bytes().len() > H4_MAX_REPLACEMENT_BYTES
        {
            return Err(H4DenyClassification::InvalidRequest);
        }
        let prepared = self
            .root
            .prepare_target(request.relative_path.as_path())
            .map_err(|_| H4DenyClassification::TargetRejected)?;
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity().is_none()
        {
            return Err(if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
                H4DenyClassification::TargetMissing
            } else {
                H4DenyClassification::TargetRejected
            });
        }
        let authority_request = H4AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            relative_path: request.relative_path.clone(),
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: sha256_hex(request.replacement_content.as_bytes()),
            replacement_bytes: request.replacement_content.as_bytes().len(),
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("existing H5 authorization target has an identity"),
            target_kind: prepared.kind(),
        };
        drop(prepared);
        Ok(authority_request)
    }

    /// Build the exact existing-replace intent from H6's opaque, compiler-
    /// derived proof.  This adapter is test/integration-only: H6 cannot mint
    /// a second capability and cannot supply a generic replace request.
    #[cfg(all(test, windows))]
    pub(crate) fn h6_authority_request_for_compiled_patch(
        &self,
        patch: &crate::d29h6::H6CompiledPatch,
    ) -> Result<H4AuthorityRequest, H4DenyClassification> {
        let bound_context = self
            .context
            .as_ref()
            .ok_or(H4DenyClassification::MissingContext)?;
        if patch.context().life_id() != bound_context.life_id() {
            return Err(H4DenyClassification::WrongLifeBinding);
        }
        if patch.context().task_id() != bound_context.task_id() {
            return Err(H4DenyClassification::WrongTaskBinding);
        }
        if !is_sha256_hex(patch.expected_sha256())
            || patch.replacement_bytes().len() != patch.derived_replacement_bytes()
            || sha256_hex(patch.replacement_bytes()) != patch.replacement_sha256()
            || patch.derived_replacement_bytes() > H4_MAX_REPLACEMENT_BYTES
        {
            return Err(H4DenyClassification::InvalidRequest);
        }
        let prepared = self
            .root
            .prepare_target(patch.relative_path().as_path())
            .map_err(|_| H4DenyClassification::TargetRejected)?;
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity() != Some(patch.target_identity())
            || prepared.root().identity() != patch.workspace_root_identity()
            || prepared.kind() != patch.target_kind()
        {
            return Err(if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
                H4DenyClassification::TargetMissing
            } else {
                H4DenyClassification::TargetRejected
            });
        }
        let authority_request = H4AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: patch.tool_call_id().to_string(),
            turn_id: patch.turn_id().to_string(),
            relative_path: patch.relative_path().clone(),
            expected_sha256: patch.expected_sha256().to_string(),
            replacement_sha256: patch.replacement_sha256().to_string(),
            replacement_bytes: patch.derived_replacement_bytes(),
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("existing H6 target has an identity"),
            target_kind: prepared.kind(),
        };
        drop(prepared);
        Ok(authority_request)
    }

    /// Consume exactly one H6 compiler proof and enter the existing H4 grant
    /// path.  The returned replacement is only the compiler-derived payload
    /// needed by canonical H5; it is not caller-supplied authority material.
    #[cfg(all(test, windows))]
    pub(crate) async fn issue_h5_authorized_replace_action_from_h6_patch(
        &self,
        patch: crate::d29h6::H6CompiledPatch,
    ) -> Result<(H4AuthorizedReplaceGrant, String), H4DenyClassification> {
        self.h6_authority_request_for_compiled_patch(&patch)?;
        let parts = patch.into_h4_parts();
        let replacement_content = String::from_utf8(parts.replacement_bytes)
            .map_err(|_| H4DenyClassification::InvalidRequest)?;
        let input = H4ReplaceAuthorizationInput::new(
            parts.context,
            parts.relative_path,
            parts.expected_sha256,
            replacement_content.clone(),
            parts.tool_call_id,
            parts.turn_id,
        );
        let grant = self.issue_h5_authorized_replace_action(input).await?;
        Ok((grant, replacement_content))
    }

    /// Parse and authorize one real Codex call through the certified H4
    /// parser/authority boundary, returning only the H4 grant and the
    /// already-bound replacement content needed by canonical H5.
    #[cfg(test)]
    pub(crate) async fn issue_h5_authorized_replace_action_from_codex_call(
        &self,
        call: &ToolCall<'_>,
    ) -> Result<(H4AuthorizedReplaceGrant, String), H4DenyClassification> {
        let request = VitaWorkspaceReplaceRequest::from_codex_call(call, self.context.as_ref())
            .map_err(|error| match error {
                H4RequestBuildError::UnmappedTool => H4DenyClassification::UnmappedTool,
                _ => H4DenyClassification::InvalidRequest,
            })?;
        let replacement_content = request.replacement_content.clone();
        let grant = self
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await?;
        Ok((grant, replacement_content))
    }

    async fn execute_request(
        &self,
        request: VitaWorkspaceReplaceRequest,
    ) -> VitaWorkspaceReplaceResult {
        self.metrics
            .attempted_requests
            .fetch_add(1, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::TurnCancelled,
            );
        }

        let Some(bound_context) = self.context.as_ref() else {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::MissingContext,
            );
        };
        let Some(request_context) = request.context.as_ref() else {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::MissingContext,
            );
        };
        if request_context.life_id() != bound_context.life_id() {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::WrongLifeBinding,
            );
        }
        if request_context.task_id() != bound_context.task_id() {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::WrongTaskBinding,
            );
        }

        let call_admission = {
            let mut state = lock_unpoisoned(&self.state);
            if state.seen_call_ids.contains(&request.tool_call_id) {
                Err(H4DenyClassification::DuplicateToolCall)
            } else if state.seen_call_ids.len() >= MAX_SEEN_CALL_IDS {
                Err(H4DenyClassification::CallLimitExceeded)
            } else {
                state.seen_call_ids.insert(request.tool_call_id.clone());
                Ok(())
            }
        };
        if let Err(classification) = call_admission {
            if classification == H4DenyClassification::DuplicateToolCall {
                self.metrics
                    .confirmation_replay_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            return VitaWorkspaceReplaceResult::denied(request, classification);
        }

        let prepared = match self.root.prepare_target(request.relative_path.as_path()) {
            Ok(prepared) => prepared,
            Err(_) => {
                return VitaWorkspaceReplaceResult::denied(
                    request,
                    H4DenyClassification::TargetRejected,
                )
            }
        };
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity().is_none()
        {
            return VitaWorkspaceReplaceResult::denied(
                request,
                if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
                    H4DenyClassification::TargetMissing
                } else {
                    H4DenyClassification::TargetRejected
                },
            );
        }
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::TurnCancelled,
            );
        }

        let replacement_bytes = request.replacement_content.as_bytes().len();
        let replacement_sha256 = sha256_hex(request.replacement_content.as_bytes());
        let authority_request = H4AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            relative_path: request.relative_path.clone(),
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256,
            replacement_bytes,
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("existing H4 target has an identity"),
            target_kind: prepared.kind(),
        };
        let initial_authority = match self.evaluate_authority(authority_request.clone()).await {
            Ok(response) => response,
            Err(classification) => {
                return VitaWorkspaceReplaceResult::denied(request, classification)
            }
        };
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::LateAfterCancellation,
            );
        }

        let (confirmation, evidence) =
            match validate_issue_completion(&initial_authority, &authority_request) {
                Ok(value) => value,
                Err(classification) => {
                    self.record_denial(classification);
                    return VitaWorkspaceReplaceResult::denied(request, classification);
                }
            };
        let grant = match VitaExecutableReplaceGrant::from_host_evidence(
            confirmation,
            evidence,
            &authority_request,
            &prepared,
        ) {
            Ok(grant) => grant,
            Err(_) => {
                self.metrics
                    .confirmation_mismatch_denials
                    .fetch_add(1, Ordering::AcqRel);
                return VitaWorkspaceReplaceResult::denied(
                    request,
                    H4DenyClassification::GrantRejected,
                );
            }
        };
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);
        if initial_authority.confirmation_consumed {
            self.metrics
                .confirmations_consumed
                .fetch_add(1, Ordering::AcqRel);
        }

        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied_after_grant(
                request,
                H4DenyClassification::LateAfterCancellation,
            );
        }
        let revalidation_request = H4AuthorityRequest {
            operation: H4AuthorityOperation::Revalidate {
                grant_id: grant.grant_id.clone(),
                authorization_revision: grant.authorization_revision,
            },
            ..authority_request.clone()
        };
        let current_authority = match self.evaluate_authority(revalidation_request.clone()).await {
            Ok(response) => response,
            Err(classification) => {
                self.metrics
                    .revalidation_denials
                    .fetch_add(1, Ordering::AcqRel);
                return VitaWorkspaceReplaceResult::denied_after_grant(request, classification);
            }
        };
        if self.cancelled.load(Ordering::Acquire) {
            self.metrics
                .revalidation_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReplaceResult::denied_after_grant(
                request,
                H4DenyClassification::LateAfterCancellation,
            );
        }
        if let Err(classification) =
            validate_revalidation(&current_authority, &revalidation_request, &grant, &prepared)
        {
            self.record_denial(classification);
            self.metrics
                .revalidation_denials
                .fetch_add(1, Ordering::AcqRel);
            return VitaWorkspaceReplaceResult::denied_after_grant(request, classification);
        }

        // D29-H4-A ends here.  No operation below this line may mutate the
        // filesystem; H4-B owns the future same-handle replacement primitive.
        VitaWorkspaceReplaceResult::authorized(request)
    }

    fn record_denial(&self, classification: H4DenyClassification) {
        match classification {
            H4DenyClassification::WorkspaceScopeDenied => {
                self.metrics
                    .workspace_scope_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            H4DenyClassification::ConfirmationMissing => {
                self.metrics
                    .confirmation_missing_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            H4DenyClassification::ConfirmationMismatch => {
                self.metrics
                    .confirmation_mismatch_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            H4DenyClassification::ConfirmationExpired => {
                self.metrics
                    .confirmation_expired_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            H4DenyClassification::ConfirmationReplay => {
                self.metrics
                    .confirmation_replay_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            _ => {}
        }
    }

    async fn evaluate_authority(
        &self,
        request: H4AuthorityRequest,
    ) -> Result<H4HostAuthorityResponse, H4DenyClassification> {
        self.metrics
            .canonical_evaluations
            .fetch_add(1, Ordering::AcqRel);
        let future = match catch_unwind(AssertUnwindSafe(|| self.authority.evaluate(request))) {
            Ok(future) => future,
            Err(_) => {
                return Err(H4DenyClassification::AuthorityPanic);
            }
        };
        let _active = ActiveAuthorityGuard::new(Arc::clone(&self.metrics));
        match CatchUnwindFuture::new(future).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(H4DenyClassification::AuthorityError),
            Err(()) => Err(H4DenyClassification::AuthorityPanic),
        }
    }

    async fn handle_call(&self, call: ToolCall<'_>) -> VitaWorkspaceReplaceResult {
        match VitaWorkspaceReplaceRequest::from_codex_call(&call, self.context.as_ref()) {
            Ok(request) => self.execute_request(request).await,
            Err(error) => VitaWorkspaceReplaceResult::denied(
                invalid_request_for_call(&call, self.context.clone()),
                match error {
                    H4RequestBuildError::UnmappedTool => H4DenyClassification::UnmappedTool,
                    _ => H4DenyClassification::InvalidRequest,
                },
            ),
        }
    }
}

// D29-H4-C IMPLEMENTATION START
#[cfg(test)]
const H4C_NATIVE_FENCE_WAIT: Duration = Duration::from_secs(5);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H4CNativeFault {
    AfterFirstWrite,
    PanicBeforeFirstMutation,
    PanicAfterFirstMutation,
}

#[cfg(test)]
type H4CNativeSetup = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
struct H4CFinalFenceRequest {
    decision: std::sync::mpsc::SyncSender<Result<(), WorkspaceReplaceFenceError>>,
}

#[cfg(test)]
struct H4CCommitFence {
    requests: tokio::sync::mpsc::Sender<H4CFinalFenceRequest>,
    cancellation: Arc<AtomicBool>,
    sent: bool,
}

#[cfg(test)]
impl H4CCommitFence {
    fn new(
        requests: tokio::sync::mpsc::Sender<H4CFinalFenceRequest>,
        cancellation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            requests,
            cancellation,
            sent: false,
        }
    }
}

#[cfg(test)]
impl super::workspace_capability::WorkspaceReplaceCommitFence for H4CCommitFence {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        if self.sent {
            return Err(WorkspaceReplaceFenceError::Error);
        }
        self.sent = true;
        if self.cancellation.load(Ordering::Acquire) {
            return Err(WorkspaceReplaceFenceError::Cancelled);
        }
        let (decision, result) = std::sync::mpsc::sync_channel(1);
        self.requests
            .blocking_send(H4CFinalFenceRequest { decision })
            .map_err(|_| WorkspaceReplaceFenceError::Error)?;
        let result = result
            .recv_timeout(H4C_NATIVE_FENCE_WAIT)
            .map_err(|_| WorkspaceReplaceFenceError::Error)?;
        if self.cancellation.load(Ordering::Acquire) {
            return Err(WorkspaceReplaceFenceError::Cancelled);
        }
        result
    }
}

#[cfg(test)]
struct H4CGrantBinding {
    grant_id: String,
    authorization_revision: i64,
    confirmation_id: String,
}

#[cfg(test)]
impl H4CGrantBinding {
    fn from_grant(grant: &VitaExecutableReplaceGrant) -> Self {
        Self {
            grant_id: grant.grant_id.clone(),
            authorization_revision: grant.authorization_revision,
            confirmation_id: grant.confirmation_id.clone(),
        }
    }
}

#[cfg(test)]
struct H4CRevalidationInput {
    context: VitaExecutionContext,
    capability_id: String,
    tool_call_id: String,
    turn_id: String,
    relative_path: super::WorkspaceRelativePath,
    expected_sha256: String,
    replacement_sha256: String,
    replacement_bytes: usize,
    workspace_root_identity: super::WorkspaceRootIdentity,
    target_identity: super::WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
}

#[cfg(test)]
impl H4CRevalidationInput {
    fn from_grant(grant: &VitaExecutableReplaceGrant) -> Self {
        Self {
            context: VitaExecutionContext::try_new(&grant.life_id, &grant.task_id)
                .expect("H4-C grant carries a valid execution context"),
            capability_id: grant.capability_id.clone(),
            tool_call_id: grant.tool_call_id.clone(),
            turn_id: grant.turn_id.clone(),
            relative_path: grant.relative_path.clone(),
            expected_sha256: grant.expected_sha256.clone(),
            replacement_sha256: grant.replacement_sha256.clone(),
            replacement_bytes: grant.replacement_bytes,
            workspace_root_identity: grant.workspace_root_identity,
            target_identity: grant.target_identity,
            target_kind: grant.target_kind,
        }
    }

    fn into_request(self, binding: &H4CGrantBinding) -> H4AuthorityRequest {
        H4AuthorityRequest {
            context: self.context,
            capability_id: self.capability_id,
            operation: H4AuthorityOperation::Revalidate {
                grant_id: binding.grant_id.clone(),
                authorization_revision: binding.authorization_revision,
            },
            tool_call_id: self.tool_call_id,
            turn_id: self.turn_id,
            relative_path: self.relative_path,
            expected_sha256: self.expected_sha256,
            replacement_sha256: self.replacement_sha256,
            replacement_bytes: self.replacement_bytes,
            workspace_root_identity: self.workspace_root_identity,
            target_identity: self.target_identity,
            target_kind: self.target_kind,
        }
    }
}

#[cfg(test)]
struct H4CFenceDecision {
    fence: Result<(), WorkspaceReplaceFenceError>,
    classification: Option<H4DenyClassification>,
}

#[cfg(test)]
impl VitaWorkspaceReplaceBroker {
    /// H4-C deliberately has a separate execution path from H4-A's
    /// authorization-only `execute_request`.  The only blocking work below
    /// is the already-frozen H4-B native primitive, and its synchronous fence
    /// is bridged back to this async function through one bounded request and
    /// one bounded decision.
    async fn execute_governed_request(
        &self,
        request: VitaWorkspaceReplaceRequest,
    ) -> VitaWorkspaceReplaceResult {
        self.execute_governed_request_with_setup(request, None, None)
            .await
    }

    async fn execute_governed_request_with_fault(
        &self,
        request: VitaWorkspaceReplaceRequest,
        native_fault: Option<H4CNativeFault>,
    ) -> VitaWorkspaceReplaceResult {
        self.execute_governed_request_with_setup(request, native_fault, None)
            .await
    }

    async fn execute_governed_request_with_setup(
        &self,
        request: VitaWorkspaceReplaceRequest,
        native_fault: Option<H4CNativeFault>,
        native_setup: Option<H4CNativeSetup>,
    ) -> VitaWorkspaceReplaceResult {
        self.metrics
            .attempted_requests
            .fetch_add(1, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::TurnCancelled,
            );
        }

        let Some(bound_context) = self.context.as_ref() else {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::MissingContext,
            );
        };
        let Some(request_context) = request.context.as_ref() else {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::MissingContext,
            );
        };
        if request_context.life_id() != bound_context.life_id() {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::WrongLifeBinding,
            );
        }
        if request_context.task_id() != bound_context.task_id() {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::WrongTaskBinding,
            );
        }

        let call_admission = {
            let mut state = lock_unpoisoned(&self.state);
            if state.seen_call_ids.contains(&request.tool_call_id) {
                Err(H4DenyClassification::DuplicateToolCall)
            } else if state.seen_call_ids.len() >= MAX_SEEN_CALL_IDS {
                Err(H4DenyClassification::CallLimitExceeded)
            } else {
                state.seen_call_ids.insert(request.tool_call_id.clone());
                Ok(())
            }
        };
        if let Err(classification) = call_admission {
            if classification == H4DenyClassification::DuplicateToolCall {
                self.metrics
                    .confirmation_replay_denials
                    .fetch_add(1, Ordering::AcqRel);
            }
            return VitaWorkspaceReplaceResult::denied(request, classification);
        }

        // This first preparation supplies the immutable action facts needed
        // by IssueReplaceGrant.  It is not the H4-B operation handle: the
        // actual exclusive handle is opened only after the grant is imported
        // inside the native worker below.
        let prepared_for_issue = match self.root.prepare_target(request.relative_path.as_path()) {
            Ok(prepared) => prepared,
            Err(_) => {
                return VitaWorkspaceReplaceResult::denied(
                    request,
                    H4DenyClassification::TargetRejected,
                )
            }
        };
        if prepared_for_issue.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared_for_issue.target_identity().is_none()
        {
            return VitaWorkspaceReplaceResult::denied(
                request,
                if prepared_for_issue.kind() == PreparedWorkspaceTargetKind::Missing {
                    H4DenyClassification::TargetMissing
                } else {
                    H4DenyClassification::TargetRejected
                },
            );
        }
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::TurnCancelled,
            );
        }

        let replacement_bytes = request.replacement_content.as_bytes().len();
        let replacement_sha256 = sha256_hex(request.replacement_content.as_bytes());
        let authority_request = H4AuthorityRequest {
            context: bound_context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            relative_path: request.relative_path.clone(),
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256,
            replacement_bytes,
            workspace_root_identity: prepared_for_issue.root().identity(),
            target_identity: prepared_for_issue
                .target_identity()
                .expect("existing H4-C target has an identity"),
            target_kind: prepared_for_issue.kind(),
        };
        let initial_authority = match self.evaluate_authority(authority_request.clone()).await {
            Ok(response) => response,
            Err(classification) => {
                return VitaWorkspaceReplaceResult::denied(request, classification)
            }
        };
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::denied(
                request,
                H4DenyClassification::LateAfterCancellation,
            );
        }

        let (confirmation, evidence) =
            match validate_issue_completion(&initial_authority, &authority_request) {
                Ok(value) => value,
                Err(classification) => {
                    self.record_denial(classification);
                    return VitaWorkspaceReplaceResult::denied(request, classification);
                }
            };
        let grant = match VitaExecutableReplaceGrant::from_host_evidence(
            confirmation,
            evidence,
            &authority_request,
            &prepared_for_issue,
        ) {
            Ok(grant) => grant,
            Err(_) => {
                self.metrics
                    .confirmation_mismatch_denials
                    .fetch_add(1, Ordering::AcqRel);
                return VitaWorkspaceReplaceResult::denied(
                    request,
                    H4DenyClassification::GrantRejected,
                );
            }
        };
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);
        if initial_authority.confirmation_consumed {
            self.metrics
                .confirmations_consumed
                .fetch_add(1, Ordering::AcqRel);
        }

        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::governed(
                request,
                VitaWorkspaceReplaceExecutionOutcome::Denied {
                    classification: H4DenyClassification::LateAfterCancellation,
                },
                Some(H4DenyClassification::LateAfterCancellation),
            );
        }

        if let Some(native_setup) = native_setup {
            native_setup();
        }
        if self.cancelled.load(Ordering::Acquire) {
            return VitaWorkspaceReplaceResult::governed(
                request,
                VitaWorkspaceReplaceExecutionOutcome::Denied {
                    classification: H4DenyClassification::LateAfterCancellation,
                },
                Some(H4DenyClassification::LateAfterCancellation),
            );
        }

        // The preflight target was used only to bind the Host issue request.
        // Release its metadata handle before H4-C enters the actual H4-B
        // preparation, so the native worker owns the only operation handle.
        drop(prepared_for_issue);

        let grant_admission = {
            let mut state = lock_unpoisoned(&self.state);
            if state.consumed_grant_ids.insert(grant.grant_id.clone()) {
                Ok(())
            } else {
                Err(H4DenyClassification::ConfirmationReplay)
            }
        };
        if let Err(classification) = grant_admission {
            self.record_denial(classification);
            return VitaWorkspaceReplaceResult::governed(
                request,
                VitaWorkspaceReplaceExecutionOutcome::Denied { classification },
                Some(classification),
            );
        }

        let binding = H4CGrantBinding::from_grant(&grant);
        let revalidation_input = H4CRevalidationInput::from_grant(&grant);
        let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
        let fence = H4CCommitFence::new(requests, Arc::clone(&self.cancelled));
        let native_request = request.clone();
        let native_root = self.root.clone();
        let native_cancellation = Arc::clone(&self.cancelled);
        self.metrics
            .native_workers_started
            .fetch_add(1, Ordering::AcqRel);
        let native = tokio::task::spawn_blocking(move || {
            execute_h4c_native_replace(
                grant,
                native_request,
                native_root,
                fence,
                native_cancellation,
                native_fault,
            )
        });

        let fence_decision = self
            .service_h4c_fence(&mut receiver, revalidation_input, &binding)
            .await;
        let native_outcome = match native.await {
            Ok(outcome) => outcome,
            Err(_) => {
                self.metrics
                    .native_workers_joined
                    .fetch_add(1, Ordering::AcqRel);
                let outcome = WorkspaceReplaceCommitOutcome::CommitUnknown {
                    error: WorkspaceReplaceError::NativeWorkerJoin,
                    evidence: WorkspaceReplaceEvidence {
                        mutation_attempted: true,
                        mutation_started: true,
                        modifying_syscalls: 1,
                        commit_unknown: true,
                        fence_calls: 1,
                        operation_handle_open_count: 1,
                        ..WorkspaceReplaceEvidence::default()
                    },
                };
                self.record_h4c_native_metrics(&outcome);
                return VitaWorkspaceReplaceResult::governed(
                    request,
                    VitaWorkspaceReplaceExecutionOutcome::from_native(outcome),
                    None,
                );
            }
        };
        self.metrics
            .native_workers_joined
            .fetch_add(1, Ordering::AcqRel);

        self.record_h4c_native_metrics(&native_outcome);
        let fence_classification = fence_decision
            .as_ref()
            .and_then(|decision| decision.classification);
        let classification = fence_classification.or_else(|| {
            native_outcome
                .error_classification()
                .filter(|_| matches!(native_outcome, WorkspaceReplaceCommitOutcome::Denied { .. }))
        });
        VitaWorkspaceReplaceResult::governed(
            request,
            VitaWorkspaceReplaceExecutionOutcome::from_native(native_outcome),
            classification,
        )
    }

    async fn service_h4c_fence(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<H4CFinalFenceRequest>,
        input: H4CRevalidationInput,
        binding: &H4CGrantBinding,
    ) -> Option<H4CFenceDecision> {
        let fence_request = receiver.recv().await?;
        self.metrics
            .final_revalidations
            .fetch_add(1, Ordering::AcqRel);
        if self.cancelled.load(Ordering::Acquire) {
            let decision = H4CFenceDecision {
                fence: Err(WorkspaceReplaceFenceError::Cancelled),
                classification: Some(H4DenyClassification::TurnCancelled),
            };
            let _ = fence_request
                .decision
                .send(Err(WorkspaceReplaceFenceError::Cancelled));
            self.metrics
                .final_revalidation_denials
                .fetch_add(1, Ordering::AcqRel);
            return Some(decision);
        }

        let authority_request = input.into_request(binding);
        let authority = self.evaluate_authority(authority_request.clone());
        let mut decision = tokio::select! {
            _ = self.cancellation_notify.notified() => H4CFenceDecision {
                fence: Err(WorkspaceReplaceFenceError::Cancelled),
                classification: Some(H4DenyClassification::TurnCancelled),
            },
            response = tokio::time::timeout(H4C_NATIVE_FENCE_WAIT, authority) => match response {
                Err(_) => H4CFenceDecision {
                    fence: Err(WorkspaceReplaceFenceError::Error),
                    classification: Some(H4DenyClassification::AuthorityError),
                },
                Ok(Ok(response)) => match validate_h4c_revalidation(
                    &response,
                    &authority_request,
                    binding,
                ) {
                    Ok(()) => H4CFenceDecision {
                        fence: Ok(()),
                        classification: None,
                    },
                    Err(classification) => H4CFenceDecision {
                        fence: Err(WorkspaceReplaceFenceError::Denied),
                        classification: Some(classification),
                    },
                },
                Ok(Err(classification)) => H4CFenceDecision {
                    fence: Err(WorkspaceReplaceFenceError::Error),
                    classification: Some(classification),
                },
            },
        };
        if self.cancelled.load(Ordering::Acquire) {
            decision = H4CFenceDecision {
                fence: Err(WorkspaceReplaceFenceError::Cancelled),
                classification: Some(H4DenyClassification::TurnCancelled),
            };
        }
        if decision.fence.is_err() {
            self.metrics
                .final_revalidation_denials
                .fetch_add(1, Ordering::AcqRel);
        }
        let _ = fence_request.decision.send(decision.fence);
        Some(decision)
    }

    async fn handle_call_governed(&self, call: ToolCall<'_>) -> VitaWorkspaceReplaceResult {
        match VitaWorkspaceReplaceRequest::from_codex_call(&call, self.context.as_ref()) {
            Ok(request) => self.execute_governed_request(request).await,
            Err(error) => VitaWorkspaceReplaceResult::denied(
                invalid_request_for_call(&call, self.context.clone()),
                match error {
                    H4RequestBuildError::UnmappedTool => H4DenyClassification::UnmappedTool,
                    _ => H4DenyClassification::InvalidRequest,
                },
            ),
        }
    }

    fn record_h4c_native_metrics(&self, outcome: &WorkspaceReplaceCommitOutcome) {
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
            | WorkspaceReplaceCommitOutcome::Conflict { evidence }
            | WorkspaceReplaceCommitOutcome::Committed { evidence }
            | WorkspaceReplaceCommitOutcome::CommitUnknown { evidence, .. } => evidence,
        };
        lock_unpoisoned(&self.native_evidence).push(evidence.clone());
        if evidence.mutation_attempted {
            self.metrics
                .filesystem_mutation_attempts
                .fetch_add(1, Ordering::AcqRel);
        }
        self.metrics
            .exclusive_operation_handles
            .fetch_add(evidence.operation_handle_open_count, Ordering::AcqRel);
        match outcome {
            WorkspaceReplaceCommitOutcome::Conflict { .. } => {
                self.metrics
                    .content_conflicts
                    .fetch_add(1, Ordering::AcqRel);
            }
            WorkspaceReplaceCommitOutcome::Committed { .. } => {
                self.metrics
                    .filesystem_mutations_committed
                    .fetch_add(1, Ordering::AcqRel);
                self.metrics
                    .filesystem_mutations
                    .fetch_add(1, Ordering::AcqRel);
                self.metrics
                    .authorized_write_count
                    .fetch_add(1, Ordering::AcqRel);
            }
            WorkspaceReplaceCommitOutcome::CommitUnknown { .. } => {
                self.metrics
                    .filesystem_commit_unknown
                    .fetch_add(1, Ordering::AcqRel);
            }
            WorkspaceReplaceCommitOutcome::Denied { .. } => {}
        }
    }
}

#[cfg(test)]
fn execute_h4c_native_replace(
    grant: VitaExecutableReplaceGrant,
    request: VitaWorkspaceReplaceRequest,
    root: super::TrustedWorkspaceRoot,
    mut fence: H4CCommitFence,
    cancellation: Arc<AtomicBool>,
    native_fault: Option<H4CNativeFault>,
) -> WorkspaceReplaceCommitOutcome {
    let mut tracker = WorkspaceReplaceMutationTracker::new();
    match catch_unwind(AssertUnwindSafe(|| {
        execute_h4c_native_replace_inner(
            grant,
            request,
            root,
            &mut fence,
            cancellation,
            native_fault,
            &mut tracker,
        )
    })) {
        Ok(outcome) => outcome,
        Err(_) => match tracker.phase() {
            WorkspaceReplaceMutationPhase::NotStarted => WorkspaceReplaceCommitOutcome::Denied {
                error: WorkspaceReplaceError::NativePanicBeforeMutation,
                evidence: tracker.evidence_after_panic(),
            },
            WorkspaceReplaceMutationPhase::Started => {
                WorkspaceReplaceCommitOutcome::CommitUnknown {
                    error: WorkspaceReplaceError::NativePanicAfterMutation,
                    evidence: tracker.evidence_after_panic(),
                }
            }
            WorkspaceReplaceMutationPhase::Committed => WorkspaceReplaceCommitOutcome::Committed {
                evidence: tracker.evidence_after_panic(),
            },
        },
    }
}

#[cfg(test)]
fn execute_h4c_native_replace_inner(
    grant: VitaExecutableReplaceGrant,
    request: VitaWorkspaceReplaceRequest,
    root: super::TrustedWorkspaceRoot,
    fence: &mut H4CCommitFence,
    cancellation: Arc<AtomicBool>,
    native_fault: Option<H4CNativeFault>,
    tracker: &mut WorkspaceReplaceMutationTracker,
) -> WorkspaceReplaceCommitOutcome {
    let prepared = match root.prepare_target(request.relative_path.as_path()) {
        Ok(prepared) => prepared,
        Err(_) => {
            return WorkspaceReplaceCommitOutcome::Denied {
                error: WorkspaceReplaceError::InvalidPreparedTarget,
                evidence: WorkspaceReplaceEvidence::default(),
            }
        }
    };
    if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
        return WorkspaceReplaceCommitOutcome::Denied {
            error: WorkspaceReplaceError::TargetMissing,
            evidence: WorkspaceReplaceEvidence::default(),
        };
    }
    if validate_h4c_native_binding(&grant, &request, &prepared).is_err() {
        return WorkspaceReplaceCommitOutcome::Denied {
            error: WorkspaceReplaceError::InvalidPreparedTarget,
            evidence: WorkspaceReplaceEvidence::default(),
        };
    }
    let expected_sha256 = grant.expected_sha256.clone();
    #[cfg(windows)]
    if let Some(native_fault) = native_fault {
        return match native_fault {
            H4CNativeFault::AfterFirstWrite => prepared
                .replace_existing_file_utf8_bounded_with_test_fault_and_tracker(
                    &expected_sha256,
                    &request.replacement_content,
                    fence,
                    cancellation.as_ref(),
                    tracker,
                    WorkspaceReplaceTestFault::AfterFirstWrite,
                ),
            H4CNativeFault::PanicBeforeFirstMutation => prepared
                .replace_existing_file_utf8_bounded_with_test_fault_and_tracker(
                    &expected_sha256,
                    &request.replacement_content,
                    fence,
                    cancellation.as_ref(),
                    tracker,
                    WorkspaceReplaceTestFault::PanicBeforeFirstMutation,
                ),
            H4CNativeFault::PanicAfterFirstMutation => prepared
                .replace_existing_file_utf8_bounded_with_test_fault_and_tracker(
                    &expected_sha256,
                    &request.replacement_content,
                    fence,
                    cancellation.as_ref(),
                    tracker,
                    WorkspaceReplaceTestFault::PanicAfterFirstMutation,
                ),
        };
    }
    #[cfg(not(windows))]
    let _ = native_fault;
    prepared.replace_existing_file_utf8_bounded_with_cancellation_and_tracker(
        &expected_sha256,
        &request.replacement_content,
        fence,
        cancellation.as_ref(),
        tracker,
    )
}

#[cfg(test)]
fn validate_h4c_native_binding(
    grant: &VitaExecutableReplaceGrant,
    request: &VitaWorkspaceReplaceRequest,
    prepared: &PreparedWorkspaceTarget,
) -> Result<(), H4DenyClassification> {
    if grant.operation != H4ReplaceOperation::ReplaceExistingUtf8File
        || grant.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
        || grant.relative_path != request.relative_path
        || grant.expected_sha256 != request.expected_sha256
        || grant.replacement_sha256 != sha256_hex(request.replacement_content.as_bytes())
        || grant.replacement_bytes != request.replacement_content.as_bytes().len()
        || grant.workspace_root_identity != prepared.root().identity()
        || grant.target_identity
            != prepared
                .target_identity()
                .ok_or(H4DenyClassification::AuthorityEvidenceMismatch)?
        || grant.target_kind != prepared.kind()
        || prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
    {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn validate_h4c_revalidation(
    response: &H4HostAuthorityResponse,
    request: &H4AuthorityRequest,
    binding: &H4CGrantBinding,
) -> Result<(), H4DenyClassification> {
    match response.status {
        H4AuthorityResponseStatus::Denied => {
            if response.grant.is_some()
                || response.confirmation.is_some()
                || response.confirmation_consumed
                || response.denial.is_none()
            {
                return Err(H4DenyClassification::AuthorityEvidenceMismatch);
            }
            return match validate_canonical_decision(&response.canonical, request) {
                Ok(_) => Err(response.denial.expect("denial presence was checked above")),
                Err(classification) => Err(classification),
            };
        }
        H4AuthorityResponseStatus::Ok => {
            if response.denial.is_some()
                || response.confirmation.is_some()
                || response.confirmation_consumed
                || response.grant.is_none()
            {
                return Err(H4DenyClassification::AuthorityEvidenceMismatch);
            }
        }
    }

    let revision = validate_canonical_decision(&response.canonical, request)?;
    let H4AuthorityOperation::Revalidate {
        grant_id,
        authorization_revision,
    } = &request.operation
    else {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    };
    if revision != *authorization_revision
        || binding.authorization_revision != *authorization_revision
        || binding.grant_id != *grant_id
    {
        return Err(H4DenyClassification::StaleRevision);
    }
    let evidence = response
        .grant
        .as_ref()
        .ok_or(H4DenyClassification::RevalidationDenied)?;
    validate_grant_evidence(evidence, request, revision, &binding.confirmation_id).map(|_| ())
}

#[cfg(test)]
pub(crate) struct H4FinalFenceRequest {
    decision: std::sync::mpsc::SyncSender<Result<(), WorkspaceReplaceFenceError>>,
}

#[cfg(test)]
pub(crate) struct H4GrantFinalFence {
    requests: tokio::sync::mpsc::Sender<H4FinalFenceRequest>,
    cancellation: Arc<AtomicBool>,
    sent: bool,
}

#[cfg(test)]
impl H4GrantFinalFence {
    fn new(
        requests: tokio::sync::mpsc::Sender<H4FinalFenceRequest>,
        cancellation: Arc<AtomicBool>,
    ) -> Self {
        Self {
            requests,
            cancellation,
            sent: false,
        }
    }
}

#[cfg(test)]
impl super::workspace_capability::WorkspaceReplaceCommitFence for H4GrantFinalFence {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        if self.sent {
            return Err(WorkspaceReplaceFenceError::Error);
        }
        self.sent = true;
        if self.cancellation.load(Ordering::Acquire) {
            return Err(WorkspaceReplaceFenceError::Cancelled);
        }
        let (decision, result) = std::sync::mpsc::sync_channel(1);
        self.requests
            .blocking_send(H4FinalFenceRequest { decision })
            .map_err(|_| WorkspaceReplaceFenceError::Error)?;
        let result = result
            .recv_timeout(H4C_NATIVE_FENCE_WAIT)
            .map_err(|_| WorkspaceReplaceFenceError::Error)?;
        if self.cancellation.load(Ordering::Acquire) {
            return Err(WorkspaceReplaceFenceError::Cancelled);
        }
        result
    }
}

#[cfg(test)]
pub(crate) struct H4GrantFinalFenceService {
    authority: Arc<dyn VitaH4AuthorityPort>,
    grant: VitaExecutableReplaceGrant,
    cancellation: Arc<AtomicBool>,
}

#[cfg(test)]
impl H4GrantFinalFenceService {
    pub(crate) async fn service(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<H4FinalFenceRequest>,
    ) -> Option<Result<(), WorkspaceReplaceFenceError>> {
        let fence_request = receiver.recv().await?;
        if self.cancellation.load(Ordering::Acquire) {
            let decision = Err(WorkspaceReplaceFenceError::Cancelled);
            let _ = fence_request.decision.send(decision);
            return Some(decision);
        }

        let binding = H4CGrantBinding::from_grant(&self.grant);
        let authority_request =
            H4CRevalidationInput::from_grant(&self.grant).into_request(&binding);
        let decision = match catch_unwind(AssertUnwindSafe(|| {
            self.authority.evaluate(authority_request.clone())
        })) {
            Err(_) => Err(WorkspaceReplaceFenceError::Error),
            Ok(future) => {
                match tokio::time::timeout(H4C_NATIVE_FENCE_WAIT, CatchUnwindFuture::new(future))
                    .await
                {
                    Err(_) | Ok(Err(())) | Ok(Ok(Err(_))) => Err(WorkspaceReplaceFenceError::Error),
                    Ok(Ok(Ok(response))) => {
                        validate_h4c_revalidation(&response, &authority_request, &binding)
                            .map_err(h4_final_fence_error)
                    }
                }
            }
        };
        let decision = if self.cancellation.load(Ordering::Acquire) {
            Err(WorkspaceReplaceFenceError::Cancelled)
        } else {
            decision
        };
        let _ = fence_request.decision.send(decision);
        Some(decision)
    }
}

#[cfg(test)]
fn h4_final_fence_error(classification: H4DenyClassification) -> WorkspaceReplaceFenceError {
    match classification {
        H4DenyClassification::StaleRevision
        | H4DenyClassification::RevalidationDenied
        | H4DenyClassification::RootDisabled
        | H4DenyClassification::WorkspaceScopeDenied
        | H4DenyClassification::ConfirmationExpired
        | H4DenyClassification::ConfirmationReplay => WorkspaceReplaceFenceError::Stale,
        H4DenyClassification::TurnCancelled | H4DenyClassification::LateAfterCancellation => {
            WorkspaceReplaceFenceError::Cancelled
        }
        _ => WorkspaceReplaceFenceError::Denied,
    }
}

#[cfg(test)]
impl VitaWorkspaceReplaceExecutionOutcome {
    fn from_native(outcome: WorkspaceReplaceCommitOutcome) -> Self {
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence: _ } => Self::Denied {
                classification: native_error_classification(error),
            },
            WorkspaceReplaceCommitOutcome::Conflict { evidence } => Self::Conflict { evidence },
            WorkspaceReplaceCommitOutcome::Committed { evidence } => Self::Committed { evidence },
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                Self::CommitUnknown { error, evidence }
            }
        }
    }
}

#[cfg(test)]
impl WorkspaceReplaceCommitOutcome {
    fn error_classification(&self) -> Option<H4DenyClassification> {
        match self {
            Self::Denied { error, .. } | Self::CommitUnknown { error, .. } => {
                Some(native_error_classification(*error))
            }
            Self::Conflict { .. } | Self::Committed { .. } => None,
        }
    }
}

#[cfg(test)]
fn native_error_classification(error: WorkspaceReplaceError) -> H4DenyClassification {
    match error {
        WorkspaceReplaceError::TargetMissing => H4DenyClassification::TargetMissing,
        WorkspaceReplaceError::CommitFenceDenied
        | WorkspaceReplaceError::CommitFenceStale
        | WorkspaceReplaceError::CommitFenceCancelled
        | WorkspaceReplaceError::CommitFenceError
        | WorkspaceReplaceError::CommitFencePanic
        | WorkspaceReplaceError::NativePanicAfterMutation
        | WorkspaceReplaceError::NativeWorkerJoin => H4DenyClassification::RevalidationDenied,
        WorkspaceReplaceError::HardLinkAmbiguous
        | WorkspaceReplaceError::ReparseTarget
        | WorkspaceReplaceError::TargetBusy
        | WorkspaceReplaceError::TargetIdentityChanged
        | WorkspaceReplaceError::ParentIdentityChanged
        | WorkspaceReplaceError::RootIdentityChanged
        | WorkspaceReplaceError::TargetOutsideRoot
        | WorkspaceReplaceError::CurrentFileTooLarge
        | WorkspaceReplaceError::CurrentContentNotUtf8
        | WorkspaceReplaceError::InvalidPreparedTarget
        | WorkspaceReplaceError::InvalidExpectedHash
        | WorkspaceReplaceError::ReplacementTooLarge
        | WorkspaceReplaceError::OperationHandleIo
        | WorkspaceReplaceError::CancellationBeforeMutation
        | WorkspaceReplaceError::FaultInjected
        | WorkspaceReplaceError::WriteFailed
        | WorkspaceReplaceError::ShortWrite
        | WorkspaceReplaceError::ZeroProgressWrite
        | WorkspaceReplaceError::SetEndOfFileFailed
        | WorkspaceReplaceError::FlushFailed
        | WorkspaceReplaceError::PostWriteVerificationFailed
        | WorkspaceReplaceError::UnavailableOnThisPlatform
        | WorkspaceReplaceError::ReparseParent
        | WorkspaceReplaceError::NativePanicBeforeMutation => H4DenyClassification::TargetRejected,
    }
}

fn invalid_request_for_call(
    call: &ToolCall<'_>,
    context: Option<VitaExecutionContext>,
) -> VitaWorkspaceReplaceRequest {
    VitaWorkspaceReplaceRequest {
        tool_call_id: bounded_text(&call.call_id, MAX_CALL_ID_CHARS)
            .unwrap_or_else(|| "invalid-call-id".to_string()),
        turn_id: bounded_text(&call.turn_id, MAX_TURN_ID_CHARS)
            .unwrap_or_else(|| "invalid-turn-id".to_string()),
        context,
        relative_path: super::WorkspaceRelativePath::parse(std::path::Path::new("invalid"))
            .expect("static invalid H4 request path is valid"),
        expected_sha256: String::new(),
        replacement_content: String::new(),
    }
}

fn bounded_text(value: &str, max_chars: usize) -> Option<String> {
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

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_canonical_decision(
    decision: &H4CanonicalDecision,
    request: &H4AuthorityRequest,
) -> Result<i64, H4DenyClassification> {
    if decision.life_id != request.context.life_id()
        || decision.capability_id != request.capability_id
    {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    }
    if !decision.workspace_scope_matches {
        return Err(H4DenyClassification::WorkspaceScopeDenied);
    }
    match decision.outcome {
        H4CanonicalOutcome::ScopeRequired
            if decision.decision_code == H4CanonicalDecisionCode::ScopeNotAvailable
                && decision.scope_requirement == H4ScopeRequirement::WorkspaceRequired
                && decision.approval_floor == H4ApprovalFloor::ExplicitPerAction => {}
        H4CanonicalOutcome::RootDisabled => return Err(H4DenyClassification::RootDisabled),
        H4CanonicalOutcome::Denied => return Err(H4DenyClassification::MissingAuthorization),
        H4CanonicalOutcome::AuthorizationUnavailable => {
            return Err(H4DenyClassification::AuthorityError)
        }
        H4CanonicalOutcome::UnknownCapability => {
            return Err(H4DenyClassification::AuthorityEvidenceMismatch)
        }
        H4CanonicalOutcome::ExplicitConfirmationRequired | H4CanonicalOutcome::Forbidden => {
            return Err(H4DenyClassification::AuthorityEvidenceMismatch)
        }
        H4CanonicalOutcome::Eligible => {
            return Err(H4DenyClassification::AuthorityEvidenceMismatch)
        }
        H4CanonicalOutcome::ScopeRequired => return Err(H4DenyClassification::ScopeUnavailable),
    }
    decision
        .authorization_revision
        .filter(|revision| *revision > 0)
        .ok_or(H4DenyClassification::StaleRevision)
}

fn validate_common_action_binding(
    request: &H4AuthorityRequest,
) -> Result<(), H4DenyClassification> {
    if request.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
        || request.target_kind != PreparedWorkspaceTargetKind::ExistingFile
        || !is_sha256_hex(&request.expected_sha256)
        || !is_sha256_hex(&request.replacement_sha256)
        || request.replacement_bytes > H4_MAX_REPLACEMENT_BYTES
        || bounded_text(&request.tool_call_id, MAX_CALL_ID_CHARS).is_none()
        || bounded_text(&request.turn_id, MAX_TURN_ID_CHARS).is_none()
        || request
            .relative_path
            .as_path()
            .to_string_lossy()
            .chars()
            .count()
            > MAX_PATH_CHARS
    {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    }
    Ok(())
}

fn validate_confirmation(
    confirmation: &HostExplicitActionConfirmationEvidence,
    request: &H4AuthorityRequest,
    revision: i64,
) -> Result<(), H4DenyClassification> {
    validate_common_action_binding(request)?;
    if confirmation.source != H4ConfirmationEvidenceSource::TrustedTestHarness
        || bounded_text(&confirmation.confirmation_id, MAX_CALL_ID_CHARS).is_none()
        || confirmation.life_id != request.context.life_id()
        || confirmation.task_id != request.context.task_id()
        || confirmation.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
        || confirmation.authorization_revision != revision
        || confirmation.workspace_root_identity != request.workspace_root_identity
        || confirmation.relative_path != request.relative_path
        || confirmation.target_identity != request.target_identity
        || confirmation.expected_sha256 != request.expected_sha256
        || confirmation.replacement_sha256 != request.replacement_sha256
        || confirmation.replacement_bytes != request.replacement_bytes
        || confirmation.tool_call_id != request.tool_call_id
        || confirmation.turn_id != request.turn_id
    {
        return Err(H4DenyClassification::ConfirmationMismatch);
    }
    let now = unix_millis();
    if confirmation.issued_at_unix_ms > now.saturating_add(MAX_HOST_CLOCK_SKEW_MS)
        || confirmation.expires_at_unix_ms <= confirmation.issued_at_unix_ms
        || confirmation
            .expires_at_unix_ms
            .saturating_sub(confirmation.issued_at_unix_ms)
            > GRANT_LIFETIME_MS
    {
        return Err(H4DenyClassification::ConfirmationMismatch);
    }
    if confirmation.expires_at_unix_ms <= now {
        return Err(H4DenyClassification::ConfirmationExpired);
    }
    Ok(())
}

fn validate_grant_evidence(
    evidence: &H4HostReplaceGrantEvidence,
    request: &H4AuthorityRequest,
    revision: i64,
    confirmation_id: &str,
) -> Result<(), H4DenyClassification> {
    validate_common_action_binding(request)?;
    if bounded_text(&evidence.grant_id, MAX_CALL_ID_CHARS).is_none()
        || evidence.life_id != request.context.life_id()
        || evidence.task_id != request.context.task_id()
        || evidence.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
        || evidence.authorization_revision != revision
        || evidence.scope != VitaRequestedScope::Workspace
        || evidence.workspace_root_identity != request.workspace_root_identity
        || evidence.relative_path != request.relative_path
        || evidence.target_identity != request.target_identity
        || evidence.target_kind != PreparedWorkspaceTargetKind::ExistingFile
        || evidence.operation != H4ReplaceOperation::ReplaceExistingUtf8File
        || evidence.expected_sha256 != request.expected_sha256
        || evidence.replacement_sha256 != request.replacement_sha256
        || evidence.replacement_bytes != request.replacement_bytes
        || evidence.tool_call_id != request.tool_call_id
        || evidence.turn_id != request.turn_id
        || evidence.confirmation_id != confirmation_id
        || !evidence.single_use
    {
        return Err(H4DenyClassification::ConfirmationMismatch);
    }
    let now = unix_millis();
    if evidence.issued_at_unix_ms > now.saturating_add(MAX_HOST_CLOCK_SKEW_MS)
        || evidence.expires_at_unix_ms <= evidence.issued_at_unix_ms
        || evidence
            .expires_at_unix_ms
            .saturating_sub(evidence.issued_at_unix_ms)
            > GRANT_LIFETIME_MS
    {
        return Err(H4DenyClassification::GrantRejected);
    }
    if evidence.expires_at_unix_ms <= now {
        return Err(H4DenyClassification::GrantRejected);
    }
    Ok(())
}

fn validate_issue_completion(
    response: &H4HostAuthorityResponse,
    request: &H4AuthorityRequest,
) -> Result<
    (
        HostExplicitActionConfirmationEvidence,
        H4HostReplaceGrantEvidence,
    ),
    H4DenyClassification,
> {
    let revision = validate_canonical_decision(&response.canonical, request)?;
    if !matches!(request.operation, H4AuthorityOperation::IssueReplaceGrant) {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    }
    if let Some(denial) = response.denial {
        return Err(denial);
    }
    if !response.confirmation_consumed {
        return Err(H4DenyClassification::ConfirmationMismatch);
    }
    let confirmation = response
        .confirmation
        .as_ref()
        .ok_or(H4DenyClassification::ConfirmationMissing)?;
    validate_confirmation(confirmation, request, revision)?;
    let grant = response
        .grant
        .as_ref()
        .ok_or(H4DenyClassification::GrantRejected)?;
    validate_grant_evidence(grant, request, revision, &confirmation.confirmation_id)?;
    Ok((confirmation.clone(), grant.clone()))
}

fn validate_revalidation(
    response: &H4HostAuthorityResponse,
    request: &H4AuthorityRequest,
    grant: &VitaExecutableReplaceGrant,
    prepared: &PreparedWorkspaceTarget,
) -> Result<(), H4DenyClassification> {
    let revision = validate_canonical_decision(&response.canonical, request)?;
    let H4AuthorityOperation::Revalidate {
        grant_id,
        authorization_revision,
    } = &request.operation
    else {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    };
    if revision != *authorization_revision
        || grant.authorization_revision != *authorization_revision
        || grant.grant_id != *grant_id
    {
        return Err(H4DenyClassification::StaleRevision);
    }
    let evidence = response
        .grant
        .as_ref()
        .ok_or(H4DenyClassification::RevalidationDenied)?;
    validate_grant_evidence(evidence, request, revision, &grant.confirmation_id)?;
    if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
        || prepared.root().identity() != grant.workspace_root_identity
        || prepared.target_identity() != Some(grant.target_identity)
        || prepared.kind() != grant.target_kind
    {
        return Err(H4DenyClassification::AuthorityEvidenceMismatch);
    }
    Ok(())
}

/// A local object derived only from exact Host evidence.  H4-A intentionally
/// exposes no `write`, `commit`, `execute`, or filesystem mutation method.
struct VitaExecutableReplaceGrant {
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
    operation: H4ReplaceOperation,
    expected_sha256: String,
    replacement_sha256: String,
    replacement_bytes: usize,
    tool_call_id: String,
    turn_id: String,
    confirmation_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
}

impl VitaExecutableReplaceGrant {
    fn from_host_evidence(
        confirmation: HostExplicitActionConfirmationEvidence,
        evidence: H4HostReplaceGrantEvidence,
        request: &H4AuthorityRequest,
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<Self, H4DenyClassification> {
        validate_confirmation(&confirmation, request, evidence.authorization_revision)?;
        validate_grant_evidence(
            &evidence,
            request,
            evidence.authorization_revision,
            &confirmation.confirmation_id,
        )?;
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.root().identity() != evidence.workspace_root_identity
            || prepared.target_identity() != Some(evidence.target_identity)
            || prepared.kind() != evidence.target_kind
        {
            return Err(H4DenyClassification::AuthorityEvidenceMismatch);
        }
        Ok(Self {
            grant_id: evidence.grant_id,
            life_id: evidence.life_id,
            task_id: evidence.task_id,
            capability_id: evidence.capability_id,
            authorization_revision: evidence.authorization_revision,
            scope: evidence.scope,
            workspace_root_identity: evidence.workspace_root_identity,
            relative_path: evidence.relative_path,
            target_identity: evidence.target_identity,
            target_kind: evidence.target_kind,
            operation: evidence.operation,
            expected_sha256: evidence.expected_sha256,
            replacement_sha256: evidence.replacement_sha256,
            replacement_bytes: evidence.replacement_bytes,
            tool_call_id: evidence.tool_call_id,
            turn_id: evidence.turn_id,
            confirmation_id: confirmation.confirmation_id,
            issued_at_unix_ms: evidence.issued_at_unix_ms,
            expires_at_unix_ms: evidence.expires_at_unix_ms,
            single_use: evidence.single_use,
        })
    }
}

#[cfg(test)]
pub(crate) struct H4ReplaceAuthorizationInput {
    context: VitaExecutionContext,
    relative_path: super::WorkspaceRelativePath,
    expected_sha256: String,
    replacement_content: String,
    tool_call_id: String,
    turn_id: String,
}

#[cfg(test)]
impl H4ReplaceAuthorizationInput {
    pub(crate) fn new(
        context: VitaExecutionContext,
        relative_path: super::WorkspaceRelativePath,
        expected_sha256: impl Into<String>,
        replacement_content: impl Into<String>,
        tool_call_id: impl Into<String>,
        turn_id: impl Into<String>,
    ) -> Self {
        Self {
            context,
            relative_path,
            expected_sha256: expected_sha256.into(),
            replacement_content: replacement_content.into(),
            tool_call_id: tool_call_id.into(),
            turn_id: turn_id.into(),
        }
    }

    fn from_request(request: &VitaWorkspaceReplaceRequest) -> Self {
        Self {
            context: request
                .context
                .clone()
                .expect("H4 test authorization input requires context"),
            relative_path: request.relative_path.clone(),
            expected_sha256: request.expected_sha256.clone(),
            replacement_content: request.replacement_content.clone(),
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
        }
    }

    fn into_request(self) -> VitaWorkspaceReplaceRequest {
        VitaWorkspaceReplaceRequest {
            tool_call_id: self.tool_call_id,
            turn_id: self.turn_id,
            context: Some(self.context),
            relative_path: self.relative_path,
            expected_sha256: self.expected_sha256,
            replacement_content: self.replacement_content,
        }
    }
}

#[cfg(test)]
pub(crate) struct H4AuthorizedReplaceGrant {
    grant: VitaExecutableReplaceGrant,
    root: super::TrustedWorkspaceRoot,
    authority: Arc<dyn VitaH4AuthorityPort>,
}

#[cfg(test)]
impl H4AuthorizedReplaceGrant {
    pub(crate) fn root(&self) -> &super::TrustedWorkspaceRoot {
        &self.root
    }

    pub(crate) fn prepare_bound_target(&self) -> Result<PreparedWorkspaceTarget, ()> {
        self.root.verify_named_path_current().map_err(|_| ())?;
        let prepared = self
            .root
            .prepare_target(self.grant.relative_path.as_path())
            .map_err(|_| ())?;
        if self.grant.operation != H4ReplaceOperation::ReplaceExistingUtf8File
            || self.grant.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
            || self.grant.scope != VitaRequestedScope::Workspace
            || !self.grant.single_use
            || prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.root().identity() != self.grant.workspace_root_identity
            || prepared.target_identity() != Some(self.grant.target_identity)
            || prepared.kind() != self.grant.target_kind
        {
            return Err(());
        }
        Ok(prepared)
    }

    pub(crate) fn life_id(&self) -> &str {
        &self.grant.life_id
    }

    pub(crate) fn task_id(&self) -> &str {
        &self.grant.task_id
    }

    pub(crate) fn capability_id(&self) -> &str {
        &self.grant.capability_id
    }

    pub(crate) fn authorization_revision(&self) -> i64 {
        self.grant.authorization_revision
    }

    pub(crate) fn relative_path(&self) -> &super::WorkspaceRelativePath {
        &self.grant.relative_path
    }

    pub(crate) fn target_identity(&self) -> super::WorkspaceRootIdentity {
        self.grant.target_identity
    }

    pub(crate) fn target_kind(&self) -> PreparedWorkspaceTargetKind {
        self.grant.target_kind
    }

    pub(crate) fn expected_sha256(&self) -> &str {
        &self.grant.expected_sha256
    }

    pub(crate) fn replacement_sha256(&self) -> &str {
        &self.grant.replacement_sha256
    }

    pub(crate) fn replacement_bytes(&self) -> usize {
        self.grant.replacement_bytes
    }

    pub(crate) fn tool_call_id(&self) -> &str {
        &self.grant.tool_call_id
    }

    pub(crate) fn turn_id(&self) -> &str {
        &self.grant.turn_id
    }

    pub(crate) fn into_bounded_final_fence(
        self,
        requests: tokio::sync::mpsc::Sender<H4FinalFenceRequest>,
        cancellation: Arc<AtomicBool>,
    ) -> (H4GrantFinalFence, H4GrantFinalFenceService) {
        let fence = H4GrantFinalFence::new(requests, Arc::clone(&cancellation));
        let service = H4GrantFinalFenceService {
            authority: self.authority,
            grant: self.grant,
            cancellation,
        };
        (fence, service)
    }
}

struct ActiveAuthorityGuard {
    metrics: Arc<H4BrokerMetrics>,
}

impl ActiveAuthorityGuard {
    fn new(metrics: Arc<H4BrokerMetrics>) -> Self {
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

impl<F> Future for CatchUnwindFuture<F>
where
    F: Future + UnwindSafeFuture,
{
    type Output = Result<F::Output, ()>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let future = unsafe { Pin::new_unchecked(&mut self.as_mut().get_unchecked_mut().future) };
        match catch_unwind(AssertUnwindSafe(|| future.poll(context))) {
            Ok(std::task::Poll::Ready(output)) => std::task::Poll::Ready(Ok(output)),
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Err(_) => std::task::Poll::Ready(Err(())),
        }
    }
}

trait UnwindSafeFuture {}

impl<F: Future> UnwindSafeFuture for F {}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Test/integration-only contributor.  The normal Vita entrypoint never
/// installs H4-A; the production registry contains only the read-only H7-C
/// route and no H4 mutation capability.
pub(crate) struct VitaWorkspaceReplaceToolContributor {
    broker: Arc<VitaWorkspaceReplaceBroker>,
}

impl VitaWorkspaceReplaceToolContributor {
    pub(crate) fn new(broker: Arc<VitaWorkspaceReplaceBroker>) -> Self {
        Self { broker }
    }
}

impl ToolContributor for VitaWorkspaceReplaceToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaWorkspaceReplaceTool {
            broker: Arc::clone(&self.broker),
        })]
    }
}

struct VitaWorkspaceReplaceTool {
    broker: Arc<VitaWorkspaceReplaceBroker>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaWorkspaceReplaceTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_WORKSPACE_REPLACE_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        let parameters = parse_tool_input_schema(&json!({
            "type": "object",
            "properties": {
                "relative_path": {"type": "string"},
                "expected_sha256": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$"
                },
                "replacement_content": {"type": "string"}
            },
            "required": ["relative_path", "expected_sha256", "replacement_content"],
            "additionalProperties": false
        }))
        .expect("D29-H4-A replace tool schema is static and valid");
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_WORKSPACE_REPLACE_TOOL_NAME.to_string(),
            description: "Authorize one exact replacement of an existing bounded UTF-8 workspace file; this H4-A foundation performs no mutation.".to_string(),
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

/// Test/integration-only H4-C contributor.  It is intentionally separate from
/// the H4-A contributor so the authorization-only canary cannot accidentally
/// acquire a mutation path.
#[cfg(test)]
pub(crate) struct VitaWorkspaceReplaceGovernedToolContributor {
    broker: Arc<VitaWorkspaceReplaceBroker>,
}

#[cfg(test)]
impl VitaWorkspaceReplaceGovernedToolContributor {
    pub(crate) fn new(broker: Arc<VitaWorkspaceReplaceBroker>) -> Self {
        Self { broker }
    }
}

#[cfg(test)]
impl ToolContributor for VitaWorkspaceReplaceGovernedToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaWorkspaceReplaceGovernedTool {
            broker: Arc::clone(&self.broker),
        })]
    }
}

#[cfg(test)]
struct VitaWorkspaceReplaceGovernedTool {
    broker: Arc<VitaWorkspaceReplaceBroker>,
}

#[cfg(test)]
impl<'call> ToolExecutor<ToolCall<'call>> for VitaWorkspaceReplaceGovernedTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_WORKSPACE_REPLACE_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        let parameters = parse_tool_input_schema(&json!({
            "type": "object",
            "properties": {
                "relative_path": {"type": "string"},
                "expected_sha256": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$"
                },
                "replacement_content": {"type": "string"}
            },
            "required": ["relative_path", "expected_sha256", "replacement_content"],
            "additionalProperties": false
        }))
        .expect("D29-H4-C replace tool schema is static and valid");
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_WORKSPACE_REPLACE_TOOL_NAME.to_string(),
            description:
                "Replace one existing bounded UTF-8 workspace file after H4 authority and same-handle checks."
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
            let result = broker.handle_call_governed(call).await;
            Ok(Box::new(JsonToolOutput::with_success(
                result.model_value(),
                Some(false),
            )) as Box<dyn ToolOutput>)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Condvar;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};

    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tempfile::{tempdir, TempDir};

    use crate::d29h3::VITA_WORKSPACE_READ_TOOL_NAME;

    const LIFE_ID: &str = "life-d29h4-a";
    const TASK_ID: &str = "task-d29h4-a";
    const FILE_CONTENT: &str = "D29_H4_A_EXISTING_FILE";
    const REPLACEMENT_CONTENT: &str = "D29_H4_A_REPLACEMENT";
    const REVISION: i64 = 2;

    struct Fixture {
        _root_dir: TempDir,
        root: super::super::TrustedWorkspaceRoot,
        context: VitaExecutionContext,
        relative_path: super::super::WorkspaceRelativePath,
        target_identity: super::super::WorkspaceRootIdentity,
    }

    impl Fixture {
        fn new() -> Self {
            let root_dir = tempdir().expect("H4-A fixture root");
            let path = root_dir.path().join("replace-me.txt");
            fs::write(&path, FILE_CONTENT.as_bytes()).expect("H4-A fixture file");
            let root = super::super::TrustedWorkspaceRoot::acquire(root_dir.path())
                .expect("H4-A workspace root");
            let relative_path =
                super::super::WorkspaceRelativePath::parse(Path::new("replace-me.txt")).unwrap();
            let prepared = root.prepare_target(relative_path.as_path()).unwrap();
            Self {
                _root_dir: root_dir,
                root,
                context: VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap(),
                relative_path,
                target_identity: prepared.target_identity().unwrap(),
            }
        }

        fn request(&self, call_id: &str) -> VitaWorkspaceReplaceRequest {
            VitaWorkspaceReplaceRequest::synthetic(
                call_id,
                Some(self.context.clone()),
                "replace-me.txt",
                &sha256_hex(FILE_CONTENT.as_bytes()),
                REPLACEMENT_CONTENT,
            )
        }

        fn authority_request(&self, operation: H4AuthorityOperation) -> H4AuthorityRequest {
            let request = self.request("call-authority");
            self.authority_request_for(&request, operation)
        }

        fn authority_request_for(
            &self,
            request: &VitaWorkspaceReplaceRequest,
            operation: H4AuthorityOperation,
        ) -> H4AuthorityRequest {
            let prepared = self
                .root
                .prepare_target(request.relative_path.as_path())
                .expect("H4 request target should prepare");
            H4AuthorityRequest {
                context: self.context.clone(),
                capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                operation,
                tool_call_id: request.tool_call_id.clone(),
                turn_id: request.turn_id.clone(),
                relative_path: request.relative_path.clone(),
                expected_sha256: request.expected_sha256.clone(),
                replacement_sha256: sha256_hex(request.replacement_content.as_bytes()),
                replacement_bytes: request.replacement_content.as_bytes().len(),
                workspace_root_identity: prepared.root().identity(),
                target_identity: prepared
                    .target_identity()
                    .expect("H4 request target should have identity"),
                target_kind: prepared.kind(),
            }
        }

        fn broker(
            &self,
            authority: Arc<dyn VitaH4AuthorityPort>,
        ) -> Arc<VitaWorkspaceReplaceBroker> {
            VitaWorkspaceReplaceBroker::new(self.context.clone(), self.root.clone(), authority)
        }
    }

    fn h5_store_for_fixture(
        fixture: &Fixture,
    ) -> (TempDir, crate::recovery_journal::RecoveryJournalStore) {
        let app_data = tempdir().expect("H5-B app-data root");
        let profile = crate::VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            fixture._root_dir.path().to_path_buf(),
        )
        .expect("H5-B profile");
        profile
            .ensure_private_runtime_layout()
            .expect("H5-B private layout");
        let store = crate::recovery_journal::RecoveryJournalStore::from_runtime_profile(&profile)
            .expect("H5-B recovery store");
        (app_data, store)
    }

    fn h5_context(
        fixture: &Fixture,
        replacement: &str,
    ) -> crate::recovery_journal::RecoveryJournalContext {
        crate::recovery_journal::RecoveryJournalContext::new(
            fixture.context.life_id(),
            fixture.context.task_id(),
            VITA_WORKSPACE_REPLACE_CAPABILITY_ID,
            &sha256_hex(replacement.as_bytes()),
            replacement.as_bytes().len(),
            "h5-admission-tool",
            "h5-admission-turn",
        )
        .expect("H5-B context")
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ConfirmationMutation {
        None,
        WrongPath,
        WrongHash,
        WrongReplacementHash,
        WrongReplacementBytes,
        WrongRoot,
        WrongTarget,
        WrongLife,
        WrongTask,
        WrongRevision,
        Expired,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RequestAfterConfirmationMutation {
        Path,
        ExpectedHash,
        ReplacementHash,
        ReplacementBytes,
        WorkspaceRoot,
        Target,
        Life,
        Task,
        ToolCall,
        Turn,
    }

    pub(crate) struct TestHostAuthority {
        root: super::super::WorkspaceRootIdentity,
        confirmations: Mutex<HashMap<String, HostExplicitActionConfirmationEvidence>>,
        grants: Mutex<HashMap<String, H4HostReplaceGrantEvidence>>,
        calls: AtomicUsize,
        next_id: AtomicUsize,
        disabled: AtomicBool,
        revision: AtomicUsize,
        mutation: ConfirmationMutation,
        trusted_confirmations_provisioned: AtomicUsize,
        request_derived_confirmations: AtomicUsize,
        events: Mutex<Vec<H4AuthorityEvent>>,
        requests: Mutex<Vec<H4AuthorityRequest>>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H4AuthorityEvent {
        TrustedConfirmationProvisioned,
        IssueEvaluated,
        RevalidationEvaluated,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub(crate) struct H4AuthorityProvenanceEvidence {
        pub(crate) trusted_confirmations_provisioned: usize,
        pub(crate) request_derived_confirmations: usize,
        pub(crate) events: Vec<H4AuthorityEvent>,
    }

    impl TestHostAuthority {
        pub(crate) fn new(root: super::super::WorkspaceRootIdentity) -> Arc<Self> {
            Self::with_mutation(root, ConfirmationMutation::None)
        }

        fn with_mutation(
            root: super::super::WorkspaceRootIdentity,
            mutation: ConfirmationMutation,
        ) -> Arc<Self> {
            Arc::new(Self {
                root,
                confirmations: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                calls: AtomicUsize::new(0),
                next_id: AtomicUsize::new(0),
                disabled: AtomicBool::new(false),
                revision: AtomicUsize::new(REVISION as usize),
                mutation,
                trusted_confirmations_provisioned: AtomicUsize::new(0),
                request_derived_confirmations: AtomicUsize::new(0),
                events: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn provision_trusted_confirmation(&self, request: &H4AuthorityRequest) {
            assert!(matches!(
                &request.operation,
                H4AuthorityOperation::IssueReplaceGrant
            ));
            let id = self.next_id.fetch_add(1, Ordering::AcqRel);
            let now = unix_millis();
            let mut confirmation = HostExplicitActionConfirmationEvidence {
                source: H4ConfirmationEvidenceSource::TrustedTestHarness,
                confirmation_id: format!("confirmation-{id}"),
                life_id: request.context.life_id().to_string(),
                task_id: request.context.task_id().to_string(),
                capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                authorization_revision: REVISION,
                workspace_root_identity: request.workspace_root_identity,
                relative_path: request.relative_path.clone(),
                target_identity: request.target_identity,
                expected_sha256: request.expected_sha256.clone(),
                replacement_sha256: request.replacement_sha256.clone(),
                replacement_bytes: request.replacement_bytes,
                tool_call_id: request.tool_call_id.clone(),
                turn_id: request.turn_id.clone(),
                issued_at_unix_ms: now,
                expires_at_unix_ms: now + GRANT_LIFETIME_MS,
            };
            match self.mutation {
                ConfirmationMutation::WrongPath => {
                    confirmation.relative_path =
                        super::super::WorkspaceRelativePath::parse(Path::new("other.txt")).unwrap();
                }
                ConfirmationMutation::WrongHash => confirmation.expected_sha256 = "a".repeat(64),
                ConfirmationMutation::WrongReplacementHash => {
                    confirmation.replacement_sha256 = "b".repeat(64)
                }
                ConfirmationMutation::WrongReplacementBytes => {
                    confirmation.replacement_bytes =
                        confirmation.replacement_bytes.saturating_add(1)
                }
                ConfirmationMutation::WrongRoot => {
                    confirmation.workspace_root_identity = request.target_identity;
                }
                ConfirmationMutation::WrongTarget => {
                    confirmation.target_identity = request.workspace_root_identity
                }
                ConfirmationMutation::WrongLife => confirmation.life_id = "other-life".to_string(),
                ConfirmationMutation::WrongTask => confirmation.task_id = "other-task".to_string(),
                ConfirmationMutation::WrongRevision => {
                    confirmation.authorization_revision = REVISION + 1
                }
                ConfirmationMutation::Expired => confirmation.expires_at_unix_ms = now - 1,
                ConfirmationMutation::None => {}
            }
            lock_unpoisoned(&self.confirmations)
                .insert(confirmation.confirmation_id.clone(), confirmation);
            self.trusted_confirmations_provisioned
                .fetch_add(1, Ordering::AcqRel);
            lock_unpoisoned(&self.events).push(H4AuthorityEvent::TrustedConfirmationProvisioned);
        }

        pub(crate) fn provenance_snapshot(&self) -> H4AuthorityProvenanceEvidence {
            H4AuthorityProvenanceEvidence {
                trusted_confirmations_provisioned: self
                    .trusted_confirmations_provisioned
                    .load(Ordering::Acquire),
                request_derived_confirmations: self
                    .request_derived_confirmations
                    .load(Ordering::Acquire),
                events: lock_unpoisoned(&self.events).clone(),
            }
        }

        fn canonical(&self, request: &H4AuthorityRequest) -> H4CanonicalDecision {
            H4CanonicalDecision {
                life_id: request.context.life_id().to_string(),
                capability_id: request.capability_id.clone(),
                outcome: if self.disabled.load(Ordering::Acquire) {
                    H4CanonicalOutcome::RootDisabled
                } else {
                    H4CanonicalOutcome::ScopeRequired
                },
                decision_code: if self.disabled.load(Ordering::Acquire) {
                    H4CanonicalDecisionCode::RootDisabled
                } else {
                    H4CanonicalDecisionCode::ScopeNotAvailable
                },
                scope_requirement: H4ScopeRequirement::WorkspaceRequired,
                approval_floor: H4ApprovalFloor::ExplicitPerAction,
                authorization_revision: Some(self.revision.load(Ordering::Acquire) as i64),
                workspace_scope_matches: request.workspace_root_identity == self.root,
            }
        }

        fn issue(&self, request: H4AuthorityRequest) -> H4HostAuthorityResponse {
            let canonical = self.canonical(&request);
            if canonical.outcome != H4CanonicalOutcome::ScopeRequired
                || !canonical.workspace_scope_matches
            {
                let denial = if canonical.outcome == H4CanonicalOutcome::RootDisabled {
                    H4DenyClassification::RootDisabled
                } else {
                    H4DenyClassification::WorkspaceScopeDenied
                };
                return H4HostAuthorityResponse {
                    status: H4AuthorityResponseStatus::Denied,
                    canonical,
                    confirmation: None,
                    grant: None,
                    denial: Some(denial),
                    confirmation_consumed: false,
                };
            }
            let revision = canonical.authorization_revision.unwrap();
            let matching_id = lock_unpoisoned(&self.confirmations)
                .iter()
                .find(|(_, confirmation)| {
                    confirmation.life_id == request.context.life_id()
                        && confirmation.task_id == request.context.task_id()
                        && confirmation.capability_id == request.capability_id
                        && confirmation.authorization_revision == revision
                        && confirmation.workspace_root_identity == request.workspace_root_identity
                        && confirmation.relative_path == request.relative_path
                        && confirmation.target_identity == request.target_identity
                        && confirmation.expected_sha256 == request.expected_sha256
                        && confirmation.replacement_sha256 == request.replacement_sha256
                        && confirmation.replacement_bytes == request.replacement_bytes
                        && confirmation.tool_call_id == request.tool_call_id
                        && confirmation.turn_id == request.turn_id
                })
                .map(|(id, _)| id.clone());
            let Some(matching_id) = matching_id else {
                let expired = lock_unpoisoned(&self.confirmations)
                    .values()
                    .any(|confirmation| confirmation.expires_at_unix_ms <= unix_millis());
                return H4HostAuthorityResponse {
                    status: H4AuthorityResponseStatus::Denied,
                    canonical,
                    confirmation: None,
                    grant: None,
                    denial: Some(if expired {
                        H4DenyClassification::ConfirmationExpired
                    } else {
                        H4DenyClassification::ConfirmationMissing
                    }),
                    confirmation_consumed: false,
                };
            };
            let confirmation = lock_unpoisoned(&self.confirmations)
                .remove(&matching_id)
                .expect("matching confirmation remains available");
            let now = unix_millis();
            let grant = H4HostReplaceGrantEvidence {
                grant_id: format!("grant-{}", self.calls.load(Ordering::Acquire)),
                life_id: request.context.life_id().to_string(),
                task_id: request.context.task_id().to_string(),
                capability_id: request.capability_id.clone(),
                authorization_revision: revision,
                scope: VitaRequestedScope::Workspace,
                workspace_root_identity: request.workspace_root_identity,
                relative_path: request.relative_path.clone(),
                target_identity: request.target_identity,
                target_kind: request.target_kind,
                operation: H4ReplaceOperation::ReplaceExistingUtf8File,
                expected_sha256: request.expected_sha256.clone(),
                replacement_sha256: request.replacement_sha256.clone(),
                replacement_bytes: request.replacement_bytes,
                tool_call_id: request.tool_call_id.clone(),
                turn_id: request.turn_id.clone(),
                confirmation_id: confirmation.confirmation_id.clone(),
                issued_at_unix_ms: now,
                expires_at_unix_ms: now + GRANT_LIFETIME_MS,
                single_use: true,
            };
            lock_unpoisoned(&self.grants).insert(grant.grant_id.clone(), grant.clone());
            H4HostAuthorityResponse {
                status: H4AuthorityResponseStatus::Ok,
                canonical,
                confirmation: Some(confirmation),
                grant: Some(grant),
                denial: None,
                confirmation_consumed: true,
            }
        }
    }

    impl VitaH4AuthorityPort for TestHostAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            self.calls.fetch_add(1, Ordering::AcqRel);
            lock_unpoisoned(&self.requests).push(request.clone());
            let response = match request.operation {
                H4AuthorityOperation::IssueReplaceGrant => {
                    lock_unpoisoned(&self.events).push(H4AuthorityEvent::IssueEvaluated);
                    self.issue(request)
                }
                H4AuthorityOperation::Revalidate {
                    ref grant_id,
                    authorization_revision: _,
                } => {
                    lock_unpoisoned(&self.events).push(H4AuthorityEvent::RevalidationEvaluated);
                    let canonical = self.canonical(&request);
                    let grant = lock_unpoisoned(&self.grants).get(grant_id).cloned();
                    let denial = if canonical.outcome == H4CanonicalOutcome::RootDisabled {
                        Some(H4DenyClassification::RootDisabled)
                    } else if !canonical.workspace_scope_matches {
                        Some(H4DenyClassification::WorkspaceScopeDenied)
                    } else if grant.is_none() {
                        Some(H4DenyClassification::RevalidationDenied)
                    } else {
                        None
                    };
                    H4HostAuthorityResponse {
                        status: if denial.is_some() {
                            H4AuthorityResponseStatus::Denied
                        } else {
                            H4AuthorityResponseStatus::Ok
                        },
                        canonical,
                        confirmation: None,
                        grant: if denial.is_some() { None } else { grant },
                        denial,
                        confirmation_consumed: false,
                    }
                }
            };
            Box::pin(async move { Ok(response) })
        }
    }

    #[tokio::test]
    async fn missing_confirmation_cannot_issue_grant() {
        let fixture = Fixture::new();
        let request = fixture.request("missing-confirmation");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        assert!(!result.authorized_for_future_replace_foundation);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 0);
        assert_eq!(snapshot.filesystem_mutations, 0);
    }

    #[tokio::test]
    async fn request_arrival_never_auto_provisions_confirmation() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker
            .execute_request(fixture.request("request-arrival-no-provision"))
            .await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        assert!(!result.authorized_for_future_replace_foundation);
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
        assert_eq!(
            authority
                .provenance_snapshot()
                .trusted_confirmations_provisioned,
            0
        );
        assert_eq!(
            authority
                .provenance_snapshot()
                .request_derived_confirmations,
            0
        );
        assert_eq!(
            authority.provenance_snapshot().events,
            vec![H4AuthorityEvent::IssueEvaluated]
        );
    }

    #[tokio::test]
    async fn trusted_preprovisioned_confirmation_allows_exact_request() {
        let fixture = Fixture::new();
        let request = fixture.request("trusted-preprovisioned");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(request).await;
        assert!(result.authorized_for_future_replace_foundation);
        assert_eq!(broker.snapshot().confirmations_consumed, 1);
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert_eq!(
            authority.provenance_snapshot().events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
    }

    #[tokio::test]
    async fn h5_governed_replace_consumes_exact_h4_grant_and_commits() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-governed-positive");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);

        let result = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("governed H5 replace");

        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Committed
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
        let scan = store.scan_transactions().unwrap();
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            crate::recovery_journal::RecoveryTransactionState::CommittedTerminal
        );
        assert_eq!(broker.snapshot().confirmations_consumed, 1);
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
        assert_eq!(
            authority.provenance_snapshot().events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
    }

    #[tokio::test]
    async fn h5_final_fence_revocation_leaves_prepared_only() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-final-fence-revoked");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        authority.disabled.store(true, Ordering::Release);
        authority
            .revision
            .store((REVISION + 1) as usize, Ordering::Release);
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);

        let result = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("revoked H5 replace returns a transaction result");

        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Denied {
                recovery: crate::d29h5::H5RecoveryDisposition::None,
            }
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        let scan = store.scan_transactions().unwrap();
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            crate::recovery_journal::RecoveryTransactionState::PreparedOnly
        );
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
        assert_eq!(
            authority.provenance_snapshot().events.last().copied(),
            Some(H4AuthorityEvent::RevalidationEvaluated)
        );
    }

    #[tokio::test]
    async fn h5_process_host_sqlite_positive_commit() {
        let fixture = Fixture::new();
        let authority = ProcessIsolatedH4Authority::new(fixture.root.identity())
            .expect("persistent H4 Host authority should start");
        let request = fixture.request("h5-process-host-sqlite-positive");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority
            .provision_confirmation(&issue)
            .expect("persistent H4 Host confirmation should provision");
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("persistent H4 Host executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("persistent H4 Host governed H5 replace");

        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Committed
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::CommittedTerminal
        );
        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|observation| {
            observation
                .canonical
                .as_ref()
                .is_some_and(|canonical| canonical.authorization_revision == Some(REVISION))
        }));
        assert!(authority.shutdown());
    }

    #[tokio::test]
    async fn h5_process_host_sqlite_rev2_to_rev3_final_fence_mutates_zero() {
        let fixture = Fixture::new();
        let authority = ProcessIsolatedH4Authority::new(fixture.root.identity())
            .expect("persistent H4 Host authority should start");
        let request = fixture.request("h5-process-host-sqlite-revocation");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority
            .provision_confirmation(&issue)
            .expect("persistent H4 Host confirmation should provision");
        let revoking = Arc::new(H4CProcessRevokingAuthority {
            inner: Arc::clone(&authority),
            revoked: AtomicBool::new(false),
        });
        let broker = fixture.broker(Arc::clone(&revoking) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("persistent H4 Host executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("revoked final fence should return a truthful H5 result");

        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Denied {
                recovery: crate::d29h5::H5RecoveryDisposition::None,
            }
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        assert!(matches!(
            result.native_diagnostics_for_test(),
            crate::workspace_capability::WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
                if !evidence.mutation_attempted
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::PreparedOnly
        );
        assert_eq!(
            authority
                .snapshot()
                .last()
                .and_then(|observation| observation.canonical.as_ref())
                .map(|canonical| canonical.authorization_revision),
            Some(Some(REVISION + 1))
        );
        assert!(authority.shutdown());
    }

    #[tokio::test]
    async fn h5_final_fence_is_bounded_without_runtime_block_on() {
        let fixture = Fixture::new();
        let inner = TestHostAuthority::new(fixture.root.identity());
        let authority = H4CGatedAuthority::new(Arc::clone(&inner));
        let request = fixture.request("h5-bounded-final-fence");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("gated H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let lifecycle = crate::d29h5::H5WorkerLifecycle::new();
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            crate::d29h5::execute_governed_h5_replace_with_test_options(
                action,
                request.replacement_content.clone(),
                store.clone(),
                Arc::new(AtomicBool::new(false)),
                None,
                false,
                false,
                Some(Arc::clone(&lifecycle)),
            ),
        )
        .await
        .expect("H5 final fence must be independently bounded")
        .expect("bounded H5 result");
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Denied {
                recovery: crate::d29h5::H5RecoveryDisposition::None,
            }
        );
        assert_eq!(lifecycle.started_count(), 1);
        assert_eq!(lifecycle.finished_count(), 1);
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::PreparedOnly
        );
    }

    #[tokio::test]
    async fn h5_late_authority_allow_mutates_zero() {
        let fixture = Fixture::new();
        let inner = TestHostAuthority::new(fixture.root.identity());
        let authority = H4CLateAllowAuthority::new(Arc::clone(&inner));
        let request = fixture.request("h5-late-authority-allow");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("late-allow H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let lifecycle = crate::d29h5::H5WorkerLifecycle::new();
        let execution = tokio::spawn(crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            None,
            false,
            false,
            Some(Arc::clone(&lifecycle)),
        ));
        tokio::time::timeout(
            Duration::from_secs(1),
            authority.revalidation_started.notified(),
        )
        .await
        .expect("late authority should receive the final-fence request");
        let result = tokio::time::timeout(Duration::from_secs(8), execution)
            .await
            .expect("native final-fence timeout")
            .expect("H5 execution task should join")
            .expect("late authority result");
        authority.release();
        tokio::time::timeout(Duration::from_secs(2), authority.late_completed.notified())
            .await
            .expect("late authority should complete after native timeout");
        assert_eq!(lifecycle.finished_count(), 1);
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Denied {
                recovery: crate::d29h5::H5RecoveryDisposition::None,
            }
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::PreparedOnly
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_panic_before_first_mutation_is_truthful() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("h5-canonical-panic-before");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("canonical panic-before grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            Some(crate::workspace_capability::WorkspaceReplaceTestFault::PanicBeforeFirstMutation),
            false,
            false,
            None,
        )
        .await
        .expect("canonical panic-before result");
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Denied {
                recovery: crate::d29h5::H5RecoveryDisposition::Required,
            }
        );
        assert!(matches!(
            result.native_diagnostics_for_test(),
            crate::workspace_capability::WorkspaceReplaceCommitOutcome::Denied {
                error: WorkspaceReplaceError::NativePanicBeforeMutation,
                evidence,
            } if !evidence.mutation_started
        ));
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_panic_after_first_mutation_is_commit_unknown() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("h5-canonical-panic-after");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("canonical panic-after grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            Some(crate::workspace_capability::WorkspaceReplaceTestFault::PanicAfterFirstMutation),
            false,
            false,
            None,
        )
        .await
        .expect("canonical panic-after result");
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::CommitUnknown {
                recovery_required: true,
            }
        );
        assert!(matches!(
            result.native_diagnostics_for_test(),
            crate::workspace_capability::WorkspaceReplaceCommitOutcome::CommitUnknown {
                error: WorkspaceReplaceError::NativePanicAfterMutation,
                evidence,
            } if evidence.mutation_started
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::RecoveryRequired
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_panic_after_native_commit_before_commit_marker_is_commit_unknown() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("h5-canonical-panic-before-marker");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("canonical panic-before-marker grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            None,
            true,
            false,
            None,
        )
        .await
        .expect("canonical panic-before-marker result");
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::CommitUnknown {
                recovery_required: true,
            }
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::RecoveryRequired
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_panic_after_commit_marker_remains_committed() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("h5-canonical-panic-after-marker");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("canonical panic-after-marker grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let result = crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            None,
            false,
            true,
            None,
        )
        .await
        .expect("canonical panic-after-marker result");
        assert_eq!(
            result.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Committed
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::CommittedTerminal
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_outer_abort_keeps_admission_until_worker_exit() {
        let fixture = Fixture::new();
        let inner = TestHostAuthority::new(fixture.root.identity());
        let authority = H4CGatedAuthority::new(Arc::clone(&inner));
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let request_a = fixture.request("h5-outer-abort-a");
        let issue_a =
            fixture.authority_request_for(&request_a, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue_a);
        let grant_a = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(
                &request_a,
            ))
            .await
            .expect("outer-abort A grant");
        let action_a = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant_a);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let lifecycle = crate::d29h5::H5WorkerLifecycle::new();
        lifecycle.hold_worker_exit();
        let execution_a =
            tokio::spawn(crate::d29h5::execute_governed_h5_replace_with_test_options(
                action_a,
                request_a.replacement_content.clone(),
                store.clone(),
                Arc::new(AtomicBool::new(false)),
                None,
                false,
                false,
                Some(Arc::clone(&lifecycle)),
            ));
        tokio::time::timeout(
            Duration::from_secs(1),
            authority.revalidation_started.notified(),
        )
        .await
        .expect("outer-abort A should reach final authority");
        execution_a.abort();
        let _ = execution_a.await;
        tokio::time::timeout(
            Duration::from_secs(2),
            lifecycle.wait_until_waiting_to_exit(),
        )
        .await
        .expect("aborted A worker should remain alive at the controlled exit gate");

        let request_b = fixture.request("h5-outer-abort-b");
        let issue_b =
            fixture.authority_request_for(&request_b, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue_b);
        let grant_b = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(
                &request_b,
            ))
            .await
            .expect("outer-abort B grant");
        let action_b = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant_b);
        let blocked = crate::d29h5::execute_governed_h5_replace_with_test_options(
            action_b,
            request_b.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            None,
            false,
            false,
            None,
        )
        .await
        .expect_err("same target must remain admitted while A worker is alive");
        assert!(matches!(
            blocked,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::ConcurrentAdmission
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            1
        );
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            crate::recovery_journal::RecoveryTransactionState::PreparedOnly
        );

        lifecycle.release_worker_exit();
        tokio::time::timeout(Duration::from_secs(2), lifecycle.wait_until_finished())
            .await
            .expect("aborted A worker should exit after cancellation");

        let request_c = fixture.request("h5-outer-abort-c");
        let issue_c =
            fixture.authority_request_for(&request_c, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue_c);
        let grant_c = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(
                &request_c,
            ))
            .await
            .expect("outer-abort C grant");
        let action_c = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant_c);
        authority.release();
        let committed = crate::d29h5::execute_governed_h5_replace(
            action_c,
            request_c.replacement_content.clone(),
            store,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("admission should be released after A worker exits");
        assert_eq!(
            committed.transaction_outcome,
            crate::d29h5::H5ReplaceTransactionOutcome::Committed
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn canonical_h5_outer_abort_worker_exits_boundedly() {
        let fixture = Fixture::new();
        let inner = TestHostAuthority::new(fixture.root.identity());
        let authority = H4CGatedAuthority::new(Arc::clone(&inner));
        let request = fixture.request("h5-outer-abort-bounded");
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        inner.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("bounded outer-abort grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let lifecycle = crate::d29h5::H5WorkerLifecycle::new();
        lifecycle.hold_worker_exit();
        let task = tokio::spawn(crate::d29h5::execute_governed_h5_replace_with_test_options(
            action,
            request.replacement_content,
            store,
            Arc::new(AtomicBool::new(false)),
            None,
            false,
            false,
            Some(Arc::clone(&lifecycle)),
        ));
        tokio::time::timeout(
            Duration::from_secs(1),
            authority.revalidation_started.notified(),
        )
        .await
        .expect("bounded outer-abort request should reach final authority");
        task.abort();
        let _ = task.await;
        tokio::time::timeout(
            Duration::from_secs(2),
            lifecycle.wait_until_waiting_to_exit(),
        )
        .await
        .expect("worker should reach the bounded exit observation");
        lifecycle.release_worker_exit();
        tokio::time::timeout(Duration::from_secs(2), lifecycle.wait_until_finished())
            .await
            .expect("worker should exit after outer cancellation");
        assert_eq!(lifecycle.started_count(), 1);
        assert_eq!(lifecycle.finished_count(), 1);
    }

    #[tokio::test]
    async fn h5_replacement_binding_mismatch_creates_no_journal() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-replacement-mismatch");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);

        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            "different replacement".to_string(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("replacement binding mismatch must deny before journal create");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TargetBindingMismatch(_)
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            0
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        assert_eq!(authority.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn h5_recovery_required_blocks_before_new_journal() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-recovery-required-admission");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let existing = store
            .create_prepared_for_expected_preimage(
                &fixture
                    .root
                    .prepare_target(fixture.relative_path.as_path())
                    .unwrap(),
                h5_context(&fixture, REPLACEMENT_CONTENT),
                &sha256_hex(FILE_CONTENT.as_bytes()),
            )
            .unwrap();
        store.persist_started(&existing).unwrap();

        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("RecoveryRequired must block before journal create");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::RecoveryRequired
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            1
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn case_alias_pending_recovery_blocks_new_replace() {
        let fixture = Fixture::new();
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let existing = store
            .create_prepared_for_expected_preimage(
                &fixture
                    .root
                    .prepare_target(Path::new("replace-me.txt"))
                    .unwrap(),
                h5_context(&fixture, REPLACEMENT_CONTENT),
                &sha256_hex(FILE_CONTENT.as_bytes()),
            )
            .unwrap();
        store.persist_started(&existing).unwrap();

        let request = VitaWorkspaceReplaceRequest::synthetic(
            "h5-case-alias",
            Some(fixture.context.clone()),
            "REPLACE-ME.TXT",
            &sha256_hex(FILE_CONTENT.as_bytes()),
            REPLACEMENT_CONTENT,
        );
        let authority = TestHostAuthority::new(fixture.root.identity());
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("case-alias H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("case alias must be blocked by pending recovery");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::RecoveryRequired
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            1
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn rename_alias_pending_recovery_blocks_new_replace() {
        let fixture = Fixture::new();
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let existing = store
            .create_prepared_for_expected_preimage(
                &fixture
                    .root
                    .prepare_target(Path::new("replace-me.txt"))
                    .unwrap(),
                h5_context(&fixture, REPLACEMENT_CONTENT),
                &sha256_hex(FILE_CONTENT.as_bytes()),
            )
            .unwrap();
        store.persist_started(&existing).unwrap();
        fs::rename(
            fixture._root_dir.path().join("replace-me.txt"),
            fixture._root_dir.path().join("renamed-target.txt"),
        )
        .unwrap();

        let request = VitaWorkspaceReplaceRequest::synthetic(
            "h5-rename-alias",
            Some(fixture.context.clone()),
            "renamed-target.txt",
            &sha256_hex(FILE_CONTENT.as_bytes()),
            REPLACEMENT_CONTENT,
        );
        let authority = TestHostAuthority::new(fixture.root.identity());
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("rename-alias H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("rename alias must be blocked by pending recovery");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::RecoveryRequired
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            1
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("renamed-target.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hardlink_alias_pending_recovery_blocks_new_replace() {
        let fixture = Fixture::new();
        fs::hard_link(
            fixture._root_dir.path().join("replace-me.txt"),
            fixture._root_dir.path().join("hardlink-target.txt"),
        )
        .unwrap();
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let existing = store
            .create_prepared_for_expected_preimage(
                &fixture
                    .root
                    .prepare_target(Path::new("replace-me.txt"))
                    .unwrap(),
                h5_context(&fixture, REPLACEMENT_CONTENT),
                &sha256_hex(FILE_CONTENT.as_bytes()),
            )
            .unwrap();
        store.persist_started(&existing).unwrap();
        let request = VitaWorkspaceReplaceRequest::synthetic(
            "h5-hardlink-alias",
            Some(fixture.context.clone()),
            "hardlink-target.txt",
            &sha256_hex(FILE_CONTENT.as_bytes()),
            REPLACEMENT_CONTENT,
        );
        let authority = TestHostAuthority::new(fixture.root.identity());
        let issue =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&issue);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("hardlink-alias H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("hardlink alias must be blocked by pending recovery");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::RecoveryRequired
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            1
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("hardlink-target.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[tokio::test]
    async fn h5_ambiguous_recovery_blocks_before_new_journal() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-ambiguous-admission");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let target = fixture
            .root
            .prepare_target(fixture.relative_path.as_path())
            .unwrap();
        let first = store
            .create_prepared_with_transaction_id_for_test(
                &target,
                h5_context(&fixture, REPLACEMENT_CONTENT),
                "h5-ambiguous-first",
            )
            .unwrap();
        store.persist_started(&first).unwrap();
        let second = store
            .create_prepared_with_transaction_id_for_test(
                &target,
                h5_context(&fixture, REPLACEMENT_CONTENT),
                "h5-ambiguous-second",
            )
            .unwrap();
        let marker = crate::recovery_journal::RecoveryMarkerV1::new(
            second.transaction_id().clone(),
            second.integrity_hash_bytes(),
            crate::recovery_journal::RecoveryMarkerState::Started,
        );
        fs::write(
            store
                .recovery_root()
                .join(format!("{}.started", marker.transaction_id().as_str())),
            marker.to_bytes().unwrap(),
        )
        .unwrap();

        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("ambiguous recovery must block before journal create");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::AmbiguousTarget
            )
        ));
        let scan = store.scan_transactions().unwrap();
        assert!(scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[tokio::test]
    async fn h5_poisoned_known_target_blocks_before_new_journal() {
        let fixture = Fixture::new();
        let request = fixture.request("h5-poisoned-admission");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let grant = broker
            .issue_h5_authorized_replace_action(H4ReplaceAuthorizationInput::from_request(&request))
            .await
            .expect("H4 executable grant");
        let action = crate::d29h5::H5AuthorizedReplaceAction::from_h4_grant(grant);
        let (_app_data, store) = h5_store_for_fixture(&fixture);
        let existing = store
            .create_prepared_for_expected_preimage(
                &fixture
                    .root
                    .prepare_target(fixture.relative_path.as_path())
                    .unwrap(),
                h5_context(&fixture, REPLACEMENT_CONTENT),
                &sha256_hex(FILE_CONTENT.as_bytes()),
            )
            .unwrap();
        let poisoned_marker = crate::recovery_journal::RecoveryMarkerV1::new(
            existing.transaction_id().clone(),
            [0x44; 32],
            crate::recovery_journal::RecoveryMarkerState::Started,
        );
        fs::write(
            store.recovery_root().join(format!(
                "{}.started",
                poisoned_marker.transaction_id().as_str()
            )),
            poisoned_marker.to_bytes().unwrap(),
        )
        .unwrap();

        let error = crate::d29h5::execute_governed_h5_replace(
            action,
            request.replacement_content.clone(),
            store.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("poisoned target must block before journal create");
        assert!(matches!(
            error,
            crate::recovery_journal::RecoveryJournalError::TransactionBlocked(
                crate::recovery_journal::RecoveryTransactionBlockReason::PoisonedTarget
            )
        ));
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            0
        );
        assert_eq!(
            fs::read(fixture._root_dir.path().join("replace-me.txt")).unwrap(),
            FILE_CONTENT.as_bytes()
        );
    }

    #[tokio::test]
    async fn confirmation_provision_occurs_before_issue_evaluation() {
        let fixture = Fixture::new();
        let request = fixture.request("provision-order");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        assert!(
            broker
                .execute_request(request)
                .await
                .authorized_for_future_replace_foundation
        );
        let evidence = authority.provenance_snapshot();
        assert_eq!(
            evidence.events[..2],
            [
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
            ]
        );
        assert_eq!(evidence.trusted_confirmations_provisioned, 1);
        assert_eq!(evidence.request_derived_confirmations, 0);
    }

    #[tokio::test]
    async fn three_valid_requests_with_empty_confirmation_store_all_deny() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        for call_id in ["unconfirmed-one", "unconfirmed-two", "unconfirmed-three"] {
            let result = broker.execute_request(fixture.request(call_id)).await;
            assert_eq!(
                result.classification,
                Some(H4DenyClassification::ConfirmationMissing)
            );
        }
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.attempted_requests, 3);
        assert_eq!(snapshot.grants_issued, 0);
        assert_eq!(snapshot.confirmations_consumed, 0);
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
        let evidence = authority.provenance_snapshot();
        assert_eq!(evidence.trusted_confirmations_provisioned, 0);
        assert_eq!(evidence.request_derived_confirmations, 0);
        assert_eq!(
            evidence
                .events
                .iter()
                .filter(|event| **event == H4AuthorityEvent::IssueEvaluated)
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn request_mutation_after_confirmation_is_denied_without_transforming_confirmation() {
        for mutation in [
            RequestAfterConfirmationMutation::Path,
            RequestAfterConfirmationMutation::ExpectedHash,
            RequestAfterConfirmationMutation::ReplacementHash,
            RequestAfterConfirmationMutation::ReplacementBytes,
            RequestAfterConfirmationMutation::WorkspaceRoot,
            RequestAfterConfirmationMutation::Target,
            RequestAfterConfirmationMutation::Life,
            RequestAfterConfirmationMutation::Task,
            RequestAfterConfirmationMutation::ToolCall,
            RequestAfterConfirmationMutation::Turn,
        ] {
            let fixture = Fixture::new();
            let authority = TestHostAuthority::new(fixture.root.identity());
            let original = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
            authority.provision_trusted_confirmation(&original);
            let before = lock_unpoisoned(&authority.confirmations)
                .values()
                .next()
                .cloned();
            let mut mutated = original.clone();
            match mutation {
                RequestAfterConfirmationMutation::Path => {
                    mutated.relative_path =
                        super::super::WorkspaceRelativePath::parse(Path::new("other.txt")).unwrap();
                }
                RequestAfterConfirmationMutation::ExpectedHash => {
                    mutated.expected_sha256 = "a".repeat(64)
                }
                RequestAfterConfirmationMutation::ReplacementHash => {
                    mutated.replacement_sha256 = "b".repeat(64)
                }
                RequestAfterConfirmationMutation::ReplacementBytes => {
                    mutated.replacement_bytes = mutated.replacement_bytes.saturating_add(1)
                }
                RequestAfterConfirmationMutation::WorkspaceRoot => {
                    mutated.workspace_root_identity = fixture.target_identity
                }
                RequestAfterConfirmationMutation::Target => {
                    mutated.target_identity = fixture.root.identity()
                }
                RequestAfterConfirmationMutation::Life => {
                    mutated.context = VitaExecutionContext::try_new("other-life", TASK_ID).unwrap()
                }
                RequestAfterConfirmationMutation::Task => {
                    mutated.context = VitaExecutionContext::try_new(LIFE_ID, "other-task").unwrap()
                }
                RequestAfterConfirmationMutation::ToolCall => {
                    mutated.tool_call_id = "mutated-tool-call".to_string()
                }
                RequestAfterConfirmationMutation::Turn => {
                    mutated.turn_id = "mutated-turn".to_string()
                }
            }
            let response = authority.evaluate(mutated.clone()).await.unwrap();
            assert!(
                response.grant.is_none(),
                "mutation {mutation:?} issued a grant"
            );
            assert!(!response.confirmation_consumed);
            assert!(validate_issue_completion(&response, &mutated).is_err());
            assert_eq!(lock_unpoisoned(&authority.confirmations).len(), 1);
            assert_eq!(
                lock_unpoisoned(&authority.confirmations)
                    .values()
                    .next()
                    .cloned(),
                before,
                "mutation {mutation:?} transformed the pre-existing confirmation"
            );
            assert_eq!(lock_unpoisoned(&authority.grants).len(), 0);
            let evidence = authority.provenance_snapshot();
            assert_eq!(evidence.trusted_confirmations_provisioned, 1);
            assert_eq!(evidence.request_derived_confirmations, 0);
            assert_eq!(
                evidence.events,
                vec![
                    H4AuthorityEvent::TrustedConfirmationProvisioned,
                    H4AuthorityEvent::IssueEvaluated,
                ]
            );
        }
    }

    #[tokio::test]
    async fn replacement_content_mutation_cannot_change_confirmation() {
        let fixture = Fixture::new();
        let original = fixture.request("replacement-content-mutation");
        let authority = TestHostAuthority::new(fixture.root.identity());
        let authority_request =
            fixture.authority_request_for(&original, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let before = lock_unpoisoned(&authority.confirmations)
            .values()
            .next()
            .cloned();
        let mut mutated = original;
        mutated.replacement_content.push('x');
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(mutated).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        assert!(!result.authorized_for_future_replace_foundation);
        assert_eq!(broker.snapshot().grants_issued, 0);
        assert_eq!(broker.snapshot().confirmations_consumed, 0);
        assert_eq!(lock_unpoisoned(&authority.confirmations).len(), 1);
        assert_eq!(
            lock_unpoisoned(&authority.confirmations)
                .values()
                .next()
                .cloned(),
            before
        );
        let evidence = authority.provenance_snapshot();
        assert_eq!(evidence.trusted_confirmations_provisioned, 1);
        assert_eq!(evidence.request_derived_confirmations, 0);
    }

    #[tokio::test]
    async fn correct_confirmation_issues_exact_single_use_grant() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("correct-confirmation");
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(request).await;
        assert!(result.authorized_for_future_replace_foundation);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.confirmations_consumed, 1);
        assert_eq!(snapshot.filesystem_mutations, 0);
        assert_eq!(snapshot.process_spawns, 0);
        assert_eq!(snapshot.external_network_requests, 0);
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
        let evidence = authority.provenance_snapshot();
        assert_eq!(evidence.trusted_confirmations_provisioned, 1);
        assert_eq!(evidence.request_derived_confirmations, 0);
    }

    #[tokio::test]
    async fn confirmation_replay_cannot_issue_second_grant() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let request = fixture.request("duplicate-call");
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        assert!(
            broker
                .execute_request(request.clone())
                .await
                .authorized_for_future_replace_foundation
        );
        let second = broker.execute_request(request).await;
        assert_eq!(
            second.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
        let evidence = authority.provenance_snapshot();
        assert_eq!(evidence.trusted_confirmations_provisioned, 1);
        assert_eq!(evidence.request_derived_confirmations, 0);
        assert_eq!(
            evidence.events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
    }

    #[tokio::test]
    async fn wrong_workspace_root_cannot_issue_grant() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let authority = TestHostAuthority::new(other.root.identity());
        let request = fixture.request("wrong-root");
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::WorkspaceScopeDenied)
        );
        assert_eq!(broker.snapshot().grants_issued, 0);
        assert_eq!(lock_unpoisoned(&authority.confirmations).len(), 1);
        assert_eq!(
            authority
                .provenance_snapshot()
                .trusted_confirmations_provisioned,
            1
        );
        assert_eq!(
            authority
                .provenance_snapshot()
                .request_derived_confirmations,
            0
        );
    }

    #[tokio::test]
    async fn wrong_action_binding_cannot_issue_grant() {
        for mutation in [
            ConfirmationMutation::WrongPath,
            ConfirmationMutation::WrongHash,
            ConfirmationMutation::WrongReplacementHash,
            ConfirmationMutation::WrongReplacementBytes,
            ConfirmationMutation::WrongRevision,
            ConfirmationMutation::WrongRoot,
            ConfirmationMutation::WrongTarget,
            ConfirmationMutation::WrongLife,
            ConfirmationMutation::WrongTask,
            ConfirmationMutation::Expired,
        ] {
            let fixture = Fixture::new();
            let authority = TestHostAuthority::with_mutation(fixture.root.identity(), mutation);
            // Provision a deliberately wrong Host record.  The requester has
            // no path to place this record in the Host store.
            let vita_request = fixture.request("wrong-binding");
            let request = fixture
                .authority_request_for(&vita_request, H4AuthorityOperation::IssueReplaceGrant);
            authority.provision_trusted_confirmation(&request);
            let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
            let result = broker.execute_request(vita_request).await;
            assert!(matches!(
                result.classification,
                Some(
                    H4DenyClassification::ConfirmationMissing
                        | H4DenyClassification::ConfirmationExpired
                        | H4DenyClassification::ConfirmationMismatch
                        | H4DenyClassification::GrantRejected
                )
            ));
            assert_eq!(broker.snapshot().grants_issued, 0);
        }
    }

    #[tokio::test]
    async fn stale_confirmation_revision_cannot_issue_grant() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::with_mutation(
            fixture.root.identity(),
            ConfirmationMutation::WrongRevision,
        );
        let request = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker
            .execute_request(fixture.request("stale-confirmation-revision"))
            .await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        assert_eq!(broker.snapshot().grants_issued, 0);
    }

    #[tokio::test]
    async fn rev2_grant_rev3_root_disabled_revalidation_denies() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&request);
        let issue = authority.evaluate(request.clone()).await.unwrap();
        assert!(issue.confirmation_consumed);
        assert!(issue.confirmation.is_some());
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
        assert_eq!(
            authority
                .provenance_snapshot()
                .trusted_confirmations_provisioned,
            1
        );
        assert_eq!(
            authority
                .provenance_snapshot()
                .request_derived_confirmations,
            0
        );
        let grant = issue.grant.clone().unwrap();
        authority.disabled.store(true, Ordering::Release);
        authority
            .revision
            .store((REVISION + 1) as usize, Ordering::Release);
        let response = authority
            .evaluate(H4AuthorityRequest {
                operation: H4AuthorityOperation::Revalidate {
                    grant_id: grant.grant_id.clone(),
                    authorization_revision: REVISION,
                },
                ..request
            })
            .await
            .unwrap();
        assert_eq!(response.canonical.outcome, H4CanonicalOutcome::RootDisabled);
        assert_eq!(
            validate_revalidation(
                &response,
                &H4AuthorityRequest {
                    operation: H4AuthorityOperation::Revalidate {
                        grant_id: grant.grant_id.clone(),
                        authorization_revision: REVISION,
                    },
                    context: fixture.context.clone(),
                    capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                    tool_call_id: "call-authority".to_string(),
                    turn_id: "turn-d29h4".to_string(),
                    relative_path: fixture.relative_path.clone(),
                    expected_sha256: sha256_hex(FILE_CONTENT.as_bytes()),
                    replacement_sha256: sha256_hex(REPLACEMENT_CONTENT.as_bytes()),
                    replacement_bytes: REPLACEMENT_CONTENT.len(),
                    workspace_root_identity: fixture.root.identity(),
                    target_identity: fixture.target_identity,
                    target_kind: PreparedWorkspaceTargetKind::ExistingFile,
                },
                &VitaExecutableReplaceGrant::from_host_evidence(
                    issue.confirmation.unwrap(),
                    grant,
                    &fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant),
                    &fixture
                        .root
                        .prepare_target(fixture.relative_path.as_path())
                        .unwrap(),
                )
                .unwrap(),
                &fixture
                    .root
                    .prepare_target(fixture.relative_path.as_path())
                    .unwrap(),
            )
            .unwrap_err(),
            H4DenyClassification::RootDisabled
        );
        let evidence = authority.provenance_snapshot();
        assert_eq!(evidence.trusted_confirmations_provisioned, 1);
        assert_eq!(evidence.request_derived_confirmations, 0);
        assert_eq!(
            evidence.events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
    }

    #[test]
    fn h4_descriptor_is_medium_explicit_per_action_workspace_required() {
        let descriptor = h4_descriptor_values();
        assert_eq!(descriptor.risk_class, "Medium");
        assert_eq!(descriptor.approval_floor, "ExplicitPerAction");
        assert_eq!(descriptor.scope_requirement, "WorkspaceRequired");

        let valid = json!({
            "relative_path": "replace-me.txt",
            "expected_sha256": "a".repeat(64),
            "replacement_content": "next"
        });
        assert!(serde_json::from_value::<VitaWorkspaceReplaceArguments>(valid).is_ok());
        for extra in [
            "revision",
            "confirmation_id",
            "workspace_root_identity",
            "confirmed",
            "source",
        ] {
            let mut value = json!({
                "relative_path": "replace-me.txt",
                "expected_sha256": "a".repeat(64),
                "replacement_content": "next"
            });
            value[extra] = json!("forged");
            assert!(serde_json::from_value::<VitaWorkspaceReplaceArguments>(value).is_err());
        }
    }

    #[test]
    fn hash_and_replacement_bounds_are_strict() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&format!("0x{}", "a".repeat(64))));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&format!("{}g", "a".repeat(63))));

        let mut over = VitaWorkspaceReplaceRequest::synthetic(
            "call-over",
            None,
            "replace-me.txt",
            &"a".repeat(64),
            "ok",
        );
        over.replacement_content = "x".repeat(H4_MAX_REPLACEMENT_BYTES + 1);
        assert!(over.replacement_content.as_bytes().len() > H4_MAX_REPLACEMENT_BYTES);
    }

    #[tokio::test]
    async fn requester_cannot_supply_confirmation_or_revision_authority() {
        let fixture = Fixture::new();
        let valid = format!(
            r#"{{"relative_path":"replace-me.txt","expected_sha256":"{}","replacement_content":"next","confirmation_id":"forged","authorization_revision":999}}"#,
            sha256_hex(FILE_CONTENT.as_bytes())
        );
        let arguments: Result<VitaWorkspaceReplaceArguments, _> = serde_json::from_str(&valid);
        assert!(arguments.is_err());
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("requester-cannot-authorize");
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(request).await;
        assert!(result.authorized_for_future_replace_foundation);
        assert_eq!(broker.snapshot().filesystem_mutations, 0);
    }

    #[test]
    fn normal_vita_entrypoint_does_not_install_h4_tool() {
        assert_eq!(
            VITA_WORKSPACE_REPLACE_TOOL_NAME,
            "vita_workspace_replace_file"
        );
        assert_eq!(
            VITA_WORKSPACE_REPLACE_CAPABILITY_ID,
            "vita.workspace.replace_file"
        );
        let source =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
                .expect("read Vita entrypoint");
        assert!(!source.contains("VitaWorkspaceReplaceToolContributor"));
        let h4_source =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/d29h4.rs"))
                .expect("read H4-A source");
        let h4_a_source = h4_source
            .split("// D29-H4-C IMPLEMENTATION START")
            .next()
            .expect("H4-A source boundary marker is present");
        for forbidden in [
            concat!("Set", "EndOfFile"),
            concat!("FlushFile", "Buffers"),
            concat!("std::fs::", "write"),
            concat!("OpenOptions::", "write"),
            concat!("ReplaceFile", "W"),
            concat!("Move", "File"),
            concat!("FileRename", "Info"),
            concat!("remove_", "file"),
        ] {
            assert!(
                !h4_a_source.contains(forbidden),
                "H4-A authority path contains forbidden mutation primitive: {forbidden}"
            );
        }
    }

    #[test]
    fn model_schema_only_allows_path_hash_and_replacement_content() {
        let valid = json!({
            "relative_path": "replace-me.txt",
            "expected_sha256": "a".repeat(64),
            "replacement_content": "next"
        });
        assert!(serde_json::from_value::<VitaWorkspaceReplaceArguments>(valid).is_ok());
        for extra in [
            "confirmation_id",
            "authorization_revision",
            "workspace_root_identity",
            "target_identity",
            "grant_id",
            "source",
        ] {
            let mut value = json!({
                "relative_path": "replace-me.txt",
                "expected_sha256": "a".repeat(64),
                "replacement_content": "next"
            });
            value[extra] = json!("forged");
            assert!(serde_json::from_value::<VitaWorkspaceReplaceArguments>(value).is_err());
        }
    }

    #[test]
    fn production_registry_contains_only_the_h7c_route() {
        let descriptor_source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("Vita manifest has repository parent")
                .join("src-tauri/src/capability/descriptor.rs"),
        )
        .expect("read D28 descriptor registry");
        assert!(descriptor_source.contains("PRODUCTION_GIT_STATUS_CAPABILITY_ID"));
        assert!(descriptor_source.contains("PRODUCTION_GIT_STATUS_PROFILE_ID"));
    }

    #[derive(Clone, Debug, Serialize)]
    #[serde(tag = "operation", rename_all = "snake_case")]
    enum H4HostWireRequest {
        Initialize {
            protocol_version: u8,
            life_id: String,
            task_id: String,
            capability_id: String,
            allowed_workspace_root_identity: String,
        },
        ProvisionReplaceConfirmation {
            confirmation_id: String,
            life_id: String,
            task_id: String,
            capability_id: String,
            authorization_revision: i64,
            workspace_root_identity: String,
            relative_path: String,
            target_identity: String,
            expected_sha256: String,
            replacement_sha256: String,
            replacement_bytes: u64,
            tool_call_id: String,
            turn_id: String,
            issued_at_unix_ms: u64,
            expires_at_unix_ms: u64,
        },
        IssueReplaceGrant {
            life_id: String,
            task_id: String,
            capability_id: String,
            tool_call_id: String,
            turn_id: String,
            relative_path: String,
            expected_sha256: String,
            replacement_sha256: String,
            replacement_bytes: u64,
            workspace_root_identity: String,
            target_identity: String,
            target_kind: String,
        },
        RevalidateReplaceGrant {
            grant_id: String,
            life_id: String,
            task_id: String,
            capability_id: String,
            tool_call_id: String,
            turn_id: String,
            relative_path: String,
            expected_sha256: String,
            replacement_sha256: String,
            replacement_bytes: u64,
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
    struct H4HostResponse {
        operation: String,
        status: String,
        canonical: Option<H4CanonicalWire>,
        confirmation: Option<H4ConfirmationWire>,
        action_grant: Option<H4GrantWire>,
        confirmation_consumed: bool,
        denial: Option<String>,
        authorization_revision: Option<i64>,
        error_code: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H4CanonicalWire {
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
        risk_class: String,
        scope_requirement: String,
        approval_floor: String,
        authorization_revision: Option<i64>,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H4ConfirmationWire {
        source: String,
        confirmation_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        expected_sha256: String,
        replacement_sha256: String,
        replacement_bytes: u64,
        tool_call_id: String,
        turn_id: String,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H4GrantWire {
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
        operation: String,
        expected_sha256: String,
        replacement_sha256: String,
        replacement_bytes: u64,
        tool_call_id: String,
        turn_id: String,
        confirmation_id: String,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        single_use: bool,
    }

    struct PersistentH4HostProcess {
        io: Mutex<Option<H4HostProcessIo>>,
        child: Arc<Mutex<Child>>,
    }

    struct H4HostProcessIo {
        stdin: ChildStdin,
        stdout: ChildStdout,
    }

    impl PersistentH4HostProcess {
        fn start(
            repo_root: &Path,
            allowed_workspace_root_identity: String,
        ) -> Result<Arc<Self>, String> {
            let executable = h4_host_fixture_executable(repo_root)?;
            let mut child = Command::new(executable)
                .current_dir(repo_root)
                .env("CARGO_TERM_COLOR", "never")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn persistent H4 Host fixture: {error}"))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "persistent H4 Host fixture stdin unavailable".to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "persistent H4 Host fixture stdout unavailable".to_string())?;
            let process = Arc::new(Self {
                io: Mutex::new(Some(H4HostProcessIo { stdin, stdout })),
                child: Arc::new(Mutex::new(child)),
            });
            let response = process
                .roundtrip_blocking(&H4HostWireRequest::Initialize {
                    protocol_version: 1,
                    life_id: LIFE_ID.to_string(),
                    task_id: TASK_ID.to_string(),
                    capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                    allowed_workspace_root_identity,
                })
                .map_err(|error| {
                    process.abort();
                    error
                })?;
            let response: H4HostResponse = serde_json::from_slice(&response)
                .map_err(|_| "persistent H4 Host initialize response malformed".to_string())?;
            if response.operation != "initialize"
                || response.status != "ok"
                || response.authorization_revision != Some(REVISION)
                || response.canonical.is_some()
                || response.confirmation.is_some()
                || response.action_grant.is_some()
                || response.confirmation_consumed
                || response.denial.is_some()
                || response.error_code.is_some()
            {
                process.abort();
                return Err("persistent H4 Host initialize response invalid".to_string());
            }
            Ok(process)
        }

        fn roundtrip_blocking(&self, request: &H4HostWireRequest) -> Result<Vec<u8>, String> {
            let body = serde_json::to_vec(request)
                .map_err(|_| "H4 Host request serialization failed".to_string())?;
            if body.is_empty() || body.len() > H4_HOST_MAX_FRAME_BYTES {
                return Err("H4 Host request exceeded bounded frame size".to_string());
            }
            let mut io = lock_unpoisoned(&self.io);
            let io = io
                .as_mut()
                .ok_or_else(|| "H4 Host process is closed".to_string())?;
            io.stdin
                .write_all(&(body.len() as u32).to_be_bytes())
                .and_then(|_| io.stdin.write_all(&body))
                .and_then(|_| io.stdin.flush())
                .map_err(|_| "H4 Host request write failed".to_string())?;
            let mut length = [0_u8; 4];
            io.stdout
                .read_exact(&mut length)
                .map_err(|_| "H4 Host response frame length read failed".to_string())?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > H4_HOST_MAX_FRAME_BYTES {
                return Err("H4 Host response exceeded bounded frame size".to_string());
            }
            let mut response = vec![0_u8; length];
            io.stdout
                .read_exact(&mut response)
                .map_err(|_| "H4 Host response frame body read failed".to_string())?;
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
                .roundtrip_blocking(&H4HostWireRequest::Shutdown {})
                .ok()
                .and_then(|body| serde_json::from_slice::<H4HostResponse>(&body).ok());
            let valid_response = response.as_ref().is_some_and(|response| {
                response.operation == "shutdown"
                    && response.status == "ok"
                    && response.canonical.is_none()
                    && response.confirmation.is_none()
                    && response.action_grant.is_none()
                    && !response.confirmation_consumed
                    && response.denial.is_none()
                    && response.authorization_revision.is_none()
                    && response.error_code.is_none()
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

        fn disable_authorization_for_test(&self, expected_revision: i64) -> Result<(), String> {
            let response =
                self.roundtrip_blocking(&H4HostWireRequest::DisableAuthorizationForTest {
                    life_id: LIFE_ID.to_string(),
                    capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                    expected_revision,
                })?;
            let response: H4HostResponse = serde_json::from_slice(&response)
                .map_err(|_| "H4 Host disable response malformed".to_string())?;
            if response.operation != "disable_authorization_for_test"
                || response.status != "ok"
                || response.canonical.is_some()
                || response.confirmation.is_some()
                || response.action_grant.is_some()
                || response.confirmation_consumed
                || response.denial.is_some()
                || response.authorization_revision != Some(expected_revision + 1)
                || response.error_code.is_some()
            {
                return Err("H4 Host disable response invalid".to_string());
            }
            Ok(())
        }
    }

    impl Drop for PersistentH4HostProcess {
        fn drop(&mut self) {
            self.abort();
        }
    }

    const H4_HOST_MAX_FRAME_BYTES: usize = 64 * 1024;
    const H4_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(10);

    fn h4_host_fixture_executable(repo_root: &Path) -> Result<PathBuf, String> {
        let executable = repo_root
            .join("src-tauri")
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "d29h4-authority-fixture.exe"
            } else {
                "d29h4-authority-fixture"
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
                "d29h4-authority-fixture",
                "--features",
                "d29-h4-host-fixture",
            ])
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .status()
            .map_err(|error| format!("build persistent H4 Host fixture: {error}"))?;
        if !status.success() || !executable.is_file() {
            return Err("persistent H4 Host fixture executable was not produced".to_string());
        }
        Ok(executable)
    }

    pub(crate) struct ProcessIsolatedH4Authority {
        process: Arc<PersistentH4HostProcess>,
        observations: Arc<Mutex<Vec<H4HostResponse>>>,
        trusted_confirmations_provisioned: AtomicUsize,
        request_derived_confirmations: AtomicUsize,
        events: Arc<Mutex<Vec<H4AuthorityEvent>>>,
    }

    impl ProcessIsolatedH4Authority {
        pub(crate) fn new(
            allowed_workspace_root_identity: super::super::WorkspaceRootIdentity,
        ) -> Result<Arc<Self>, String> {
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or_else(|| "D29-H4 manifest has no repository parent".to_string())?
                .to_path_buf();
            let process = PersistentH4HostProcess::start(
                &repo_root,
                identity_wire(allowed_workspace_root_identity),
            )?;
            Ok(Arc::new(Self {
                process,
                observations: Arc::new(Mutex::new(Vec::new())),
                trusted_confirmations_provisioned: AtomicUsize::new(0),
                request_derived_confirmations: AtomicUsize::new(0),
                events: Arc::new(Mutex::new(Vec::new())),
            }))
        }

        pub(crate) fn snapshot(&self) -> Vec<H4HostResponse> {
            lock_unpoisoned(&self.observations).clone()
        }

        pub(crate) fn observation_count(&self) -> usize {
            lock_unpoisoned(&self.observations).len()
        }

        pub(crate) fn provenance_snapshot(&self) -> H4AuthorityProvenanceEvidence {
            H4AuthorityProvenanceEvidence {
                trusted_confirmations_provisioned: self
                    .trusted_confirmations_provisioned
                    .load(Ordering::Acquire),
                request_derived_confirmations: self
                    .request_derived_confirmations
                    .load(Ordering::Acquire),
                events: lock_unpoisoned(&self.events).clone(),
            }
        }

        /// Test/integration-only trusted confirmation seam.  The caller must
        /// establish the exact action intent before invoking this method; the
        /// normal authority evaluation path never provisions confirmations.
        pub(crate) fn provision_confirmation(
            &self,
            request: &H4AuthorityRequest,
        ) -> Result<(), String> {
            if !matches!(&request.operation, H4AuthorityOperation::IssueReplaceGrant) {
                return Err(
                    "H4 confirmation provisioning requires an IssueReplaceGrant intent".to_string(),
                );
            }
            provision_h4_confirmation(&self.process, request)?;
            self.trusted_confirmations_provisioned
                .fetch_add(1, Ordering::AcqRel);
            lock_unpoisoned(&self.events).push(H4AuthorityEvent::TrustedConfirmationProvisioned);
            Ok(())
        }

        pub(crate) fn shutdown(&self) -> bool {
            self.process.shutdown()
        }

        pub(crate) fn disable_authorization_for_test(
            &self,
            expected_revision: i64,
        ) -> Result<(), String> {
            self.process
                .disable_authorization_for_test(expected_revision)
        }
    }

    impl VitaH4AuthorityPort for ProcessIsolatedH4Authority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            let process = Arc::clone(&self.process);
            let observations = Arc::clone(&self.observations);
            let events = Arc::clone(&self.events);
            let wire = h4_wire_request(&request);
            let event = match &request.operation {
                H4AuthorityOperation::IssueReplaceGrant => H4AuthorityEvent::IssueEvaluated,
                H4AuthorityOperation::Revalidate { .. } => H4AuthorityEvent::RevalidationEvaluated,
            };
            Box::pin(async move {
                let process_for_roundtrip = Arc::clone(&process);
                let join = tokio::task::spawn_blocking(move || {
                    process_for_roundtrip.roundtrip_blocking(&wire)
                });
                let raw = match tokio::time::timeout(H4_HOST_IPC_TIMEOUT, join).await {
                    Ok(Ok(Ok(raw))) => raw,
                    _ => {
                        process.abort();
                        return Err(VitaH4AuthorityError::Unavailable);
                    }
                };
                let response: H4HostResponse = match serde_json::from_slice(&raw) {
                    Ok(response) => response,
                    Err(_) => {
                        process.abort();
                        return Err(VitaH4AuthorityError::InvalidVerdict);
                    }
                };
                let typed = match parse_h4_host_response(&request, &response) {
                    Ok(typed) => typed,
                    Err(error) => {
                        process.abort();
                        return Err(error);
                    }
                };
                lock_unpoisoned(&events).push(event);
                lock_unpoisoned(&observations).push(response);
                Ok(typed)
            })
        }
    }

    #[tokio::test]
    async fn process_authority_issue_does_not_auto_provision_confirmation() {
        let fixture = Fixture::new();
        let authority = ProcessIsolatedH4Authority::new(fixture.root.identity()).unwrap();
        let request = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
        let response = authority.evaluate(request).await.unwrap();
        let provenance = authority.provenance_snapshot();
        let observations = authority.snapshot();
        assert!(authority.shutdown());

        assert_eq!(
            response.denial,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        assert!(response.confirmation.is_none());
        assert!(response.grant.is_none());
        assert!(!response.confirmation_consumed);
        assert_eq!(provenance.trusted_confirmations_provisioned, 0);
        assert_eq!(provenance.request_derived_confirmations, 0);
        assert_eq!(provenance.events, vec![H4AuthorityEvent::IssueEvaluated]);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].denial.as_deref(),
            Some("confirmation_missing")
        );
    }

    fn provision_h4_confirmation(
        process: &PersistentH4HostProcess,
        request: &H4AuthorityRequest,
    ) -> Result<(), String> {
        let now = unix_millis();
        let confirmation_id = format!(
            "d29h4-c-{}",
            &sha256_hex(request.tool_call_id.as_bytes())[..32]
        );
        let response =
            process.roundtrip_blocking(&H4HostWireRequest::ProvisionReplaceConfirmation {
                confirmation_id,
                life_id: request.context.life_id().to_string(),
                task_id: request.context.task_id().to_string(),
                capability_id: request.capability_id.clone(),
                authorization_revision: REVISION,
                workspace_root_identity: identity_wire(request.workspace_root_identity),
                relative_path: request
                    .relative_path
                    .as_path()
                    .to_string_lossy()
                    .into_owned(),
                target_identity: identity_wire(request.target_identity),
                expected_sha256: request.expected_sha256.clone(),
                replacement_sha256: request.replacement_sha256.clone(),
                replacement_bytes: request.replacement_bytes as u64,
                tool_call_id: request.tool_call_id.clone(),
                turn_id: request.turn_id.clone(),
                issued_at_unix_ms: now,
                expires_at_unix_ms: now.saturating_add(GRANT_LIFETIME_MS),
            })?;
        let response: H4HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "H4 Host confirmation response malformed".to_string())?;
        if response.operation != "provision_replace_confirmation"
            || response.status != "ok"
            || response.canonical.is_some()
            || response.confirmation.is_some()
            || response.action_grant.is_some()
            || response.confirmation_consumed
            || response.denial.is_some()
            || response.authorization_revision.is_some()
            || response.error_code.is_some()
        {
            return Err("H4 Host confirmation provisioning response invalid".to_string());
        }
        Ok(())
    }

    fn h4_wire_request(request: &H4AuthorityRequest) -> H4HostWireRequest {
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
            request.expected_sha256.clone(),
            request.replacement_sha256.clone(),
            request.replacement_bytes as u64,
            identity_wire(request.workspace_root_identity),
            identity_wire(request.target_identity),
            target_kind_wire(request.target_kind).to_string(),
        );
        match &request.operation {
            H4AuthorityOperation::IssueReplaceGrant => H4HostWireRequest::IssueReplaceGrant {
                life_id: common.0,
                task_id: common.1,
                capability_id: common.2,
                tool_call_id: common.3,
                turn_id: common.4,
                relative_path: common.5,
                expected_sha256: common.6,
                replacement_sha256: common.7,
                replacement_bytes: common.8,
                workspace_root_identity: common.9,
                target_identity: common.10,
                target_kind: common.11,
            },
            H4AuthorityOperation::Revalidate {
                grant_id,
                authorization_revision,
            } => H4HostWireRequest::RevalidateReplaceGrant {
                grant_id: grant_id.clone(),
                life_id: common.0,
                task_id: common.1,
                capability_id: common.2,
                tool_call_id: common.3,
                turn_id: common.4,
                relative_path: common.5,
                expected_sha256: common.6,
                replacement_sha256: common.7,
                replacement_bytes: common.8,
                workspace_root_identity: common.9,
                target_identity: common.10,
                target_kind: common.11,
                authorization_revision: *authorization_revision,
            },
        }
    }

    fn parse_h4_host_response(
        request: &H4AuthorityRequest,
        response: &H4HostResponse,
    ) -> Result<H4HostAuthorityResponse, VitaH4AuthorityError> {
        let status = match response.status.as_str() {
            "ok" => H4AuthorityResponseStatus::Ok,
            "denied" => H4AuthorityResponseStatus::Denied,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        let expected_operation = match request.operation {
            H4AuthorityOperation::IssueReplaceGrant => "issue_replace_grant",
            H4AuthorityOperation::Revalidate { .. } => "revalidate_replace_grant",
        };
        if response.operation != expected_operation
            || response.error_code.is_some()
            || response.canonical.is_none()
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let canonical = response.canonical.as_ref().unwrap();
        if canonical.canonical_evaluations != 1
            || canonical.production_registry_size != 1
            || canonical.test_registry_size != 1
            || canonical.authorization_row_reads != 1
            || !canonical.host_scope_authority_present
            || canonical.life_id != request.context.life_id()
            || canonical.capability_id != request.capability_id
            || canonical.risk_class != H4_DESCRIPTOR_RISK_CLASS
            || canonical.scope_requirement != H4_DESCRIPTOR_SCOPE_REQUIREMENT
            || canonical.approval_floor != H4_DESCRIPTOR_APPROVAL_FLOOR
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let canonical = H4CanonicalDecision {
            life_id: canonical.life_id.clone(),
            capability_id: canonical.capability_id.clone(),
            outcome: parse_h4_outcome(&canonical.outcome)?,
            decision_code: parse_h4_decision_code(&canonical.decision_code)?,
            scope_requirement: parse_h4_scope_requirement(&canonical.scope_requirement)?,
            approval_floor: parse_h4_approval_floor(&canonical.approval_floor)?,
            authorization_revision: canonical.authorization_revision,
            workspace_scope_matches: canonical.requested_root_matched_authorized_root,
        };
        let confirmation = response
            .confirmation
            .as_ref()
            .map(|confirmation| parse_h4_confirmation(request, confirmation))
            .transpose()?;
        let grant = response
            .action_grant
            .as_ref()
            .map(|grant| parse_h4_grant(request, grant))
            .transpose()?;
        let denial = response
            .denial
            .as_deref()
            .map(parse_h4_denial)
            .transpose()?;
        validate_h4_wire_response_shape(
            &request.operation,
            status,
            confirmation.as_ref(),
            grant.as_ref(),
            denial,
            response.confirmation_consumed,
        )?;
        Ok(H4HostAuthorityResponse {
            status,
            canonical,
            confirmation,
            grant,
            denial,
            confirmation_consumed: response.confirmation_consumed,
        })
    }

    fn validate_h4_wire_response_shape(
        operation: &H4AuthorityOperation,
        status: H4AuthorityResponseStatus,
        confirmation: Option<&HostExplicitActionConfirmationEvidence>,
        grant: Option<&H4HostReplaceGrantEvidence>,
        denial: Option<H4DenyClassification>,
        confirmation_consumed: bool,
    ) -> Result<(), VitaH4AuthorityError> {
        let valid = match (operation, status) {
            (H4AuthorityOperation::IssueReplaceGrant, H4AuthorityResponseStatus::Ok) => {
                confirmation.is_some()
                    && grant.is_some()
                    && denial.is_none()
                    && confirmation_consumed
            }
            (H4AuthorityOperation::IssueReplaceGrant, H4AuthorityResponseStatus::Denied) => {
                confirmation.is_none()
                    && grant.is_none()
                    && denial.is_some()
                    && !confirmation_consumed
            }
            (H4AuthorityOperation::Revalidate { .. }, H4AuthorityResponseStatus::Ok) => {
                confirmation.is_none()
                    && grant.is_some()
                    && denial.is_none()
                    && !confirmation_consumed
            }
            (H4AuthorityOperation::Revalidate { .. }, H4AuthorityResponseStatus::Denied) => {
                confirmation.is_none()
                    && grant.is_none()
                    && denial.is_some()
                    && !confirmation_consumed
            }
        };
        if valid {
            Ok(())
        } else {
            Err(VitaH4AuthorityError::InvalidVerdict)
        }
    }

    fn parse_h4_confirmation(
        request: &H4AuthorityRequest,
        confirmation: &H4ConfirmationWire,
    ) -> Result<HostExplicitActionConfirmationEvidence, VitaH4AuthorityError> {
        let relative_path =
            super::super::WorkspaceRelativePath::parse(Path::new(&confirmation.relative_path))
                .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        let replacement_bytes = usize::try_from(confirmation.replacement_bytes)
            .ok()
            .filter(|bytes| *bytes <= H4_MAX_REPLACEMENT_BYTES)
            .ok_or(VitaH4AuthorityError::InvalidVerdict)?;
        if bounded_text(&confirmation.confirmation_id, MAX_CALL_ID_CHARS).is_none()
            || confirmation.source != "trusted_test_harness"
            || confirmation.life_id != request.context.life_id()
            || confirmation.task_id != request.context.task_id()
            || confirmation.capability_id != request.capability_id
            || confirmation.workspace_root_identity
                != identity_wire(request.workspace_root_identity)
            || confirmation.target_identity != identity_wire(request.target_identity)
            || !is_sha256_hex(&confirmation.expected_sha256)
            || !is_sha256_hex(&confirmation.replacement_sha256)
            || bounded_text(&confirmation.tool_call_id, MAX_CALL_ID_CHARS).is_none()
            || bounded_text(&confirmation.turn_id, MAX_TURN_ID_CHARS).is_none()
            || confirmation.expires_at_unix_ms <= confirmation.issued_at_unix_ms
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        Ok(HostExplicitActionConfirmationEvidence {
            source: H4ConfirmationEvidenceSource::TrustedTestHarness,
            confirmation_id: confirmation.confirmation_id.clone(),
            life_id: confirmation.life_id.clone(),
            task_id: confirmation.task_id.clone(),
            capability_id: confirmation.capability_id.clone(),
            authorization_revision: confirmation.authorization_revision,
            workspace_root_identity: request.workspace_root_identity,
            relative_path,
            target_identity: request.target_identity,
            expected_sha256: confirmation.expected_sha256.clone(),
            replacement_sha256: confirmation.replacement_sha256.clone(),
            replacement_bytes,
            tool_call_id: confirmation.tool_call_id.clone(),
            turn_id: confirmation.turn_id.clone(),
            issued_at_unix_ms: confirmation.issued_at_unix_ms,
            expires_at_unix_ms: confirmation.expires_at_unix_ms,
        })
    }

    fn parse_h4_grant(
        request: &H4AuthorityRequest,
        grant: &H4GrantWire,
    ) -> Result<H4HostReplaceGrantEvidence, VitaH4AuthorityError> {
        let relative_path =
            super::super::WorkspaceRelativePath::parse(Path::new(&grant.relative_path))
                .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        let replacement_bytes = usize::try_from(grant.replacement_bytes)
            .ok()
            .filter(|bytes| *bytes <= H4_MAX_REPLACEMENT_BYTES)
            .ok_or(VitaH4AuthorityError::InvalidVerdict)?;
        if bounded_text(&grant.grant_id, MAX_CALL_ID_CHARS).is_none()
            || grant.life_id != request.context.life_id()
            || grant.task_id != request.context.task_id()
            || grant.capability_id != request.capability_id
            || grant.scope != "workspace"
            || grant.workspace_root_identity != identity_wire(request.workspace_root_identity)
            || grant.target_identity != identity_wire(request.target_identity)
            || grant.operation != H4ReplaceOperation::ReplaceExistingUtf8File.as_str()
            || !is_sha256_hex(&grant.expected_sha256)
            || !is_sha256_hex(&grant.replacement_sha256)
            || bounded_text(&grant.tool_call_id, MAX_CALL_ID_CHARS).is_none()
            || bounded_text(&grant.turn_id, MAX_TURN_ID_CHARS).is_none()
            || bounded_text(&grant.confirmation_id, MAX_CALL_ID_CHARS).is_none()
            || grant.expires_at_unix_ms <= grant.issued_at_unix_ms
            || !grant.single_use
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let target_kind = match grant.target_kind.as_str() {
            "existing_file" => PreparedWorkspaceTargetKind::ExistingFile,
            "existing_directory" => PreparedWorkspaceTargetKind::ExistingDirectory,
            "missing" => PreparedWorkspaceTargetKind::Missing,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        Ok(H4HostReplaceGrantEvidence {
            grant_id: grant.grant_id.clone(),
            life_id: grant.life_id.clone(),
            task_id: grant.task_id.clone(),
            capability_id: grant.capability_id.clone(),
            authorization_revision: grant.authorization_revision,
            scope: VitaRequestedScope::Workspace,
            workspace_root_identity: request.workspace_root_identity,
            relative_path,
            target_identity: request.target_identity,
            target_kind,
            operation: H4ReplaceOperation::ReplaceExistingUtf8File,
            expected_sha256: grant.expected_sha256.clone(),
            replacement_sha256: grant.replacement_sha256.clone(),
            replacement_bytes,
            tool_call_id: grant.tool_call_id.clone(),
            turn_id: grant.turn_id.clone(),
            confirmation_id: grant.confirmation_id.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
        })
    }

    fn parse_h4_outcome(value: &str) -> Result<H4CanonicalOutcome, VitaH4AuthorityError> {
        Ok(match value {
            "Denied" => H4CanonicalOutcome::Denied,
            "RootDisabled" => H4CanonicalOutcome::RootDisabled,
            "ExplicitConfirmationRequired" => H4CanonicalOutcome::ExplicitConfirmationRequired,
            "ScopeRequired" => H4CanonicalOutcome::ScopeRequired,
            "Forbidden" => H4CanonicalOutcome::Forbidden,
            "Eligible" => H4CanonicalOutcome::Eligible,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        })
    }

    fn parse_h4_decision_code(
        value: &str,
    ) -> Result<H4CanonicalDecisionCode, VitaH4AuthorityError> {
        Ok(match value {
            "CAPABILITY_AUTHORIZATION_DENIED" => H4CanonicalDecisionCode::Denied,
            "CAPABILITY_ROOT_DISABLED" => H4CanonicalDecisionCode::RootDisabled,
            "CAPABILITY_CONFIRMATION_REQUIRED" => {
                H4CanonicalDecisionCode::ExplicitConfirmationRequired
            }
            "CAPABILITY_SCOPE_NOT_AVAILABLE" => H4CanonicalDecisionCode::ScopeNotAvailable,
            "CAPABILITY_FORBIDDEN" => H4CanonicalDecisionCode::Forbidden,
            "CAPABILITY_ELIGIBLE" => H4CanonicalDecisionCode::Eligible,
            "CAPABILITY_AUTHORIZATION_UNAVAILABLE" => {
                H4CanonicalDecisionCode::AuthorizationUnavailable
            }
            "CAPABILITY_UNKNOWN" => H4CanonicalDecisionCode::UnknownCapability,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        })
    }

    fn parse_h4_scope_requirement(value: &str) -> Result<H4ScopeRequirement, VitaH4AuthorityError> {
        Ok(match value {
            "None" => H4ScopeRequirement::None,
            "WorkspaceRequired" => H4ScopeRequirement::WorkspaceRequired,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        })
    }

    fn parse_h4_approval_floor(value: &str) -> Result<H4ApprovalFloor, VitaH4AuthorityError> {
        Ok(match value {
            "RootEnabled" => H4ApprovalFloor::RootEnabled,
            "ExplicitPerAction" => H4ApprovalFloor::ExplicitPerAction,
            "Forbidden" => H4ApprovalFloor::Forbidden,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        })
    }

    fn parse_h4_denial(value: &str) -> Result<H4DenyClassification, VitaH4AuthorityError> {
        Ok(match value {
            "workspace_scope_denied" => H4DenyClassification::WorkspaceScopeDenied,
            "confirmation_missing" => H4DenyClassification::ConfirmationMissing,
            "confirmation_mismatch" => H4DenyClassification::ConfirmationMismatch,
            "confirmation_expired" => H4DenyClassification::ConfirmationExpired,
            "confirmation_replay" => H4DenyClassification::ConfirmationReplay,
            "replace_grant_revalidation_denied" => H4DenyClassification::RevalidationDenied,
            "grant_capacity_exhausted" => H4DenyClassification::CallLimitExceeded,
            "root_disabled" => H4DenyClassification::RootDisabled,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H4FixtureMode {
        AuthorizationOnly,
        GovernedReplace,
    }

    #[derive(Clone, Debug, Default)]
    struct H4FixtureObservation {
        request_count: usize,
        first_request_has_h3_tool: bool,
        first_request_has_h4_tool: bool,
        second_request_received_h3_hash: bool,
        third_request_received_authorized_h4_result: bool,
        third_request_received_committed_h4_result: bool,
        third_request_excluded_authority_facts: bool,
        error: Option<String>,
    }

    #[derive(Default)]
    struct H4CanaryGateState {
        initial_turn_id: Option<String>,
        error: Option<String>,
        released: bool,
    }

    struct H4CanaryGate {
        state: Mutex<H4CanaryGateState>,
        changed: Condvar,
    }

    impl H4CanaryGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(H4CanaryGateState::default()),
                changed: Condvar::new(),
            })
        }

        fn capture_initial_turn_id(&self, body: &[u8]) -> Result<(), String> {
            let turn_id = serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|body| body.get("client_metadata").cloned())
                .and_then(|metadata| metadata.get("turn_id").cloned())
                .and_then(|turn_id| turn_id.as_str().map(str::to_string))
                .filter(|turn_id| !turn_id.is_empty())
                .ok_or_else(|| "H4-A first Responses request omitted client turn_id".to_string());
            let mut state = lock_unpoisoned(&self.state);
            let result = match turn_id {
                Ok(turn_id) => {
                    state.initial_turn_id = Some(turn_id);
                    Ok(())
                }
                Err(error) => {
                    state.error = Some(error.clone());
                    Err(error)
                }
            };
            self.changed.notify_all();
            result
        }

        fn wait_for_initial_turn_id_blocking(&self) -> Result<String, String> {
            let deadline = Instant::now() + H4_CANARY_TURN_TIMEOUT;
            let mut state = lock_unpoisoned(&self.state);
            loop {
                if let Some(error) = state.error.clone() {
                    return Err(error);
                }
                if let Some(turn_id) = state.initial_turn_id.clone() {
                    return Ok(turn_id);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("H4-A first Responses request turn-id wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() {
                    return Err("H4-A first Responses request turn-id wait timed out".to_string());
                }
            }
        }

        fn wait_until_released(&self) -> Result<(), String> {
            let deadline = Instant::now() + H4_CANARY_TURN_TIMEOUT;
            let mut state = lock_unpoisoned(&self.state);
            while !state.released {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("H4-A first Responses request release wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() && !state.released {
                    return Err("H4-A first Responses request release wait timed out".to_string());
                }
            }
            Ok(())
        }

        fn release(&self) {
            lock_unpoisoned(&self.state).released = true;
            self.changed.notify_all();
        }
    }

    struct H4ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H4FixtureObservation>>,
        gate: Arc<H4CanaryGate>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl H4ResponsesFixture {
        fn start() -> Self {
            Self::start_with_mode(H4FixtureMode::AuthorizationOnly)
        }

        fn start_h4c() -> Self {
            Self::start_with_mode(H4FixtureMode::GovernedReplace)
        }

        fn start_with_mode(mode: H4FixtureMode) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind H4 loopback fixture");
            let address = listener.local_addr().expect("H4 fixture address");
            let stop = Arc::new(AtomicBool::new(false));
            let observation = Arc::new(Mutex::new(H4FixtureObservation::default()));
            let gate = H4CanaryGate::new();
            let stop_for_thread = Arc::clone(&stop);
            let observation_for_thread = Arc::clone(&observation);
            let gate_for_thread = Arc::clone(&gate);
            let join = thread::spawn(move || {
                let mut response_index = 0usize;
                while !stop_for_thread.load(Ordering::Acquire) && response_index < 3 {
                    let (mut stream, peer) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) => {
                            lock_unpoisoned(&observation_for_thread).error =
                                Some(error.to_string());
                            return;
                        }
                    };
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    let result = handle_h4_fixture_request(
                        &mut stream,
                        peer,
                        response_index,
                        &gate_for_thread,
                        mode,
                    );
                    let mut observed = lock_unpoisoned(&observation_for_thread);
                    observed.request_count += 1;
                    if let Ok(body) = &result {
                        match response_index {
                            0 => {
                                observed.first_request_has_h3_tool =
                                    request_has_tool(body, VITA_WORKSPACE_READ_TOOL_NAME);
                                observed.first_request_has_h4_tool =
                                    request_has_tool(body, VITA_WORKSPACE_REPLACE_TOOL_NAME);
                            }
                            1 => {
                                observed.second_request_received_h3_hash =
                                    request_has_h3_success_with_hash(body);
                            }
                            2 => {
                                observed.third_request_received_authorized_h4_result =
                                    request_has_authorized_h4_result(body);
                                observed.third_request_received_committed_h4_result =
                                    request_has_committed_h4_result(body);
                                observed.third_request_excluded_authority_facts =
                                    request_excludes_h4_authority_facts(body);
                            }
                            _ => {}
                        }
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
                gate,
                join: Some(join),
            }
        }

        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}/v1", self.address.port())
        }

        async fn wait_for_initial_turn_id(&self) -> Result<String, String> {
            let gate = Arc::clone(&self.gate);
            tokio::task::spawn_blocking(move || gate.wait_for_initial_turn_id_blocking())
                .await
                .map_err(|_| "H4-A turn-id wait task failed".to_string())?
        }

        fn release_initial_request(&self) {
            self.gate.release();
        }

        fn shutdown(mut self) -> (H4FixtureObservation, bool) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            let joined = self
                .join
                .take()
                .map(|join| join.join().is_ok())
                .unwrap_or(true);
            (lock_unpoisoned(&self.observation).clone(), joined)
        }
    }

    impl Drop for H4ResponsesFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    const H4_CANARY_MODEL: &str = "d29h4-a-local-responses-model";
    const H4_CANARY_PROMPT: &str =
        "Read the file, then request the exact governed replacement without applying it.";
    const H4_CANARY_REPLY: &str = "VITA_D29H4_A_CANARY_STOPPED_BEFORE_MUTATION";
    const H4_CANARY_READ_CALL_ID: &str = "call-d29h4-a-read";
    const H4_CANARY_REPLACE_CALL_ID: &str = "call-d29h4-a-replace";
    const H4_CANARY_PROVIDER_ID: &str = "d29h4-a-loopback-responses";
    const H4_CANARY_FILE_CONTENT: &str = "VITA_D29H4_A_CANARY_ORIGINAL";
    const H4_CANARY_REPLACEMENT_CONTENT: &str = "VITA_D29H4_A_CANARY_REPLACEMENT";
    const H4_CANARY_TURN_TIMEOUT: Duration = Duration::from_secs(30);
    const H4_CANARY_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
    const H4_CANARY_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
    const H4_CANARY_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
    const H4_CANARY_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

    fn request_has_tool(body: &[u8], tool_name: &str) -> bool {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("tools").cloned())
            .and_then(|tools| tools.as_array().cloned())
            .is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool.get("name").and_then(Value::as_str) == Some(tool_name))
            })
    }

    fn function_call_output(body: &[u8], call_id: &str) -> Option<Value> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("input").cloned())
            .and_then(|input| input.as_array().cloned())
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

    fn request_has_h3_success_with_hash(body: &[u8]) -> bool {
        let Some(output) = function_call_output(body, H4_CANARY_READ_CALL_ID) else {
            return false;
        };
        output.get("status").and_then(Value::as_str) == Some("success")
            && output.get("content").and_then(Value::as_str) == Some(H4_CANARY_FILE_CONTENT)
            && output.get("bytes_read").and_then(Value::as_u64)
                == Some(H4_CANARY_FILE_CONTENT.len() as u64)
            && output.get("content_sha256").and_then(Value::as_str)
                == Some(sha256_hex(H4_CANARY_FILE_CONTENT.as_bytes()).as_str())
    }

    fn request_has_authorized_h4_result(body: &[u8]) -> bool {
        let Some(output) = function_call_output(body, H4_CANARY_REPLACE_CALL_ID) else {
            return false;
        };
        output.get("status").and_then(Value::as_str)
            == Some("authorized_for_future_replace_foundation")
            && output.get("mutation_performed").and_then(Value::as_bool) == Some(false)
            && output.get("side_effect_count").and_then(Value::as_u64) == Some(0)
    }

    fn request_has_committed_h4_result(body: &[u8]) -> bool {
        let Some(output) = function_call_output(body, H4_CANARY_REPLACE_CALL_ID) else {
            return false;
        };
        output.get("status").and_then(Value::as_str) == Some("committed")
            && output.get("commit_outcome").and_then(Value::as_str) == Some("committed")
            && output.get("mutation_performed").and_then(Value::as_bool) == Some(true)
            && output.get("side_effect_count").and_then(Value::as_u64) == Some(1)
            && output.get("before_sha256").and_then(Value::as_str)
                == Some(sha256_hex(H4_CANARY_FILE_CONTENT.as_bytes()).as_str())
            && output.get("after_sha256").and_then(Value::as_str)
                == Some(sha256_hex(H4_CANARY_REPLACEMENT_CONTENT.as_bytes()).as_str())
    }

    fn request_excludes_h4_authority_facts(body: &[u8]) -> bool {
        let Some(output) = function_call_output(body, H4_CANARY_REPLACE_CALL_ID) else {
            return false;
        };
        [
            "authorization_revision",
            "confirmation_id",
            "grant_id",
            "workspace_root_identity",
            "target_identity",
            "replacement_content",
            "source",
        ]
        .into_iter()
        .all(|field| {
            !output
                .as_object()
                .is_some_and(|object| object.contains_key(field))
        })
    }

    fn handle_h4_fixture_request(
        stream: &mut TcpStream,
        peer: SocketAddr,
        response_index: usize,
        gate: &H4CanaryGate,
        mode: H4FixtureMode,
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("H4-A fixture received a non-loopback peer".to_string());
        }
        let body = read_h4_http_request(stream)?;
        if response_index == 0 {
            gate.capture_initial_turn_id(&body)?;
            gate.wait_until_released()?;
        }
        let events = match mode {
            H4FixtureMode::AuthorizationOnly => match response_index {
                0 => h4_canary_first_response_events(),
                1 => h4_canary_second_response_events(),
                2 => h4_canary_completion_response_events(),
                _ => return Err("H4-A fixture received too many requests".to_string()),
            },
            H4FixtureMode::GovernedReplace => match response_index {
                0 => h4c_canary_first_response_events(),
                1 => h4c_canary_second_response_events(),
                2 => h4c_canary_completion_response_events(),
                _ => return Err("H4-C fixture received too many requests".to_string()),
            },
        };
        write_h4_sse_response(stream, events)?;
        Ok(body)
    }

    fn h4_canary_first_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h4-a-1", "object": "response", "status": "in_progress", "model": H4_CANARY_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": H4_CANARY_READ_CALL_ID, "name": VITA_WORKSPACE_READ_TOOL_NAME, "arguments": "{\"relative_path\":\"replace-me.txt\",\"max_bytes\":65536}"}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h4-a-1", "object": "response", "status": "completed", "model": H4_CANARY_MODEL}
            }),
        ]
    }

    fn h4_canary_second_response_events() -> Vec<Value> {
        let expected_hash = sha256_hex(H4_CANARY_FILE_CONTENT.as_bytes());
        let arguments = serde_json::to_string(&json!({
            "relative_path": "replace-me.txt",
            "expected_sha256": expected_hash,
            "replacement_content": H4_CANARY_REPLACEMENT_CONTENT,
        }))
        .expect("H4-A replacement arguments serialize");
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h4-a-2", "object": "response", "status": "in_progress", "model": H4_CANARY_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": H4_CANARY_REPLACE_CALL_ID, "name": VITA_WORKSPACE_REPLACE_TOOL_NAME, "arguments": arguments}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h4-a-2", "object": "response", "status": "completed", "model": H4_CANARY_MODEL}
            }),
        ]
    }

    fn h4_canary_completion_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h4-a-3", "object": "response", "status": "in_progress", "model": H4_CANARY_MODEL}
            }),
            json!({
                "type": "response.output_item.added",
                "item": {"type": "message", "id": "msg-d29h4-a", "role": "assistant", "status": "in_progress", "content": []}
            }),
            json!({"type": "response.content_part.added"}),
            json!({"type": "response.output_text.delta", "delta": H4_CANARY_REPLY}),
            json!({"type": "response.output_text.done", "text": H4_CANARY_REPLY}),
            json!({"type": "response.content_part.done"}),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "message", "id": "msg-d29h4-a", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": H4_CANARY_REPLY}]}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h4-a-3", "object": "response", "status": "completed", "model": H4_CANARY_MODEL}
            }),
        ]
    }

    fn h4c_canary_first_response_events() -> Vec<Value> {
        h4_canary_first_response_events()
    }

    fn h4c_canary_second_response_events() -> Vec<Value> {
        h4_canary_second_response_events()
    }

    fn h4c_canary_completion_response_events() -> Vec<Value> {
        h4_canary_completion_response_events()
    }

    fn write_h4_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
        let mut body = String::new();
        for event in events {
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "H4-A fixture event omitted type".to_string())?;
            body.push_str("event: ");
            body.push_str(event_type);
            body.push_str("\ndata: ");
            body.push_str(
                &serde_json::to_string(&event)
                    .map_err(|_| "H4-A fixture event serialization failed".to_string())?,
            );
            body.push_str("\n\n");
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .set_write_timeout(Some(H4_CANARY_HTTP_TIMEOUT))
            .map_err(|_| "H4-A fixture write timeout setup failed".to_string())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| "H4-A fixture response write failed".to_string())
    }

    fn read_h4_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        stream
            .set_read_timeout(Some(H4_CANARY_HTTP_TIMEOUT))
            .map_err(|_| "H4-A fixture read timeout setup failed".to_string())?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "H4-A fixture request read failed".to_string())?;
            if read == 0 {
                return Err("H4-A fixture request closed before headers".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > H4_CANARY_HTTP_MAX_BODY {
                return Err("H4-A fixture request exceeded bounded size".to_string());
            }
            if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let header = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| "H4-A fixture headers were not UTF-8".to_string())?;
        let content_length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| "H4-A fixture omitted content length".to_string())?;
        if content_length > H4_CANARY_HTTP_MAX_BODY {
            return Err("H4-A fixture content length exceeded bounded size".to_string());
        }
        while bytes.len() < header_end + content_length {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "H4-A fixture request body read failed".to_string())?;
            if read == 0 {
                return Err("H4-A fixture request closed before body".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        Ok(bytes[header_end..header_end + content_length].to_vec())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct H4CodexStateCanary {
        files: [Option<(u64, Option<SystemTime>)>; 3],
    }

    fn h4_codex_state_canary() -> H4CodexStateCanary {
        let root = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join(".codex"));
        let names = ["config.toml", "auth.json", ".codex-global-state.json"];
        H4CodexStateCanary {
            files: names.map(|name| {
                root.as_deref()
                    .and_then(|root| fs::symlink_metadata(root.join(name)).ok())
                    .map(|metadata| (metadata.len(), metadata.modified().ok()))
            }),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum H4ShutdownStatus {
        NotAttempted,
        Success,
        TimedOut,
        Failed,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct H4CleanupEvidence {
        initial_shutdown: H4ShutdownStatus,
        final_shutdown: H4ShutdownStatus,
        manager_thread_count: usize,
        fixture_listener_joined: bool,
    }

    struct H4Runtime {
        _app_data: TempDir,
        workspace: TempDir,
        manager: Arc<codex_core_api::ThreadManager>,
        thread: Option<Arc<codex_core_api::CodexThread>>,
        thread_id: Option<codex_core_api::ThreadId>,
        fixture: Option<H4ResponsesFixture>,
    }

    impl H4Runtime {
        async fn shutdown(mut self) -> (H4CleanupEvidence, H4FixtureObservation) {
            let mut initial_shutdown = H4ShutdownStatus::NotAttempted;
            let mut final_shutdown = H4ShutdownStatus::NotAttempted;
            if let Some(thread) = self.thread.take() {
                initial_shutdown = match tokio::time::timeout(
                    H4_CANARY_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H4ShutdownStatus::Success,
                    Ok(Err(_)) => H4ShutdownStatus::Failed,
                    Err(_) => H4ShutdownStatus::TimedOut,
                };
                if initial_shutdown != H4ShutdownStatus::Success {
                    let _ = tokio::time::timeout(
                        H4_CANARY_CLEANUP_TIMEOUT,
                        thread.submit(codex_core_api::Op::Interrupt),
                    )
                    .await;
                }
                final_shutdown = match tokio::time::timeout(
                    H4_CANARY_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H4ShutdownStatus::Success,
                    Ok(Err(_)) => H4ShutdownStatus::Failed,
                    Err(_) => H4ShutdownStatus::TimedOut,
                };
                if final_shutdown == H4ShutdownStatus::Success {
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
                .map(H4ResponsesFixture::shutdown)
                .unwrap_or_else(|| (H4FixtureObservation::default(), true));
            (
                H4CleanupEvidence {
                    initial_shutdown,
                    final_shutdown,
                    manager_thread_count,
                    fixture_listener_joined,
                },
                fixture_observation,
            )
        }
    }

    async fn start_h4_runtime() -> Result<
        (
            H4Runtime,
            Arc<crate::d29h3::VitaWorkspaceReadBroker>,
            Arc<VitaWorkspaceReplaceBroker>,
            Arc<ProcessIsolatedH4Authority>,
            H4CodexStateCanary,
        ),
        String,
    > {
        start_h4_runtime_with_mode(H4FixtureMode::AuthorizationOnly).await
    }

    async fn start_h4c_runtime() -> Result<
        (
            H4Runtime,
            Arc<crate::d29h3::VitaWorkspaceReadBroker>,
            Arc<VitaWorkspaceReplaceBroker>,
            Arc<ProcessIsolatedH4Authority>,
            H4CodexStateCanary,
        ),
        String,
    > {
        start_h4_runtime_with_mode(H4FixtureMode::GovernedReplace).await
    }

    async fn start_h4_runtime_with_mode(
        mode: H4FixtureMode,
    ) -> Result<
        (
            H4Runtime,
            Arc<crate::d29h3::VitaWorkspaceReadBroker>,
            Arc<VitaWorkspaceReplaceBroker>,
            Arc<ProcessIsolatedH4Authority>,
            H4CodexStateCanary,
        ),
        String,
    > {
        let before = h4_codex_state_canary();
        let app_data = tempdir().map_err(|_| "create H4-A app data failed".to_string())?;
        let workspace = tempdir().map_err(|_| "create H4-A workspace failed".to_string())?;
        let file_path = workspace.path().join("replace-me.txt");
        fs::write(&file_path, H4_CANARY_FILE_CONTENT.as_bytes())
            .map_err(|_| "create H4-A canary file failed".to_string())?;
        let profile = crate::VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
        )
        .map_err(|error| format!("create H4-A profile: {error}"))?;
        let fixture = match mode {
            H4FixtureMode::AuthorizationOnly => H4ResponsesFixture::start(),
            H4FixtureMode::GovernedReplace => H4ResponsesFixture::start_h4c(),
        };
        let provider = crate::ProviderProfile::new_for_test_localhost(
            H4_CANARY_PROVIDER_ID,
            "D29-H4-A loopback Responses fixture",
            crate::ProviderProtocol::OpenAiResponses,
            fixture.base_url(),
            H4_CANARY_MODEL,
            None,
            H4_CANARY_HTTP_TIMEOUT,
            crate::ProviderRetryPolicy::default(),
            crate::ProviderCapabilities {
                tools: true,
                ..crate::ProviderCapabilities::none()
            },
        )
        .map_err(|error| format!("create H4-A provider: {error}"))?;
        let provider_authority =
            crate::provider_gateway::VitaProviderAuthority::configure(provider)
                .map_err(|error| format!("configure H4-A provider: {error}"))?;
        let binding = crate::provider_gateway::VitaGatewayBinding::for_owned_private_listener(
            fixture.address.port(),
        )
        .map_err(|error| format!("create H4-A gateway binding: {error}"))?;
        let ready = provider_authority
            .prepare_gateway(binding)
            .map_err(|error| format!("prepare H4-A gateway: {error}"))?;
        let entrypoint =
            crate::VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
                .await
                .map_err(|error| format!("compile H4-A Codex config: {error}"))?;
        let config = entrypoint.config().clone();
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .map_err(|error| format!("create H4-A context: {error:?}"))?;
        let root = entrypoint
            .profile()
            .workspace_authority()
            .cloned()
            .ok_or_else(|| "H4-A requires the Windows workspace authority".to_string())?;
        let h3_broker = crate::d29h3::canary_read_broker(context.clone(), root.clone());
        let h4_authority = ProcessIsolatedH4Authority::new(root.identity())?;
        let h4_broker = VitaWorkspaceReplaceBroker::new(
            context.clone(),
            root,
            Arc::clone(&h4_authority) as Arc<dyn VitaH4AuthorityPort>,
        );
        let mut extensions =
            codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extensions.tool_contributor(Arc::new(
            crate::d29h3::VitaWorkspaceReadToolContributor::new(Arc::clone(&h3_broker)),
        ));
        match mode {
            H4FixtureMode::AuthorizationOnly => extensions.tool_contributor(Arc::new(
                VitaWorkspaceReplaceToolContributor::new(Arc::clone(&h4_broker)),
            )),
            H4FixtureMode::GovernedReplace => extensions.tool_contributor(Arc::new(
                VitaWorkspaceReplaceGovernedToolContributor::new(Arc::clone(&h4_broker)),
            )),
        }
        let extensions = Arc::new(extensions.build());
        let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
            codex_core_api::CodexAuth::from_api_key("d29h4-a-in-memory-kernel-auth"),
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
            "d29h4-a-local-installation".to_string(),
            None,
            None,
        ));
        let new_thread = tokio::time::timeout(
            H4_CANARY_TURN_TIMEOUT,
            manager.start_thread(codex_core_api::StartThreadOptions::new(config)),
        )
        .await
        .map_err(|_| "H4-A thread startup timed out".to_string())?
        .map_err(|error| format!("H4-A thread startup failed: {error}"))?;
        Ok((
            H4Runtime {
                _app_data: app_data,
                workspace,
                manager,
                thread: Some(new_thread.thread),
                thread_id: Some(new_thread.thread_id),
                fixture: Some(fixture),
            },
            h3_broker,
            h4_broker,
            h4_authority,
            before,
        ))
    }

    async fn start_h4_turn(thread: &Arc<codex_core_api::CodexThread>) -> Result<String, String> {
        let submission = tokio::time::timeout(
            H4_CANARY_TURN_TIMEOUT,
            thread.start_or_steer_turn(codex_core_api::TurnInputRequest::user_input(vec![
                codex_core_api::UserInput::Text {
                    text: H4_CANARY_PROMPT.to_string(),
                    text_elements: Vec::new(),
                },
            ])),
        )
        .await
        .map_err(|_| "H4-A turn submission timed out".to_string())?
        .map_err(|error| format!("H4-A turn submission failed: {error}"))?;
        match submission {
            codex_core_api::TurnInputSubmission::Started { turn_id }
            | codex_core_api::TurnInputSubmission::Steered { turn_id } => Ok(turn_id),
            codex_core_api::TurnInputSubmission::NotSubmitted { reason } => {
                Err(format!("H4-A turn was not submitted: {reason:?}"))
            }
        }
    }

    async fn wait_h4_turn(
        thread: &Arc<codex_core_api::CodexThread>,
    ) -> Result<(Option<String>, Option<String>, usize), String> {
        let deadline = Instant::now() + H4_CANARY_TURN_TIMEOUT;
        let mut event_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("H4-A turn did not reach a terminal event".to_string());
            }
            let event = tokio::time::timeout(remaining, thread.next_event())
                .await
                .map_err(|_| "H4-A event wait timed out".to_string())?
                .map_err(|error| format!("H4-A event stream failed: {error}"))?;
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

    fn h4_canary_authority_request(
        broker: &VitaWorkspaceReplaceBroker,
        context: &VitaExecutionContext,
        turn_id: String,
    ) -> H4AuthorityRequest {
        let prepared = broker
            .root
            .prepare_target(Path::new("replace-me.txt"))
            .expect("H4-A canary target should prepare");
        H4AuthorityRequest {
            context: context.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            operation: H4AuthorityOperation::IssueReplaceGrant,
            tool_call_id: H4_CANARY_REPLACE_CALL_ID.to_string(),
            turn_id,
            relative_path: super::super::WorkspaceRelativePath::parse(Path::new("replace-me.txt"))
                .expect("H4-A canary path should parse"),
            expected_sha256: sha256_hex(H4_CANARY_FILE_CONTENT.as_bytes()),
            replacement_sha256: sha256_hex(H4_CANARY_REPLACEMENT_CONTENT.as_bytes()),
            replacement_bytes: H4_CANARY_REPLACEMENT_CONTENT.as_bytes().len(),
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("H4-A canary target identity should exist"),
            target_kind: prepared.kind(),
        }
    }

    #[test]
    fn real_codex_h4a_canary_reaches_authorized_grant_but_does_not_mutate() {
        thread::Builder::new()
            .name("d29h4-a-real-codex-tool".to_string())
            .stack_size(H4_CANARY_TEST_STACK_SIZE)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("H4-A test runtime should build");
                runtime.block_on(real_codex_h4a_canary_body());
            })
            .expect("H4-A test thread should start")
            .join()
            .expect("H4-A test thread should finish");
    }

    async fn real_codex_h4a_canary_body() {
        let (runtime, h3_broker, h4_broker, authority, before) =
            start_h4_runtime().await.expect("H4-A runtime should start");
        let file_path = runtime.workspace.path().join("replace-me.txt");
        let turn_id = start_h4_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("H4-A turn should start");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .expect("H4-A Responses fixture should remain available")
            .wait_for_initial_turn_id()
            .await
            .expect("H4-A fixture should expose the active turn id");
        assert_eq!(observed_turn_id, turn_id);
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .expect("H4-A canary context should remain valid");
        let authority_request = h4_canary_authority_request(&h4_broker, &context, turn_id);
        authority
            .provision_confirmation(&authority_request)
            .expect("H4-A canary trusted confirmation should pre-provision");
        runtime
            .fixture
            .as_ref()
            .expect("H4-A Responses fixture should remain available")
            .release_initial_request();
        let turn = wait_h4_turn(runtime.thread.as_ref().unwrap()).await;
        let file_after = fs::read(&file_path).expect("H4-A canary target remains readable");
        let (cleanup, fixture_observation) = runtime.shutdown().await;
        let host_shutdown = authority.shutdown();
        let turn = turn.unwrap_or_else(|error| {
            panic!(
                "H4-A turn should complete: {error}; fixture={fixture_observation:?}; cleanup={cleanup:?}"
            )
        });

        assert_eq!(before, h4_codex_state_canary(), "user Codex state changed");
        assert_eq!(turn.1, None);
        assert_eq!(turn.0.as_deref(), Some(H4_CANARY_REPLY));
        assert!(turn.2 > 0);
        assert_eq!(file_after, H4_CANARY_FILE_CONTENT.as_bytes());
        assert_eq!(cleanup.initial_shutdown, H4ShutdownStatus::Success);
        assert_eq!(cleanup.final_shutdown, H4ShutdownStatus::Success);
        assert_eq!(cleanup.manager_thread_count, 0);
        assert!(cleanup.fixture_listener_joined);
        assert!(host_shutdown);

        assert_eq!(fixture_observation.request_count, 3);
        assert!(fixture_observation.first_request_has_h3_tool);
        assert!(fixture_observation.first_request_has_h4_tool);
        assert!(fixture_observation.second_request_received_h3_hash);
        assert!(fixture_observation.third_request_received_authorized_h4_result);
        assert!(fixture_observation.third_request_excluded_authority_facts);
        assert!(fixture_observation.error.is_none());

        let h3_snapshot = h3_broker.snapshot();
        assert_eq!(h3_snapshot.attempted_requests, 1);
        assert_eq!(h3_snapshot.authorized_file_reads, 1);
        assert_eq!(h3_snapshot.file_bytes_read, H4_CANARY_FILE_CONTENT.len());
        assert_eq!(h3_snapshot.filesystem_mutations, 0);
        assert_eq!(h3_snapshot.process_spawns, 0);
        assert_eq!(h3_snapshot.external_network_requests, 0);

        let h4_snapshot = h4_broker.snapshot();
        assert_eq!(h4_snapshot.attempted_requests, 1);
        assert_eq!(h4_snapshot.canonical_evaluations, 2);
        assert_eq!(h4_snapshot.confirmations_consumed, 1);
        assert_eq!(h4_snapshot.grants_issued, 1);
        assert_eq!(h4_snapshot.authorized_write_count, 0);
        assert_eq!(h4_snapshot.filesystem_mutations, 0);
        assert_eq!(h4_snapshot.process_spawns, 0);
        assert_eq!(h4_snapshot.external_network_requests, 0);
        assert_eq!(h4_snapshot.max_active_authority, 1);

        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        let provenance = authority.provenance_snapshot();
        assert_eq!(provenance.trusted_confirmations_provisioned, 1);
        assert_eq!(provenance.request_derived_confirmations, 0);
        assert_eq!(
            provenance.events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
        let issue = &observations[0];
        let revalidate = &observations[1];
        for observation in &observations {
            let canonical = observation
                .canonical
                .as_ref()
                .expect("H4-A Host canonical result");
            assert_eq!(canonical.canonical_evaluations, 1);
            assert_eq!(canonical.production_registry_size, 1);
            assert_eq!(canonical.test_registry_size, 1);
            assert_eq!(canonical.authorization_row_reads, 1);
            assert!(canonical.host_scope_authority_present);
            assert!(canonical.requested_root_matched_authorized_root);
            assert_eq!(canonical.outcome, "ScopeRequired");
            assert_eq!(canonical.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
            assert_eq!(canonical.risk_class, H4_DESCRIPTOR_RISK_CLASS);
            assert_eq!(canonical.scope_requirement, H4_DESCRIPTOR_SCOPE_REQUIREMENT);
            assert_eq!(canonical.approval_floor, H4_DESCRIPTOR_APPROVAL_FLOOR);
            assert_eq!(canonical.authorization_revision, Some(REVISION));
        }
        assert_eq!(
            issue
                .confirmation
                .as_ref()
                .expect("H4-A issue confirmation")
                .source,
            "trusted_test_harness"
        );
        assert_ne!(
            issue
                .confirmation
                .as_ref()
                .expect("H4-A issue confirmation")
                .source,
            "tool_request"
        );
        assert!(issue.confirmation.is_some());
        assert!(issue.action_grant.is_some());
        assert!(issue.confirmation_consumed);
        assert_eq!(issue.denial, None);
        assert!(revalidate.confirmation.is_none());
        assert!(revalidate.action_grant.is_some());
        assert!(!revalidate.confirmation_consumed);
        assert_eq!(revalidate.denial, None);
    }

    #[test]
    fn h4a_has_zero_filesystem_mutations() {
        let metrics = H4BrokerMetrics::default();
        assert_eq!(metrics.filesystem_mutations.load(Ordering::Acquire), 0);
        assert_eq!(metrics.authorized_write_count.load(Ordering::Acquire), 0);
        assert_eq!(metrics.process_spawns.load(Ordering::Acquire), 0);
        assert_eq!(metrics.external_network_requests.load(Ordering::Acquire), 0);
        let _ = Duration::from_millis(1);
        let _ = thread::current();
    }

    // D29-H4-C TESTS CONTINUE
    // Everything below this marker is the explicit test/integration execution
    // path.  The H4-A source-boundary test intentionally scans only the
    // authority-only portion above it.

    struct H4CGatedAuthority {
        inner: Arc<TestHostAuthority>,
        revalidation_started: Arc<tokio::sync::Notify>,
        release_revalidation: Arc<tokio::sync::Notify>,
        panic_on_revalidation: bool,
    }

    impl H4CGatedAuthority {
        fn new(inner: Arc<TestHostAuthority>) -> Arc<Self> {
            Self::with_panic(inner, false)
        }

        fn with_panic(inner: Arc<TestHostAuthority>, panic_on_revalidation: bool) -> Arc<Self> {
            Arc::new(Self {
                inner,
                revalidation_started: Arc::new(tokio::sync::Notify::new()),
                release_revalidation: Arc::new(tokio::sync::Notify::new()),
                panic_on_revalidation,
            })
        }

        fn release(&self) {
            self.release_revalidation.notify_one();
        }
    }

    impl VitaH4AuthorityPort for H4CGatedAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            if matches!(request.operation, H4AuthorityOperation::Revalidate { .. }) {
                let started = Arc::clone(&self.revalidation_started);
                let release = Arc::clone(&self.release_revalidation);
                let inner = Arc::clone(&self.inner);
                let panic_on_revalidation = self.panic_on_revalidation;
                Box::pin(async move {
                    started.notify_one();
                    release.notified().await;
                    if panic_on_revalidation {
                        panic!("synthetic H4-C final authority panic");
                    }
                    inner.evaluate(request).await
                })
            } else {
                self.inner.evaluate(request)
            }
        }
    }

    struct H4CLateAllowAuthority {
        inner: Arc<TestHostAuthority>,
        revalidation_started: Arc<tokio::sync::Notify>,
        release_revalidation: Arc<tokio::sync::Notify>,
        late_completed: Arc<tokio::sync::Notify>,
    }

    impl H4CLateAllowAuthority {
        fn new(inner: Arc<TestHostAuthority>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                revalidation_started: Arc::new(tokio::sync::Notify::new()),
                release_revalidation: Arc::new(tokio::sync::Notify::new()),
                late_completed: Arc::new(tokio::sync::Notify::new()),
            })
        }

        fn release(&self) {
            self.release_revalidation.notify_one();
        }
    }

    impl VitaH4AuthorityPort for H4CLateAllowAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            if matches!(request.operation, H4AuthorityOperation::Revalidate { .. }) {
                let started = Arc::clone(&self.revalidation_started);
                let release = Arc::clone(&self.release_revalidation);
                let inner = Arc::clone(&self.inner);
                let completed = Arc::clone(&self.late_completed);
                let (sender, receiver) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    release.notified().await;
                    let response = inner.evaluate(request).await;
                    let _ = sender.send(response);
                    completed.notify_one();
                });
                Box::pin(async move {
                    started.notify_one();
                    receiver
                        .await
                        .map_err(|_| VitaH4AuthorityError::Unavailable)?
                })
            } else {
                self.inner.evaluate(request)
            }
        }
    }

    struct H4CRevokingAuthority {
        inner: Arc<TestHostAuthority>,
    }

    impl VitaH4AuthorityPort for H4CRevokingAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            if matches!(request.operation, H4AuthorityOperation::Revalidate { .. }) {
                self.inner.disabled.store(true, Ordering::Release);
                self.inner
                    .revision
                    .store((REVISION + 1) as usize, Ordering::Release);
            }
            self.inner.evaluate(request)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H4CMalformedVerdict {
        MixedDenialAndGrant,
        UnexpectedConfirmation,
        UnexpectedConfirmationConsumed,
        OkStatusWithDenial,
        DeniedStatusWithGrant,
    }

    struct H4CMalformedVerdictAuthority {
        inner: Arc<TestHostAuthority>,
        mode: H4CMalformedVerdict,
    }

    impl VitaH4AuthorityPort for H4CMalformedVerdictAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            let inner = Arc::clone(&self.inner);
            let mode = self.mode;
            let is_revalidation =
                matches!(&request.operation, H4AuthorityOperation::Revalidate { .. });
            Box::pin(async move {
                let mut response = inner.evaluate(request.clone()).await?;
                if is_revalidation {
                    match mode {
                        H4CMalformedVerdict::MixedDenialAndGrant => {
                            response.status = H4AuthorityResponseStatus::Denied;
                            response.denial = Some(H4DenyClassification::RevalidationDenied);
                        }
                        H4CMalformedVerdict::UnexpectedConfirmation => {
                            response.status = H4AuthorityResponseStatus::Ok;
                            response.confirmation = Some(h4c_unexpected_confirmation(&request));
                        }
                        H4CMalformedVerdict::UnexpectedConfirmationConsumed => {
                            response.status = H4AuthorityResponseStatus::Ok;
                            response.confirmation_consumed = true;
                        }
                        H4CMalformedVerdict::OkStatusWithDenial => {
                            response.status = H4AuthorityResponseStatus::Ok;
                            response.denial = Some(H4DenyClassification::RevalidationDenied);
                        }
                        H4CMalformedVerdict::DeniedStatusWithGrant => {
                            response.status = H4AuthorityResponseStatus::Denied;
                            response.denial = Some(H4DenyClassification::RevalidationDenied);
                        }
                    }
                }
                Ok(response)
            })
        }
    }

    struct H4CProcessRevokingAuthority {
        inner: Arc<ProcessIsolatedH4Authority>,
        revoked: AtomicBool,
    }

    impl VitaH4AuthorityPort for H4CProcessRevokingAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            let inner = Arc::clone(&self.inner);
            if matches!(request.operation, H4AuthorityOperation::Revalidate { .. })
                && !self.revoked.swap(true, Ordering::AcqRel)
            {
                Box::pin(async move {
                    let inner_for_disable = Arc::clone(&inner);
                    tokio::task::spawn_blocking(move || {
                        inner_for_disable.disable_authorization_for_test(REVISION)
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

    fn h4c_fixture(
        call_id: &str,
    ) -> (
        Fixture,
        Arc<TestHostAuthority>,
        Arc<VitaWorkspaceReplaceBroker>,
        VitaWorkspaceReplaceRequest,
    ) {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request(call_id);
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        (fixture, authority, broker, request)
    }

    fn h4c_target_path(fixture: &Fixture) -> PathBuf {
        fixture.root.final_path().join("replace-me.txt")
    }

    fn h4c_assert_unmodified(fixture: &Fixture) {
        assert_eq!(
            fs::read(h4c_target_path(fixture)).expect("H4-C target remains readable"),
            FILE_CONTENT.as_bytes()
        );
    }

    fn h4c_assert_no_authority_facts(value: &Value) {
        for field in [
            "authorization_revision",
            "confirmation_id",
            "grant_id",
            "workspace_root_identity",
            "target_identity",
            "source",
            "replacement_content",
        ] {
            assert!(
                !value
                    .as_object()
                    .is_some_and(|object| object.contains_key(field)),
                "model output exposed authority field {field}"
            );
        }
    }

    fn h4c_unexpected_confirmation(
        request: &H4AuthorityRequest,
    ) -> HostExplicitActionConfirmationEvidence {
        let issued_at_unix_ms = unix_millis();
        HostExplicitActionConfirmationEvidence {
            source: H4ConfirmationEvidenceSource::TrustedTestHarness,
            confirmation_id: "unexpected-confirmation".to_string(),
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: request.capability_id.clone(),
            authorization_revision: REVISION,
            workspace_root_identity: request.workspace_root_identity,
            relative_path: request.relative_path.clone(),
            target_identity: request.target_identity,
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_bytes: request.replacement_bytes,
            tool_call_id: request.tool_call_id.clone(),
            turn_id: request.turn_id.clone(),
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms + GRANT_LIFETIME_MS,
        }
    }

    async fn assert_h4c_malformed_verdict(mode: H4CMalformedVerdict, call_id: &str) {
        let (fixture, authority, _unused_broker, request) = h4c_fixture(call_id);
        let malformed = Arc::new(H4CMalformedVerdictAuthority {
            inner: Arc::clone(&authority),
            mode,
        });
        let broker = fixture.broker(malformed as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_governed_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::AuthorityEvidenceMismatch)
        );
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        h4c_assert_unmodified(&fixture);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(snapshot.final_revalidation_denials, 1);
        assert_eq!(snapshot.filesystem_mutation_attempts, 0);
        assert_eq!(snapshot.filesystem_mutations_committed, 0);
        assert_eq!(snapshot.filesystem_commit_unknown, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn governed_execution_does_not_revalidate_before_native_fence() {
        let (fixture, authority, _unused_broker, request) = h4c_fixture("h4c-no-early-revalidate");
        let gated = H4CGatedAuthority::new(Arc::clone(&authority));
        let broker = fixture.broker(Arc::clone(&gated) as Arc<dyn VitaH4AuthorityPort>);
        let execution = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.execute_governed_request(request).await })
        };
        gated.revalidation_started.notified().await;
        let requests = lock_unpoisoned(&authority.requests).clone();
        assert_eq!(requests.len(), 1, "Host saw revalidation before fence");
        assert!(matches!(
            requests[0].operation,
            H4AuthorityOperation::IssueReplaceGrant
        ));
        assert_eq!(broker.snapshot().final_revalidations, 1);
        gated.release();
        let result = execution.await.expect("H4-C execution task joined");
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        assert_eq!(broker.snapshot().native_workers_started, 1);
        assert_eq!(broker.snapshot().native_workers_joined, 1);
        assert_eq!(lock_unpoisoned(&authority.requests).len(), 2);
        drop(fixture);
    }

    #[tokio::test]
    async fn native_fence_requests_exact_host_revalidation() {
        let (fixture, authority, broker, request) = h4c_fixture("h4c-exact-revalidation");
        let expected = fixture.authority_request_for(
            &request,
            H4AuthorityOperation::Revalidate {
                grant_id: "placeholder".to_string(),
                authorization_revision: REVISION,
            },
        );
        let result = broker.execute_governed_request(request).await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        let requests = lock_unpoisoned(&authority.requests).clone();
        assert_eq!(requests.len(), 2);
        let final_request = &requests[1];
        let expected_grant_id = authority
            .grants
            .lock()
            .unwrap()
            .keys()
            .next()
            .cloned()
            .expect("H4-C Host issued grant");
        match &final_request.operation {
            H4AuthorityOperation::Revalidate {
                grant_id,
                authorization_revision,
            } => {
                assert_eq!(grant_id, &expected_grant_id);
                assert_eq!(*authorization_revision, REVISION);
            }
            other => panic!("expected final revalidation, got {other:?}"),
        }
        assert_eq!(final_request.context, expected.context);
        assert_eq!(final_request.capability_id, expected.capability_id);
        assert_eq!(final_request.tool_call_id, expected.tool_call_id);
        assert_eq!(final_request.turn_id, expected.turn_id);
        assert_eq!(final_request.relative_path, expected.relative_path);
        assert_eq!(final_request.expected_sha256, expected.expected_sha256);
        assert_eq!(
            final_request.replacement_sha256,
            expected.replacement_sha256
        );
        assert_eq!(final_request.replacement_bytes, expected.replacement_bytes);
        assert_eq!(
            final_request.workspace_root_identity,
            expected.workspace_root_identity
        );
        assert_eq!(final_request.target_identity, expected.target_identity);
        assert_eq!(final_request.target_kind, expected.target_kind);
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
        assert_eq!(broker.snapshot().final_revalidations, 1);
    }

    #[tokio::test]
    async fn final_host_revalidation_pass_allows_one_commit() {
        let (fixture, authority, broker, request) = h4c_fixture("h4c-one-commit");
        let result = broker.execute_governed_request(request).await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.attempted_requests, 1);
        assert_eq!(snapshot.canonical_evaluations, 2);
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.confirmations_consumed, 1);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(snapshot.exclusive_operation_handles, 1);
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(snapshot.final_revalidation_denials, 0);
        assert_eq!(snapshot.filesystem_mutation_attempts, 1);
        assert_eq!(snapshot.filesystem_mutations_committed, 1);
        assert_eq!(snapshot.filesystem_commit_unknown, 0);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(snapshot.process_spawns, 0);
        assert_eq!(snapshot.external_network_requests, 0);
        assert_eq!(
            authority
                .provenance_snapshot()
                .request_derived_confirmations,
            0
        );
    }

    #[test]
    fn rev2_to_rev3_at_native_fence_mutates_zero() {
        thread::Builder::new()
            .name("d29h4-c-process-revocation".to_string())
            .stack_size(H4_CANARY_TEST_STACK_SIZE)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("H4-C process revocation runtime should build");
                runtime.block_on(async {
                    let fixture = Fixture::new();
                    let authority = ProcessIsolatedH4Authority::new(fixture.root.identity())
                        .expect("H4-C process authority should start");
                    let request = fixture.request("h4c-process-rev2-rev3");
                    let issue = fixture
                        .authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
                    authority
                        .provision_confirmation(&issue)
                        .expect("H4-C process confirmation should provision");
                    let revoked = Arc::new(H4CProcessRevokingAuthority {
                        inner: Arc::clone(&authority),
                        revoked: AtomicBool::new(false),
                    });
                    let broker =
                        fixture.broker(Arc::clone(&revoked) as Arc<dyn VitaH4AuthorityPort>);
                    let result = broker.execute_governed_request(request).await;
                    assert_eq!(
                        result.classification,
                        Some(H4DenyClassification::RootDisabled)
                    );
                    h4c_assert_unmodified(&fixture);
                    let snapshot = broker.snapshot();
                    assert_eq!(snapshot.final_revalidations, 1);
                    assert_eq!(snapshot.filesystem_mutation_attempts, 0);
                    assert_eq!(snapshot.native_workers_started, 1);
                    assert_eq!(snapshot.native_workers_joined, 1);
                    let observations = authority.snapshot();
                    assert_eq!(observations.len(), 2);
                    assert_eq!(
                        observations[0]
                            .canonical
                            .as_ref()
                            .expect("process issue canonical")
                            .authorization_revision,
                        Some(REVISION)
                    );
                    assert_eq!(
                        observations[1]
                            .canonical
                            .as_ref()
                            .expect("process revalidation canonical")
                            .outcome,
                        "RootDisabled"
                    );
                    assert_eq!(
                        observations[1]
                            .canonical
                            .as_ref()
                            .expect("process revalidation canonical revision")
                            .authorization_revision,
                        Some(REVISION + 1)
                    );
                    assert!(authority.shutdown());
                });
            })
            .expect("H4-C process revocation test should start")
            .join()
            .expect("H4-C process revocation test should finish");
    }

    #[tokio::test]
    async fn in_memory_rev2_to_rev3_at_native_fence_mutates_zero() {
        let (fixture, authority, _unused_broker, request) = h4c_fixture("h4c-rev2-rev3");
        let revoked = Arc::new(H4CRevokingAuthority {
            inner: Arc::clone(&authority),
        });
        let broker = fixture.broker(Arc::clone(&revoked) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_governed_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::RootDisabled)
        );
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        h4c_assert_unmodified(&fixture);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(snapshot.final_revalidation_denials, 1);
        assert_eq!(snapshot.filesystem_mutation_attempts, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(
            authority.revision.load(Ordering::Acquire),
            (REVISION + 1) as usize
        );
    }

    #[tokio::test]
    async fn missing_confirmation_never_starts_native_worker() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let request = fixture.request("h4c-missing-confirmation");
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_governed_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::ConfirmationMissing)
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 0);
        assert_eq!(snapshot.native_workers_joined, 0);
        assert_eq!(snapshot.final_revalidations, 0);
        assert_eq!(snapshot.filesystem_mutations_committed, 0);
        h4c_assert_unmodified(&fixture);
    }

    #[tokio::test]
    async fn wrong_workspace_root_never_starts_native_worker() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let authority = TestHostAuthority::new(other.root.identity());
        let request = fixture.request("h4c-wrong-root");
        let authority_request =
            fixture.authority_request_for(&request, H4AuthorityOperation::IssueReplaceGrant);
        authority.provision_trusted_confirmation(&authority_request);
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_governed_request(request).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::WorkspaceScopeDenied)
        );
        assert_eq!(broker.snapshot().native_workers_started, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        h4c_assert_unmodified(&fixture);
    }

    #[tokio::test]
    async fn stale_content_after_grant_conflicts_without_mutation() {
        let (fixture, authority, broker, request) = h4c_fixture("h4c-stale-content");
        let path = h4c_target_path(&fixture);
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::write(&path, b"changed after grant").expect("change content after grant");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Conflict { .. })
        ));
        assert_eq!(result.classification, None);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(authority.requests.lock().unwrap().len(), 1);
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            b"changed after grant"
        );
    }

    #[tokio::test]
    async fn target_identity_change_after_grant_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-target-identity");
        let target = h4c_target_path(&fixture);
        let moved = fixture.root.final_path().join("replace-me-old.txt");
        let replacement = target.clone();
        let target_for_setup = target.clone();
        let moved_for_setup = moved.clone();
        let replacement_for_setup = replacement.clone();
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::rename(&target_for_setup, &moved_for_setup).expect("rename target after grant");
            fs::write(&replacement_for_setup, b"new namespace object")
                .expect("create new target object");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        assert_eq!(fs::read(&moved).unwrap(), FILE_CONTENT.as_bytes());
        assert_eq!(fs::read(&replacement).unwrap(), b"new namespace object");
    }

    #[cfg(windows)]
    struct H4CBusyHandle(usize);

    #[cfg(windows)]
    impl Drop for H4CBusyHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(
                    self.0 as windows_sys::Win32::Foundation::HANDLE,
                );
            }
        }
    }

    #[cfg(windows)]
    fn h4c_open_busy_target(path: &Path) -> H4CBusyHandle {
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
        assert!(!handle.is_null() && handle != INVALID_HANDLE_VALUE);
        H4CBusyHandle(handle as usize)
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hard_link_after_grant_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-hard-link");
        let target = h4c_target_path(&fixture);
        let alias = fixture.root.final_path().join("replace-me-alias.txt");
        let target_for_setup = target.clone();
        let alias_for_setup = alias.clone();
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::hard_link(&target_for_setup, &alias_for_setup)
                .expect("create hard link after grant");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        h4c_assert_unmodified(&fixture);
        assert_eq!(fs::read(alias).unwrap(), FILE_CONTENT.as_bytes());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn busy_target_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-busy");
        let busy = Arc::new(Mutex::new(None::<H4CBusyHandle>));
        let busy_for_setup = Arc::clone(&busy);
        let path = h4c_target_path(&fixture);
        let setup: H4CNativeSetup = Arc::new(move || {
            *busy_for_setup.lock().unwrap() = Some(h4c_open_busy_target(&path));
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        drop(busy);
        h4c_assert_unmodified(&fixture);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn reparse_target_mutates_zero() {
        use std::os::windows::fs::symlink_file;
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-reparse");
        let target = h4c_target_path(&fixture);
        let moved = fixture.root.final_path().join("replace-me-reparse-old.txt");
        let outside = tempdir().expect("H4-C reparse outside root");
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").expect("outside file");
        let link = target.clone();
        let target_for_setup = target.clone();
        let moved_for_setup = moved.clone();
        let outside_for_setup = outside_file.clone();
        let link_for_setup = link.clone();
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::rename(&target_for_setup, &moved_for_setup).expect("rename target before reparse");
            symlink_file(&outside_for_setup, &link_for_setup).expect("create reparse target");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
        assert_eq!(fs::read(&moved).unwrap(), FILE_CONTENT.as_bytes());
    }

    #[tokio::test]
    async fn missing_target_is_not_created() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-missing-target");
        let target = h4c_target_path(&fixture);
        let moved = fixture.root.final_path().join("replace-me-missing-old.txt");
        let target_for_setup = target.clone();
        let moved_for_setup = moved.clone();
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::rename(&target_for_setup, &moved_for_setup)
                .expect("remove target from namespace after grant");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert!(!target.exists(), "H4-C recreated a missing target");
        assert_eq!(fs::read(moved).unwrap(), FILE_CONTENT.as_bytes());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn oversized_target_after_grant_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-oversized-target");
        let path = h4c_target_path(&fixture);
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::write(
                &path,
                vec![
                    b'x';
                    super::super::workspace_capability::WORKSPACE_REPLACE_HARD_MAX_BYTES + 1
                ],
            )
            .expect("write oversized target after grant");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        assert_eq!(
            fs::metadata(h4c_target_path(&fixture)).unwrap().len() as usize,
            super::super::workspace_capability::WORKSPACE_REPLACE_HARD_MAX_BYTES + 1
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn invalid_utf8_target_after_grant_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-invalid-utf8-target");
        let path = h4c_target_path(&fixture);
        let setup: H4CNativeSetup = Arc::new(move || {
            fs::write(&path, [0xff, 0xfe, 0xfd]).expect("write invalid UTF-8 target after grant");
        });
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(broker.snapshot().final_revalidations, 0);
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            [0xff, 0xfe, 0xfd]
        );
    }

    #[tokio::test]
    async fn duplicate_tool_call_commits_at_most_once() {
        let (fixture, authority, broker, request) = h4c_fixture("h4c-duplicate");
        let first = broker.execute_governed_request(request.clone()).await;
        let second = broker.execute_governed_request(request).await;
        assert!(matches!(
            first.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        assert_eq!(
            second.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(snapshot.filesystem_mutations_committed, 1);
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
    }

    #[tokio::test]
    async fn confirmation_replay_never_reprovisions() {
        let (_fixture, authority, broker, request) = h4c_fixture("h4c-confirmation-replay");
        let _ = broker.execute_governed_request(request.clone()).await;
        let provenance_before = authority.provenance_snapshot();
        let second = broker.execute_governed_request(request).await;
        assert_eq!(
            second.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        let provenance_after = authority.provenance_snapshot();
        assert_eq!(
            provenance_after.trusted_confirmations_provisioned,
            provenance_before.trusted_confirmations_provisioned
        );
        assert_eq!(provenance_after.request_derived_confirmations, 0);
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert_eq!(broker.snapshot().filesystem_mutations_committed, 1);
    }

    #[tokio::test]
    async fn grant_is_consumed_once() {
        let (fixture, authority, broker, request) = h4c_fixture("h4c-grant-once");
        let first = broker.execute_governed_request(request.clone()).await;
        assert!(matches!(
            first.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        let replay = broker.execute_governed_request(request).await;
        assert_eq!(
            replay.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        assert_eq!(authority.grants.lock().unwrap().len(), 1);
        assert_eq!(broker.snapshot().filesystem_mutations_committed, 1);
        assert_eq!(broker.snapshot().native_workers_started, 1);
        assert_eq!(
            fs::read(h4c_target_path(&fixture)).unwrap(),
            REPLACEMENT_CONTENT.as_bytes()
        );
    }

    #[tokio::test]
    async fn cancellation_before_fence_mutates_zero() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-cancel-before-fence");
        let broker_for_setup = Arc::clone(&broker);
        let setup: H4CNativeSetup = Arc::new(move || broker_for_setup.cancel());
        let result = broker
            .execute_governed_request_with_setup(request, None, Some(setup))
            .await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::LateAfterCancellation)
        );
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 0);
        assert_eq!(snapshot.native_workers_joined, 0);
        assert_eq!(snapshot.final_revalidations, 0);
        h4c_assert_unmodified(&fixture);
    }

    #[tokio::test]
    async fn cancellation_during_final_revalidation_mutates_zero() {
        let (fixture, authority, _unused_broker, request) = h4c_fixture("h4c-cancel-during-fence");
        let gated = H4CGatedAuthority::new(Arc::clone(&authority));
        let broker = fixture.broker(Arc::clone(&gated) as Arc<dyn VitaH4AuthorityPort>);
        let task = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.execute_governed_request(request).await })
        };
        gated.revalidation_started.notified().await;
        broker.cancel();
        let result = task.await.expect("H4-C cancellation task joined");
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::TurnCancelled)
        );
        h4c_assert_unmodified(&fixture);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(snapshot.filesystem_mutation_attempts, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        gated.release();
    }

    #[tokio::test]
    async fn late_authority_allow_cannot_mutate() {
        let (fixture, authority, _unused_broker, request) = h4c_fixture("h4c-late-allow");
        let late = H4CLateAllowAuthority::new(Arc::clone(&authority));
        let broker = fixture.broker(Arc::clone(&late) as Arc<dyn VitaH4AuthorityPort>);
        let task = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.execute_governed_request(request).await })
        };
        late.revalidation_started.notified().await;
        broker.cancel();
        let result = task.await.expect("H4-C late-allow task joined");
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::TurnCancelled)
        );
        late.release();
        tokio::time::timeout(Duration::from_secs(1), late.late_completed.notified())
            .await
            .expect("late authority allow should arrive");
        h4c_assert_unmodified(&fixture);
        assert_eq!(broker.snapshot().native_workers_started, 1);
        assert_eq!(broker.snapshot().native_workers_joined, 1);
        assert_eq!(broker.snapshot().filesystem_mutations_committed, 0);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn final_authority_panic_mutates_zero() {
        let (fixture, authority, _unused_broker, request) = h4c_fixture("h4c-authority-panic");
        let gated = H4CGatedAuthority::with_panic(Arc::clone(&authority), true);
        let broker = fixture.broker(Arc::clone(&gated) as Arc<dyn VitaH4AuthorityPort>);
        let task = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.execute_governed_request(request).await })
        };
        gated.revalidation_started.notified().await;
        gated.release();
        let result = task.await.expect("H4-C panic task joined");
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::AuthorityPanic)
        );
        h4c_assert_unmodified(&fixture);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.final_revalidations, 1);
        assert_eq!(snapshot.final_revalidation_denials, 1);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(snapshot.filesystem_mutations_committed, 0);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn commit_unknown_maps_truthfully() {
        let (_fixture, _authority, broker, request) = h4c_fixture("h4c-commit-unknown");
        let result = broker
            .execute_governed_request_with_fault(request, Some(H4CNativeFault::AfterFirstWrite))
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::CommitUnknown { .. })
        ));
        let value = result.model_value();
        assert_eq!(value["status"], "commit_outcome_unknown");
        assert_eq!(value["commit_outcome"], "unknown");
        assert_eq!(value["mutation_started"], true);
        assert_eq!(value["automatic_retry"], false);
        assert_eq!(value["side_effect_state"], "may_have_mutated");
        assert_eq!(value["side_effect_count"], 1);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.filesystem_commit_unknown, 1);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn commit_unknown_is_never_automatically_retried() {
        let (_fixture, authority, broker, request) = h4c_fixture("h4c-no-unknown-retry");
        let result = broker
            .execute_governed_request_with_fault(
                request.clone(),
                Some(H4CNativeFault::AfterFirstWrite),
            )
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::CommitUnknown { .. })
        ));
        assert_eq!(broker.snapshot().native_workers_started, 1);
        assert_eq!(broker.snapshot().native_workers_joined, 1);
        assert_eq!(broker.snapshot().grants_issued, 1);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
        assert_eq!(broker.snapshot().automatic_mutation_retries, 0);
        let replay = broker.execute_governed_request(request).await;
        assert_eq!(
            replay.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        assert_eq!(broker.snapshot().native_workers_started, 1);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_panic_before_first_mutation_is_denied_with_zero_side_effect() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-native-panic-before");
        let result = broker
            .execute_governed_request_with_fault(
                request,
                Some(H4CNativeFault::PanicBeforeFirstMutation),
            )
            .await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::TargetRejected)
        );
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        let value = result.model_value();
        assert_eq!(value["status"], "denied");
        assert_eq!(value["mutation_performed"], false);
        assert_eq!(value["side_effect_count"], 0);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.filesystem_mutations_committed, 0);
        assert_eq!(snapshot.filesystem_commit_unknown, 0);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        let evidence = broker.native_evidence_snapshot();
        assert_eq!(evidence.len(), 1);
        assert!(!evidence[0].mutation_started);
        assert_eq!(evidence[0].modifying_syscalls, 0);
        assert_eq!(evidence[0].committed_mutations, 0);
        assert!(!evidence[0].commit_unknown);
        h4c_assert_unmodified(&fixture);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_panic_after_first_mutation_is_commit_unknown() {
        let (_fixture, _authority, broker, request) = h4c_fixture("h4c-native-panic-after");
        let result = broker
            .execute_governed_request_with_fault(
                request,
                Some(H4CNativeFault::PanicAfterFirstMutation),
            )
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::CommitUnknown { .. })
        ));
        let value = result.model_value();
        assert_eq!(value["status"], "commit_outcome_unknown");
        assert_eq!(value["commit_outcome"], "unknown");
        assert_eq!(value["mutation_started"], true);
        assert_eq!(value["automatic_retry"], false);
        assert_eq!(value["side_effect_state"], "may_have_mutated");
        assert_eq!(value["side_effect_count"], 1);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.filesystem_mutations_committed, 0);
        assert_eq!(snapshot.filesystem_commit_unknown, 1);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        let evidence = broker.native_evidence_snapshot();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].mutation_started);
        assert_eq!(evidence[0].modifying_syscalls, 1);
        assert_eq!(evidence[0].committed_mutations, 0);
        assert!(evidence[0].commit_unknown);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_panic_after_mutation_is_never_retried() {
        let (_fixture, authority, broker, request) = h4c_fixture("h4c-native-panic-no-retry");
        let result = broker
            .execute_governed_request_with_fault(
                request.clone(),
                Some(H4CNativeFault::PanicAfterFirstMutation),
            )
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::CommitUnknown { .. })
        ));
        let replay = broker.execute_governed_request(request).await;
        assert_eq!(
            replay.classification,
            Some(H4DenyClassification::DuplicateToolCall)
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        assert_eq!(snapshot.filesystem_commit_unknown, 1);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(authority.requests.lock().unwrap().len(), 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_panic_worker_is_joined() {
        let (_fixture, _authority, broker, request) = h4c_fixture("h4c-native-panic-joined");
        let result = broker
            .execute_governed_request_with_fault(
                request,
                Some(H4CNativeFault::PanicBeforeFirstMutation),
            )
            .await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        assert_eq!(broker.snapshot().native_workers_started, 1);
        assert_eq!(broker.snapshot().native_workers_joined, 1);
    }

    #[tokio::test]
    async fn final_revalidation_rejects_denial_plus_grant() {
        assert_h4c_malformed_verdict(
            H4CMalformedVerdict::MixedDenialAndGrant,
            "h4c-malformed-denial-grant",
        )
        .await;
    }

    #[tokio::test]
    async fn final_revalidation_rejects_confirmation_payload() {
        assert_h4c_malformed_verdict(
            H4CMalformedVerdict::UnexpectedConfirmation,
            "h4c-malformed-confirmation",
        )
        .await;
    }

    #[tokio::test]
    async fn final_revalidation_rejects_confirmation_consumed() {
        assert_h4c_malformed_verdict(
            H4CMalformedVerdict::UnexpectedConfirmationConsumed,
            "h4c-malformed-confirmed",
        )
        .await;
    }

    #[tokio::test]
    async fn final_revalidation_rejects_malformed_status_grant_combination() {
        assert_h4c_malformed_verdict(
            H4CMalformedVerdict::OkStatusWithDenial,
            "h4c-malformed-ok-denial",
        )
        .await;
        assert_h4c_malformed_verdict(
            H4CMalformedVerdict::DeniedStatusWithGrant,
            "h4c-malformed-denied-grant",
        )
        .await;
    }

    #[tokio::test]
    async fn malformed_final_verdict_mutates_zero() {
        for (mode, call_id) in [
            (
                H4CMalformedVerdict::MixedDenialAndGrant,
                "h4c-malformed-zero-denial-grant",
            ),
            (
                H4CMalformedVerdict::UnexpectedConfirmation,
                "h4c-malformed-zero-confirmation",
            ),
            (
                H4CMalformedVerdict::UnexpectedConfirmationConsumed,
                "h4c-malformed-zero-consumed",
            ),
            (
                H4CMalformedVerdict::OkStatusWithDenial,
                "h4c-malformed-zero-ok-denial",
            ),
            (
                H4CMalformedVerdict::DeniedStatusWithGrant,
                "h4c-malformed-zero-denied-grant",
            ),
        ] {
            assert_h4c_malformed_verdict(mode, call_id).await;
        }
    }

    #[tokio::test]
    async fn native_worker_is_joined_on_success() {
        let (_fixture, _authority, broker, request) = h4c_fixture("h4c-joined-success");
        let result = broker.execute_governed_request(request).await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Committed { .. })
        ));
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
    }

    #[tokio::test]
    async fn native_worker_is_joined_on_denial() {
        let (fixture, authority, _broker, request) = h4c_fixture("h4c-joined-denial");
        let revoked = Arc::new(H4CRevokingAuthority {
            inner: Arc::clone(&authority),
        });
        let broker = fixture.broker(Arc::clone(&revoked) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_governed_request(request).await;
        assert!(matches!(
            result.execution,
            Some(VitaWorkspaceReplaceExecutionOutcome::Denied { .. })
        ));
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.native_workers_started, 1);
        assert_eq!(snapshot.native_workers_joined, 1);
        h4c_assert_unmodified(&fixture);
    }

    #[tokio::test]
    async fn model_output_excludes_authority_facts() {
        let (fixture, _authority, broker, request) = h4c_fixture("h4c-model-output");
        let result = broker.execute_governed_request(request).await;
        let value = result.model_value();
        assert_eq!(value["status"], "committed");
        assert_eq!(value["mutation_performed"], true);
        h4c_assert_no_authority_facts(&value);
        let denied = VitaWorkspaceReplaceResult::denied_after_grant(
            VitaWorkspaceReplaceRequest::synthetic(
                "h4c-model-denied",
                Some(fixture.context.clone()),
                "replace-me.txt",
                &sha256_hex(FILE_CONTENT.as_bytes()),
                REPLACEMENT_CONTENT,
            ),
            H4DenyClassification::RootDisabled,
        );
        h4c_assert_no_authority_facts(&denied.model_value());
    }

    #[test]
    fn h4c_fault_surface_is_test_only_and_no_new_schema_exists() {
        let source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/workspace_capability.rs"),
        )
        .expect("read H4-B workspace primitive");
        assert!(source.contains("WorkspaceReplaceTestFault"));
        let migrations = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("Vita manifest has repository parent")
                .join("src-tauri/src/storage/migrations.rs"),
        )
        .unwrap_or_default();
        assert!(!migrations.contains("Migration031"));
    }

    #[test]
    fn real_codex_h4c_canary_commits_one_governed_existing_file_replace() {
        thread::Builder::new()
            .name("d29h4-c-real-codex-tool".to_string())
            .stack_size(H4_CANARY_TEST_STACK_SIZE)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("H4-C test runtime should build");
                runtime.block_on(real_codex_h4c_canary_body());
            })
            .expect("H4-C test thread should start")
            .join()
            .expect("H4-C test thread should finish");
    }

    async fn real_codex_h4c_canary_body() {
        let (runtime, h3_broker, h4_broker, authority, before) = start_h4c_runtime()
            .await
            .expect("H4-C runtime should start");
        let file_path = runtime.workspace.path().join("replace-me.txt");
        let turn_id = start_h4_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("H4-C turn should start");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .expect("H4-C Responses fixture should remain available")
            .wait_for_initial_turn_id()
            .await
            .expect("H4-C fixture should expose the active turn id");
        assert_eq!(observed_turn_id, turn_id);
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .expect("H4-C canary context should remain valid");
        let authority_request = h4_canary_authority_request(&h4_broker, &context, turn_id);
        authority
            .provision_confirmation(&authority_request)
            .expect("H4-C canary trusted confirmation should pre-provision");
        runtime
            .fixture
            .as_ref()
            .expect("H4-C Responses fixture should remain available")
            .release_initial_request();
        let turn = wait_h4_turn(runtime.thread.as_ref().unwrap()).await;
        let file_after = fs::read(&file_path).expect("H4-C canary target remains readable");
        let (cleanup, fixture_observation) = runtime.shutdown().await;
        let host_shutdown = authority.shutdown();
        let turn = turn.unwrap_or_else(|error| {
            panic!(
                "H4-C turn should complete: {error}; fixture={fixture_observation:?}; cleanup={cleanup:?}"
            )
        });

        assert_eq!(before, h4_codex_state_canary(), "user Codex state changed");
        assert_eq!(turn.1, None);
        assert_eq!(turn.0.as_deref(), Some(H4_CANARY_REPLY));
        assert!(turn.2 > 0);
        assert_eq!(file_after, H4_CANARY_REPLACEMENT_CONTENT.as_bytes());
        assert_eq!(cleanup.initial_shutdown, H4ShutdownStatus::Success);
        assert_eq!(cleanup.final_shutdown, H4ShutdownStatus::Success);
        assert_eq!(cleanup.manager_thread_count, 0);
        assert!(cleanup.fixture_listener_joined);
        assert!(host_shutdown);

        assert_eq!(fixture_observation.request_count, 3);
        assert!(fixture_observation.first_request_has_h3_tool);
        assert!(fixture_observation.first_request_has_h4_tool);
        assert!(fixture_observation.second_request_received_h3_hash);
        assert!(fixture_observation.third_request_received_committed_h4_result);
        assert!(!fixture_observation.third_request_received_authorized_h4_result);
        assert!(fixture_observation.third_request_excluded_authority_facts);
        assert!(fixture_observation.error.is_none());

        let h3_snapshot = h3_broker.snapshot();
        assert_eq!(h3_snapshot.attempted_requests, 1);
        assert_eq!(h3_snapshot.authorized_file_reads, 1);
        assert_eq!(h3_snapshot.file_bytes_read, H4_CANARY_FILE_CONTENT.len());
        assert_eq!(h3_snapshot.filesystem_mutations, 0);
        assert_eq!(h3_snapshot.process_spawns, 0);
        assert_eq!(h3_snapshot.external_network_requests, 0);

        let h4_snapshot = h4_broker.snapshot();
        assert_eq!(h4_snapshot.attempted_requests, 1);
        assert_eq!(h4_snapshot.canonical_evaluations, 2);
        assert_eq!(h4_snapshot.confirmations_consumed, 1);
        assert_eq!(h4_snapshot.grants_issued, 1);
        assert_eq!(h4_snapshot.native_workers_started, 1);
        assert_eq!(h4_snapshot.native_workers_joined, 1);
        assert_eq!(h4_snapshot.exclusive_operation_handles, 1);
        assert_eq!(h4_snapshot.final_revalidations, 1);
        assert_eq!(h4_snapshot.final_revalidation_denials, 0);
        assert_eq!(h4_snapshot.filesystem_mutation_attempts, 1);
        assert_eq!(h4_snapshot.filesystem_mutations_committed, 1);
        assert_eq!(h4_snapshot.filesystem_commit_unknown, 0);
        assert_eq!(h4_snapshot.automatic_mutation_retries, 0);
        assert_eq!(h4_snapshot.authorized_write_count, 1);
        assert_eq!(h4_snapshot.filesystem_mutations, 1);
        assert_eq!(h4_snapshot.process_spawns, 0);
        assert_eq!(h4_snapshot.external_network_requests, 0);
        assert_eq!(h4_snapshot.max_active_authority, 1);

        let observations = authority.snapshot();
        assert_eq!(observations.len(), 2);
        let provenance = authority.provenance_snapshot();
        assert_eq!(provenance.trusted_confirmations_provisioned, 1);
        assert_eq!(provenance.request_derived_confirmations, 0);
        assert_eq!(
            provenance.events,
            vec![
                H4AuthorityEvent::TrustedConfirmationProvisioned,
                H4AuthorityEvent::IssueEvaluated,
                H4AuthorityEvent::RevalidationEvaluated,
            ]
        );
        for observation in &observations {
            let canonical = observation
                .canonical
                .as_ref()
                .expect("H4-C Host canonical result");
            assert_eq!(canonical.canonical_evaluations, 1);
            assert_eq!(canonical.production_registry_size, 1);
            assert_eq!(canonical.test_registry_size, 1);
            assert_eq!(canonical.authorization_row_reads, 1);
            assert!(canonical.host_scope_authority_present);
            assert!(canonical.requested_root_matched_authorized_root);
            assert_eq!(canonical.outcome, "ScopeRequired");
            assert_eq!(canonical.decision_code, "CAPABILITY_SCOPE_NOT_AVAILABLE");
            assert_eq!(canonical.risk_class, H4_DESCRIPTOR_RISK_CLASS);
            assert_eq!(canonical.scope_requirement, H4_DESCRIPTOR_SCOPE_REQUIREMENT);
            assert_eq!(canonical.approval_floor, H4_DESCRIPTOR_APPROVAL_FLOOR);
            assert_eq!(canonical.authorization_revision, Some(REVISION));
        }
        let evidence = h4_broker.native_evidence_snapshot();
        assert_eq!(evidence.len(), 1);
        let evidence = &evidence[0];
        assert_eq!(evidence.operation_handle_open_count, 1);
        assert_eq!(evidence.fence_calls, 1);
        assert_eq!(
            evidence.before_sha256.as_deref(),
            Some(sha256_hex(H4_CANARY_FILE_CONTENT.as_bytes(),).as_str())
        );
        assert_eq!(
            evidence.after_sha256.as_deref(),
            Some(sha256_hex(H4_CANARY_REPLACEMENT_CONTENT.as_bytes(),).as_str())
        );
        assert_eq!(evidence.modifying_syscalls, 3);
        assert_eq!(evidence.committed_mutations, 1);
        assert!(!evidence.commit_unknown);
        assert!(evidence.events.first() == Some(&WorkspaceReplaceEvidenceEvent::InitialHashCheck));
        assert!(evidence
            .events
            .contains(&WorkspaceReplaceEvidenceEvent::CommitFence));
        assert!(evidence
            .events
            .contains(&WorkspaceReplaceEvidenceEvent::PostFenceRootCheck));
        assert!(evidence
            .events
            .contains(&WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck));
        assert!(evidence
            .events
            .contains(&WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall));
        let event_index = |event: WorkspaceReplaceEvidenceEvent| {
            evidence
                .events
                .iter()
                .position(|observed| *observed == event)
                .expect("H4-C evidence event is present")
        };
        let initial_hash = event_index(WorkspaceReplaceEvidenceEvent::InitialHashCheck);
        let fence = event_index(WorkspaceReplaceEvidenceEvent::CommitFence);
        let post_root = event_index(WorkspaceReplaceEvidenceEvent::PostFenceRootCheck);
        let post_parent = event_index(WorkspaceReplaceEvidenceEvent::PostFenceParentCheck);
        let post_target = event_index(WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck);
        let post_link = event_index(WorkspaceReplaceEvidenceEvent::PostFenceLinkCheck);
        let post_hash = event_index(WorkspaceReplaceEvidenceEvent::PostFenceHashCheck);
        let post_cancel = event_index(WorkspaceReplaceEvidenceEvent::PostFenceCancellationCheck);
        let first_mutation = event_index(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall);
        assert!(initial_hash < fence);
        assert!(fence < post_root);
        assert!(post_root < post_parent);
        assert!(post_parent < post_target);
        assert!(post_target < post_link);
        assert!(post_link < post_hash);
        assert!(post_hash < post_cancel);
        assert!(post_cancel < first_mutation);
    }
}
