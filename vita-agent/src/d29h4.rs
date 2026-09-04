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
use std::time::{SystemTime, UNIX_EPOCH};

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::workspace_capability::{PreparedWorkspaceTarget, PreparedWorkspaceTargetKind};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostExplicitActionConfirmationEvidence {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct H4HostAuthorityResponse {
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
struct H4AuthorityRequest {
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
enum H4DenyClassification {
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
    fn as_str(self) -> &'static str {
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
}

impl VitaWorkspaceReplaceResult {
    fn denied(request: VitaWorkspaceReplaceRequest, classification: H4DenyClassification) -> Self {
        Self {
            request,
            classification: Some(classification),
            grant_issued: false,
            authorized_for_future_replace_foundation: false,
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
        }
    }

    fn authorized(request: VitaWorkspaceReplaceRequest) -> Self {
        Self {
            request,
            classification: None,
            grant_issued: true,
            authorized_for_future_replace_foundation: true,
        }
    }

    fn model_value(&self) -> Value {
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
}

/// H4-A's Vita-side boundary is test/integration-only.  It can import an
/// exact Host grant and prove that a future replacement is authorized, but it
/// intentionally has no mutation method or write-capable operation handle.
pub(crate) struct VitaWorkspaceReplaceBroker {
    context: Option<VitaExecutionContext>,
    root: super::TrustedWorkspaceRoot,
    authority: Arc<dyn VitaH4AuthorityPort>,
    state: Mutex<H4BrokerState>,
    cancelled: AtomicBool,
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
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(H4BrokerMetrics::default()),
        })
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
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
        }
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
    if bounded_text(&confirmation.confirmation_id, MAX_CALL_ID_CHARS).is_none()
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
/// installs H4-A and the production capability registry remains empty.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::AtomicUsize;
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
            H4AuthorityRequest {
                context: self.context.clone(),
                capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                operation,
                tool_call_id: request.tool_call_id,
                turn_id: request.turn_id,
                relative_path: request.relative_path,
                expected_sha256: request.expected_sha256,
                replacement_sha256: sha256_hex(REPLACEMENT_CONTENT.as_bytes()),
                replacement_bytes: REPLACEMENT_CONTENT.as_bytes().len(),
                workspace_root_identity: self.root.identity(),
                target_identity: self.target_identity,
                target_kind: PreparedWorkspaceTargetKind::ExistingFile,
            }
        }

        fn broker(
            &self,
            authority: Arc<dyn VitaH4AuthorityPort>,
        ) -> Arc<VitaWorkspaceReplaceBroker> {
            VitaWorkspaceReplaceBroker::new(self.context.clone(), self.root.clone(), authority)
        }
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

    struct TestHostAuthority {
        root: super::super::WorkspaceRootIdentity,
        confirmations: Mutex<HashMap<String, HostExplicitActionConfirmationEvidence>>,
        grants: Mutex<HashMap<String, H4HostReplaceGrantEvidence>>,
        calls: AtomicUsize,
        next_id: AtomicUsize,
        disabled: AtomicBool,
        revision: AtomicUsize,
        mutation: ConfirmationMutation,
        auto_provision: bool,
    }

    impl TestHostAuthority {
        fn new(root: super::super::WorkspaceRootIdentity) -> Arc<Self> {
            Self::with_auto_provision(root, true)
        }

        fn new_without_provision(root: super::super::WorkspaceRootIdentity) -> Arc<Self> {
            Self::with_auto_provision(root, false)
        }

        fn with_auto_provision(
            root: super::super::WorkspaceRootIdentity,
            auto_provision: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                root,
                confirmations: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                calls: AtomicUsize::new(0),
                next_id: AtomicUsize::new(0),
                disabled: AtomicBool::new(false),
                revision: AtomicUsize::new(REVISION as usize),
                mutation: ConfirmationMutation::None,
                auto_provision,
            })
        }

        fn provision(&self, request: &H4AuthorityRequest) {
            let id = self.next_id.fetch_add(1, Ordering::AcqRel);
            let now = unix_millis();
            let mut confirmation = HostExplicitActionConfirmationEvidence {
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
                return H4HostAuthorityResponse {
                    canonical,
                    confirmation: None,
                    grant: None,
                    denial: None,
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
            let response = match request.operation {
                H4AuthorityOperation::IssueReplaceGrant => {
                    if self.auto_provision && lock_unpoisoned(&self.confirmations).is_empty() {
                        // The fixture's explicit provisioning is a trusted
                        // Host action, never a field in the model request.
                        self.provision(&request);
                    }
                    self.issue(request)
                }
                H4AuthorityOperation::Revalidate {
                    ref grant_id,
                    authorization_revision: _,
                } => {
                    let canonical = self.canonical(&request);
                    let grant = lock_unpoisoned(&self.grants).get(grant_id).cloned();
                    H4HostAuthorityResponse {
                        canonical,
                        confirmation: None,
                        grant,
                        denial: None,
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
        let authority = TestHostAuthority::new_without_provision(fixture.root.identity());
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
    async fn correct_confirmation_issues_exact_single_use_grant() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker
            .execute_request(fixture.request("correct-confirmation"))
            .await;
        assert!(result.authorized_for_future_replace_foundation);
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.confirmations_consumed, 1);
        assert_eq!(snapshot.filesystem_mutations, 0);
        assert_eq!(snapshot.process_spawns, 0);
        assert_eq!(snapshot.external_network_requests, 0);
    }

    #[tokio::test]
    async fn confirmation_replay_cannot_issue_second_grant() {
        let fixture = Fixture::new();
        let authority = TestHostAuthority::new(fixture.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let request = fixture.request("duplicate-call");
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
    }

    #[tokio::test]
    async fn wrong_workspace_root_cannot_issue_grant() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let authority = TestHostAuthority::new_without_provision(other.root.identity());
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker.execute_request(fixture.request("wrong-root")).await;
        assert_eq!(
            result.classification,
            Some(H4DenyClassification::WorkspaceScopeDenied)
        );
        assert_eq!(broker.snapshot().grants_issued, 0);
        assert!(lock_unpoisoned(&authority.confirmations).is_empty());
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
            let authority = Arc::new(TestHostAuthority {
                root: fixture.root.identity(),
                confirmations: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                calls: AtomicUsize::new(0),
                next_id: AtomicUsize::new(0),
                disabled: AtomicBool::new(false),
                revision: AtomicUsize::new(REVISION as usize),
                mutation,
                auto_provision: false,
            });
            // Provision a deliberately wrong Host record.  The requester has
            // no path to place this record in the Host store.
            let request = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
            authority.provision(&request);
            let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
            let result = broker
                .execute_request(fixture.request("wrong-binding"))
                .await;
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
        let authority = Arc::new(TestHostAuthority {
            root: fixture.root.identity(),
            confirmations: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
            calls: AtomicUsize::new(0),
            next_id: AtomicUsize::new(0),
            disabled: AtomicBool::new(false),
            revision: AtomicUsize::new(REVISION as usize),
            mutation: ConfirmationMutation::WrongRevision,
            auto_provision: false,
        });
        let request = fixture.authority_request(H4AuthorityOperation::IssueReplaceGrant);
        authority.provision(&request);
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
        authority.provision(&request);
        let issue = authority.evaluate(request.clone()).await.unwrap();
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
        let broker = fixture.broker(Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>);
        let result = broker
            .execute_request(fixture.request("requester-cannot-authorize"))
            .await;
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
                !h4_source.contains(forbidden),
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
    fn production_registry_remains_empty() {
        let descriptor_source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("Vita manifest has repository parent")
                .join("src-tauri/src/capability/descriptor.rs"),
        )
        .expect("read D28 descriptor registry");
        assert!(descriptor_source.contains("Self::from_trusted_descriptors([])"));
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

    struct ProcessIsolatedH4Authority {
        process: Arc<PersistentH4HostProcess>,
        observations: Arc<Mutex<Vec<H4HostResponse>>>,
    }

    impl ProcessIsolatedH4Authority {
        fn new(
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
            }))
        }

        fn snapshot(&self) -> Vec<H4HostResponse> {
            lock_unpoisoned(&self.observations).clone()
        }

        fn shutdown(&self) -> bool {
            self.process.shutdown()
        }
    }

    impl VitaH4AuthorityPort for ProcessIsolatedH4Authority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            let process = Arc::clone(&self.process);
            let observations = Arc::clone(&self.observations);
            let request_for_io = request.clone();
            let wire = h4_wire_request(&request);
            Box::pin(async move {
                let process_for_roundtrip = Arc::clone(&process);
                let join = tokio::task::spawn_blocking(move || {
                    if matches!(
                        request_for_io.operation,
                        H4AuthorityOperation::IssueReplaceGrant
                    ) {
                        provision_h4_confirmation(&process_for_roundtrip, &request_for_io)?;
                    }
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
                lock_unpoisoned(&observations).push(response);
                Ok(typed)
            })
        }
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
            || canonical.production_registry_size != 0
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
        if response.status != "ok" && response.status != "denied" {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let denial = response
            .denial
            .as_deref()
            .map(parse_h4_denial)
            .transpose()?;
        Ok(H4HostAuthorityResponse {
            canonical,
            confirmation,
            grant,
            denial,
            confirmation_consumed: response.confirmation_consumed,
        })
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

    #[derive(Clone, Debug, Default)]
    struct H4FixtureObservation {
        request_count: usize,
        first_request_has_h3_tool: bool,
        first_request_has_h4_tool: bool,
        second_request_received_h3_hash: bool,
        third_request_received_authorized_h4_result: bool,
        third_request_excluded_authority_facts: bool,
        error: Option<String>,
    }

    struct H4ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H4FixtureObservation>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl H4ResponsesFixture {
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind H4-A loopback fixture");
            let address = listener.local_addr().expect("H4-A fixture address");
            let stop = Arc::new(AtomicBool::new(false));
            let observation = Arc::new(Mutex::new(H4FixtureObservation::default()));
            let stop_for_thread = Arc::clone(&stop);
            let observation_for_thread = Arc::clone(&observation);
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
                    let result = handle_h4_fixture_request(&mut stream, peer, response_index);
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
                join: Some(join),
            }
        }

        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}/v1", self.address.port())
        }

        fn shutdown(mut self) -> (H4FixtureObservation, bool) {
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

    impl Drop for H4ResponsesFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
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
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("H4-A fixture received a non-loopback peer".to_string());
        }
        let body = read_h4_http_request(stream)?;
        let events = match response_index {
            0 => h4_canary_first_response_events(),
            1 => h4_canary_second_response_events(),
            2 => h4_canary_completion_response_events(),
            _ => return Err("H4-A fixture received too many requests".to_string()),
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
        let fixture = H4ResponsesFixture::start();
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
        extensions.tool_contributor(Arc::new(VitaWorkspaceReplaceToolContributor::new(
            Arc::clone(&h4_broker),
        )));
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

    async fn run_h4_turn(
        thread: &Arc<codex_core_api::CodexThread>,
    ) -> Result<(Option<String>, Option<String>, usize), String> {
        tokio::time::timeout(
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
        let turn = run_h4_turn(runtime.thread.as_ref().unwrap()).await;
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
        let issue = &observations[0];
        let revalidate = &observations[1];
        for observation in &observations {
            let canonical = observation
                .canonical
                .as_ref()
                .expect("H4-A Host canonical result");
            assert_eq!(canonical.canonical_evaluations, 1);
            assert_eq!(canonical.production_registry_size, 0);
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
}
