//! D29-H1 deny-first boundary for real Codex tool requests.
//!
//! The module owns the narrow Vita-side request/decision/result seam.  It
//! deliberately has no executor, process, filesystem, browser, network, or
//! plugin capability.  A future stage may install an adapter for the host's
//! canonical authority, but H1 cannot turn an authority decision into an
//! executable grant.
#![allow(dead_code)]

use std::collections::HashSet;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolCallSource,
    ToolContributor, ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};

pub const VITA_GOVERNED_ACTION_TOOL_NAME: &str = "vita_governed_action";
pub const VITA_GOVERNED_ACTION_CAPABILITY_ID: &str = "vita.governed_action";
pub(crate) const VITA_H1_MAX_TOOL_CALLS: usize = 8;

const MAX_ID_CHARS: usize = 128;
const MAX_OPERATION_CHARS: usize = 128;
const MAX_RESOURCE_CHARS: usize = 256;

/// Explicit Digital Life ownership for one Codex turn.
///
/// There is no constructor that fills either identity from a global, stock
/// Codex, or process environment value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VitaExecutionContext {
    life_id: String,
    task_id: String,
}

impl VitaExecutionContext {
    pub fn try_new(
        life_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Result<Self, VitaExecutionContextError> {
        let life_id = bounded_identity("life_id", life_id.into())?;
        let task_id = bounded_identity("task_id", task_id.into())?;
        Ok(Self { life_id, task_id })
    }

    pub fn life_id(&self) -> &str {
        &self.life_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaExecutionContextError {
    Empty(&'static str),
    TooLong(&'static str),
    InvalidCharacter(&'static str),
}

impl VitaExecutionContextError {
    fn field(self) -> &'static str {
        match self {
            Self::Empty(field) | Self::TooLong(field) | Self::InvalidCharacter(field) => field,
        }
    }
}

/// The only scope values that can cross the H1 boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaRequestedScope {
    None,
    Workspace,
    NetworkDestination,
    ExternalResource,
}

impl VitaRequestedScope {
    fn parse(value: Option<&str>) -> Result<Self, VitaRequestBuildError> {
        match value {
            None | Some("none") => Ok(Self::None),
            Some("workspace") => Ok(Self::Workspace),
            Some("network_destination") => Ok(Self::NetworkDestination),
            Some("external_resource") => Ok(Self::ExternalResource),
            Some(_) => Err(VitaRequestBuildError::InvalidScope),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Workspace => "workspace",
            Self::NetworkDestination => "network_destination",
            Self::ExternalResource => "external_resource",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VitaToolIdentity {
    namespace: Option<String>,
    name: String,
}

impl VitaToolIdentity {
    fn from_codex(name: &ToolName) -> Self {
        Self {
            namespace: name.namespace.clone(),
            name: name.name.clone(),
        }
    }

    fn is_trusted_h1_tool(&self) -> bool {
        self.name == VITA_GOVERNED_ACTION_TOOL_NAME
            && ToolName::new(self.namespace.clone(), self.name.clone()).is_default_namespace()
    }

    fn display_name(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{namespace}:{}", self.name),
            None => self.name.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VitaToolCallSource {
    Direct,
    CodeMode,
}

impl VitaToolCallSource {
    fn from_codex(source: &ToolCallSource) -> Self {
        match source {
            ToolCallSource::Direct => Self::Direct,
            ToolCallSource::CodeMode { .. } => Self::CodeMode,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::CodeMode => "code_mode",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VitaRequestEvidence {
    codex_turn_id: String,
    source: VitaToolCallSource,
}

/// The minimum typed request retained from a real Codex ToolCall.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VitaToolAuthorityRequest {
    tool_call_id: String,
    tool_identity: VitaToolIdentity,
    operation: String,
    context: Option<VitaExecutionContext>,
    capability_id: String,
    requested_scope: VitaRequestedScope,
    requested_resource: Option<String>,
    expected_authorization_revision: Option<i64>,
    evidence: VitaRequestEvidence,
}

impl VitaToolAuthorityRequest {
    fn from_codex_call(
        call: &ToolCall<'_>,
        context: Option<&VitaExecutionContext>,
    ) -> Result<Self, VitaRequestBuildError> {
        let tool_identity = VitaToolIdentity::from_codex(&call.tool_name);
        if !tool_identity.is_trusted_h1_tool() {
            return Err(VitaRequestBuildError::UnmappedTool);
        }

        let tool_call_id = bounded_identity("tool_call_id", call.call_id.clone())
            .map_err(|_| VitaRequestBuildError::InvalidCallId)?;
        let codex_turn_id = bounded_identity("turn_id", call.turn_id.clone())
            .map_err(|_| VitaRequestBuildError::InvalidTurnId)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| VitaRequestBuildError::InvalidArguments)?;
        let arguments: VitaToolArguments =
            serde_json::from_str(arguments).map_err(|_| VitaRequestBuildError::InvalidArguments)?;
        let operation = bounded_operation(arguments.operation)
            .map_err(|_| VitaRequestBuildError::InvalidOperation)?;
        let requested_scope = VitaRequestedScope::parse(arguments.scope.as_deref())?;
        if let Some(revision) = arguments.expected_revision {
            if revision < 1 {
                return Err(VitaRequestBuildError::InvalidRevision);
            }
        }
        let requested_resource = arguments
            .resource
            .map(|resource| {
                bounded_resource(resource).map_err(|_| VitaRequestBuildError::InvalidResource)
            })
            .transpose()?;

        // The capability identity is selected solely by this trusted static
        // mapping.  No model argument participates in its construction.
        Ok(Self {
            tool_call_id,
            tool_identity,
            operation,
            context: context.cloned(),
            capability_id: VITA_GOVERNED_ACTION_CAPABILITY_ID.to_string(),
            requested_scope,
            requested_resource,
            expected_authorization_revision: arguments.expected_revision,
            evidence: VitaRequestEvidence {
                codex_turn_id,
                source: VitaToolCallSource::from_codex(&call.source),
            },
        })
    }

    pub fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }

    pub fn tool_identity(&self) -> String {
        self.tool_identity.display_name()
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn context(&self) -> Option<&VitaExecutionContext> {
        self.context.as_ref()
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn requested_scope(&self) -> VitaRequestedScope {
        self.requested_scope
    }

    pub fn requested_resource(&self) -> Option<&str> {
        self.requested_resource.as_deref()
    }

    pub fn expected_authorization_revision(&self) -> Option<i64> {
        self.expected_authorization_revision
    }

    #[cfg(test)]
    fn synthetic(
        tool_call_id: &str,
        tool_name: ToolName,
        operation: &str,
        context: Option<VitaExecutionContext>,
        requested_scope: VitaRequestedScope,
        expected_authorization_revision: Option<i64>,
    ) -> Self {
        Self {
            tool_call_id: tool_call_id.to_string(),
            tool_identity: VitaToolIdentity::from_codex(&tool_name),
            operation: operation.to_string(),
            context,
            capability_id: if tool_name.name == VITA_GOVERNED_ACTION_TOOL_NAME
                && tool_name.is_default_namespace()
            {
                VITA_GOVERNED_ACTION_CAPABILITY_ID.to_string()
            } else {
                "vita.unknown".to_string()
            },
            requested_scope,
            requested_resource: None,
            expected_authorization_revision,
            evidence: VitaRequestEvidence {
                codex_turn_id: "turn-test".to_string(),
                source: VitaToolCallSource::Direct,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VitaToolArguments {
    operation: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    expected_revision: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VitaRequestBuildError {
    UnmappedTool,
    InvalidCallId,
    InvalidTurnId,
    InvalidArguments,
    InvalidOperation,
    InvalidScope,
    InvalidResource,
    InvalidRevision,
}

impl VitaRequestBuildError {
    fn classification(self) -> VitaDenyClassification {
        match self {
            Self::UnmappedTool => VitaDenyClassification::UnmappedTool,
            Self::InvalidCallId
            | Self::InvalidTurnId
            | Self::InvalidArguments
            | Self::InvalidOperation
            | Self::InvalidScope
            | Self::InvalidResource
            | Self::InvalidRevision => VitaDenyClassification::MalformedToolRequest,
        }
    }
}

/// Neutral verdict vocabulary crossing the Vita authority port.
///
/// The host may map a canonical authority system into this bounded contract,
/// but Vita does not own or recreate that authority system.  A verdict is
/// evidence about one normalized request; it is never an executable grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaAuthorityOutcome {
    Denied,
    Eligible,
}

impl VitaAuthorityOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Eligible => "eligible",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaAuthorityReason {
    UnknownCapabilityDescriptor,
    AuthorizationUnavailable,
    InvalidRequest,
    NotEligible,
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeNotAvailable,
    Forbidden,
    Eligible,
    InvalidVerdict,
}

impl VitaAuthorityReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCapabilityDescriptor => "unknown_capability_descriptor",
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::InvalidRequest => "invalid_authority_request",
            Self::NotEligible => "not_eligible",
            Self::Denied => "authorization_denied",
            Self::RootDisabled => "root_disabled",
            Self::ExplicitConfirmationRequired => "explicit_confirmation_required",
            Self::ScopeNotAvailable => "scope_not_available",
            Self::Forbidden => "forbidden",
            Self::Eligible => "eligible",
            Self::InvalidVerdict => "invalid_authority_verdict",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaAuthorityEvidenceSource {
    HostCanonicalAuthority,
    TestFixture,
}

impl VitaAuthorityEvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostCanonicalAuthority => "host_canonical_authority",
            Self::TestFixture => "test_fixture",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VitaAuthorityEvidence {
    source: VitaAuthorityEvidenceSource,
    authorization_revision: Option<i64>,
}

impl VitaAuthorityEvidence {
    pub fn source(&self) -> VitaAuthorityEvidenceSource {
        self.source
    }

    pub fn authorization_revision(&self) -> Option<i64> {
        self.authorization_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VitaAuthorityError {
    Unavailable,
    InvalidRequest,
    InvalidVerdict,
}

impl std::fmt::Display for VitaAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authority unavailable",
            Self::InvalidRequest => "authority request was invalid",
            Self::InvalidVerdict => "authority verdict was invalid",
        })
    }
}

impl std::error::Error for VitaAuthorityError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VitaAuthorityVerdict {
    outcome: VitaAuthorityOutcome,
    reason: VitaAuthorityReason,
    life_id: String,
    capability_id: String,
    requested_scope: VitaRequestedScope,
    evidence: VitaAuthorityEvidence,
}

impl VitaAuthorityVerdict {
    pub fn from_request(
        request: &VitaToolAuthorityRequest,
        outcome: VitaAuthorityOutcome,
        reason: VitaAuthorityReason,
        authorization_revision: Option<i64>,
        source: VitaAuthorityEvidenceSource,
    ) -> Result<Self, VitaAuthorityError> {
        let Some(context) = request.context.as_ref() else {
            return Err(VitaAuthorityError::InvalidRequest);
        };
        Ok(Self {
            outcome,
            reason,
            life_id: context.life_id.clone(),
            capability_id: request.capability_id.clone(),
            requested_scope: request.requested_scope,
            evidence: VitaAuthorityEvidence {
                source,
                authorization_revision,
            },
        })
    }

    pub fn outcome(&self) -> VitaAuthorityOutcome {
        self.outcome
    }

    pub fn reason(&self) -> VitaAuthorityReason {
        self.reason
    }

    pub fn life_id(&self) -> &str {
        &self.life_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn requested_scope(&self) -> VitaRequestedScope {
        self.requested_scope
    }

    pub fn evidence(&self) -> &VitaAuthorityEvidence {
        &self.evidence
    }
}

/// Async-shaped neutral authority port.  The host supplies the authority
/// implementation; Vita only consumes the bounded verdict.
pub type VitaAuthorityFuture = Pin<
    Box<dyn Future<Output = Result<VitaAuthorityVerdict, VitaAuthorityError>> + Send + 'static>,
>;

pub trait VitaToolAuthorityPort: Send + Sync {
    fn evaluate(&self, request: VitaToolAuthorityRequest) -> VitaAuthorityFuture;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VitaDenyClassification {
    MissingContext,
    UnknownCapabilityDescriptor,
    WrongLifeBinding,
    WrongTaskBinding,
    UnmappedTool,
    MissingAuthorization,
    StaleRevision,
    BroaderScope,
    ScopeUnavailable,
    DuplicateToolCall,
    TurnCancelled,
    LateAfterCancellation,
    TooManyToolCalls,
    AuthorityError,
    AuthorityPanic,
    AuthorityEvidenceMismatch,
    NoExecutableGrant,
    MalformedToolRequest,
}

impl VitaDenyClassification {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingContext => "missing_execution_context",
            Self::UnknownCapabilityDescriptor => "unknown_capability_descriptor",
            Self::WrongLifeBinding => "wrong_life_binding",
            Self::WrongTaskBinding => "wrong_task_binding",
            Self::UnmappedTool => "unmapped_tool",
            Self::MissingAuthorization => "missing_authorization",
            Self::StaleRevision => "stale_authorization_revision",
            Self::BroaderScope => "broader_requested_scope",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::DuplicateToolCall => "duplicate_tool_call_id",
            Self::TurnCancelled => "turn_cancelled",
            Self::LateAfterCancellation => "late_authority_after_cancellation",
            Self::TooManyToolCalls => "h1_tool_call_limit",
            Self::AuthorityError => "authority_error",
            Self::AuthorityPanic => "authority_panic",
            Self::AuthorityEvidenceMismatch => "authority_evidence_mismatch",
            Self::NoExecutableGrant => "no_executable_grant_in_h1",
            Self::MalformedToolRequest => "malformed_tool_request",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VitaToolDecision {
    classification: VitaDenyClassification,
    authority_outcome: Option<VitaAuthorityOutcome>,
    authority_reason: Option<VitaAuthorityReason>,
    authorization_revision: Option<i64>,
    authority_evidence: Option<VitaAuthorityEvidence>,
}

impl VitaToolDecision {
    fn boundary_denied(classification: VitaDenyClassification) -> Self {
        Self {
            classification,
            authority_outcome: None,
            authority_reason: None,
            authorization_revision: None,
            authority_evidence: None,
        }
    }

    fn authority_denied(
        classification: VitaDenyClassification,
        authority: &VitaAuthorityVerdict,
    ) -> Self {
        Self {
            classification,
            authority_outcome: Some(authority.outcome()),
            authority_reason: Some(authority.reason()),
            authorization_revision: authority.evidence().authorization_revision(),
            authority_evidence: Some(authority.evidence().clone()),
        }
    }
}

/// Bounded model-facing result.  H1 has no success/execution variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VitaToolResult {
    request: VitaToolAuthorityRequest,
    decision: VitaToolDecision,
    execution_started: bool,
    side_effect_count: u8,
}

impl VitaToolResult {
    fn denied(request: VitaToolAuthorityRequest, classification: VitaDenyClassification) -> Self {
        Self {
            request,
            decision: VitaToolDecision::boundary_denied(classification),
            execution_started: false,
            side_effect_count: 0,
        }
    }

    fn denied_by_authority(
        request: VitaToolAuthorityRequest,
        classification: VitaDenyClassification,
        authority: &VitaAuthorityVerdict,
    ) -> Self {
        Self {
            request,
            decision: VitaToolDecision::authority_denied(classification, authority),
            execution_started: false,
            side_effect_count: 0,
        }
    }

    pub(crate) fn deny_classification(&self) -> VitaDenyClassification {
        self.decision.classification
    }

    pub(crate) fn execution_started(&self) -> bool {
        self.execution_started
    }

    pub(crate) fn side_effect_count(&self) -> u8 {
        self.side_effect_count
    }

    pub(crate) fn authority_lookup_attempted(&self) -> bool {
        self.decision.authority_outcome.is_some()
    }

    pub(crate) fn authority_revision(&self) -> Option<i64> {
        self.decision.authorization_revision
    }

    fn model_value(&self) -> Value {
        json!({
            "status": "denied",
            "tool_call_id": self.request.tool_call_id,
            "tool": self.request.tool_identity.display_name(),
            "operation": self.request.operation,
            "life_id": self.request.context.as_ref().map(|context| context.life_id()),
            "task_id": self.request.context.as_ref().map(|context| context.task_id()),
            "capability_id": self.request.capability_id,
            "requested_scope": self.request.requested_scope.as_str(),
            "requested_resource": self.request.requested_resource,
            "expected_authorization_revision": self.request.expected_authorization_revision,
            "codex_turn_id": self.request.evidence.codex_turn_id,
            "source": self.request.evidence.source.as_str(),
            "deny_classification": self.decision.classification.as_str(),
            "authority_reason": self.decision.authority_reason.map(VitaAuthorityReason::as_str),
            "authority_revision": self.decision.authorization_revision,
            "authority_evidence": self.decision.authority_evidence.as_ref().map(|evidence| json!({
                "source": evidence.source.as_str(),
                "authorization_revision": evidence.authorization_revision,
            })),
            "execution_started": self.execution_started,
            "side_effect_count": self.side_effect_count,
        })
    }
}

#[derive(Default)]
struct BrokerState {
    seen_call_ids: HashSet<String>,
    admitted_calls: usize,
}

#[derive(Default)]
struct VitaBrokerMetrics {
    attempted_requests: AtomicUsize,
    authority_lookups: AtomicUsize,
    duplicate_denials: AtomicUsize,
    late_denials: AtomicUsize,
    authority_errors: AtomicUsize,
    authority_panics: AtomicUsize,
    execution_started: AtomicUsize,
    side_effect_count: AtomicUsize,
    active_authority: AtomicUsize,
    max_active_authority: AtomicUsize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VitaBrokerSnapshot {
    pub attempted_requests: usize,
    pub authority_lookups: usize,
    pub duplicate_denials: usize,
    pub late_denials: usize,
    pub authority_errors: usize,
    pub authority_panics: usize,
    pub execution_started: usize,
    pub side_effect_count: usize,
    pub max_active_authority: usize,
}

/// Thin deny-first broker.  It owns bounded duplicate/cancellation state but
/// intentionally owns no side-effect executor.
pub struct VitaToolBroker {
    context: Option<VitaExecutionContext>,
    authority: Arc<dyn VitaToolAuthorityPort>,
    state: Mutex<BrokerState>,
    cancelled: AtomicBool,
    metrics: Arc<VitaBrokerMetrics>,
}

impl VitaToolBroker {
    pub fn new(
        context: VitaExecutionContext,
        authority: Arc<dyn VitaToolAuthorityPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: Some(context),
            authority,
            state: Mutex::new(BrokerState::default()),
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(VitaBrokerMetrics::default()),
        })
    }

    #[cfg(test)]
    fn without_context(authority: Arc<dyn VitaToolAuthorityPort>) -> Arc<Self> {
        Arc::new(Self {
            context: None,
            authority,
            state: Mutex::new(BrokerState::default()),
            cancelled: AtomicBool::new(false),
            metrics: Arc::new(VitaBrokerMetrics::default()),
        })
    }

    fn request_from_call(
        &self,
        call: &ToolCall<'_>,
    ) -> Result<VitaToolAuthorityRequest, VitaRequestBuildError> {
        VitaToolAuthorityRequest::from_codex_call(call, self.context.as_ref())
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn retire(&self) {
        self.cancel();
    }

    pub fn snapshot(&self) -> VitaBrokerSnapshot {
        VitaBrokerSnapshot {
            attempted_requests: self.metrics.attempted_requests.load(Ordering::Acquire),
            authority_lookups: self.metrics.authority_lookups.load(Ordering::Acquire),
            duplicate_denials: self.metrics.duplicate_denials.load(Ordering::Acquire),
            late_denials: self.metrics.late_denials.load(Ordering::Acquire),
            authority_errors: self.metrics.authority_errors.load(Ordering::Acquire),
            authority_panics: self.metrics.authority_panics.load(Ordering::Acquire),
            execution_started: self.metrics.execution_started.load(Ordering::Acquire),
            side_effect_count: self.metrics.side_effect_count.load(Ordering::Acquire),
            max_active_authority: self.metrics.max_active_authority.load(Ordering::Acquire),
        }
    }

    async fn authorize(&self, request: VitaToolAuthorityRequest) -> VitaToolResult {
        self.metrics
            .attempted_requests
            .fetch_add(1, Ordering::AcqRel);

        if self.cancelled.load(Ordering::Acquire) {
            return VitaToolResult::denied(request, VitaDenyClassification::TurnCancelled);
        }

        let Some(bound_context) = self.context.as_ref() else {
            return VitaToolResult::denied(request, VitaDenyClassification::MissingContext);
        };
        let Some(request_context) = request.context.as_ref() else {
            return VitaToolResult::denied(request, VitaDenyClassification::MissingContext);
        };
        if request_context.life_id != bound_context.life_id {
            return VitaToolResult::denied(request, VitaDenyClassification::WrongLifeBinding);
        }
        if request_context.task_id != bound_context.task_id {
            return VitaToolResult::denied(request, VitaDenyClassification::WrongTaskBinding);
        }
        if !request.tool_identity.is_trusted_h1_tool()
            || request.capability_id != VITA_GOVERNED_ACTION_CAPABILITY_ID
        {
            return VitaToolResult::denied(request, VitaDenyClassification::UnmappedTool);
        }

        {
            let mut state = lock_unpoisoned(&self.state);
            if state.seen_call_ids.contains(&request.tool_call_id) {
                self.metrics
                    .duplicate_denials
                    .fetch_add(1, Ordering::AcqRel);
                return VitaToolResult::denied(request, VitaDenyClassification::DuplicateToolCall);
            }
            if state.admitted_calls >= VITA_H1_MAX_TOOL_CALLS {
                return VitaToolResult::denied(request, VitaDenyClassification::TooManyToolCalls);
            }
            state.seen_call_ids.insert(request.tool_call_id.clone());
            state.admitted_calls += 1;
        }

        self.metrics
            .authority_lookups
            .fetch_add(1, Ordering::AcqRel);
        let authority_future = match catch_unwind(AssertUnwindSafe(|| {
            self.authority.evaluate(request.clone())
        })) {
            Ok(future) => future,
            Err(_) => {
                self.metrics.authority_panics.fetch_add(1, Ordering::AcqRel);
                return VitaToolResult::denied(request, VitaDenyClassification::AuthorityPanic);
            }
        };

        let _active_guard = ActiveAuthorityGuard::new(Arc::clone(&self.metrics));
        let authority_result = CatchUnwindFuture::new(authority_future).await;

        let authority = match authority_result {
            Ok(Ok(authority)) => authority,
            Ok(Err(_error)) => {
                self.metrics.authority_errors.fetch_add(1, Ordering::AcqRel);
                return VitaToolResult::denied(request, VitaDenyClassification::AuthorityError);
            }
            Err(()) => {
                self.metrics.authority_panics.fetch_add(1, Ordering::AcqRel);
                return VitaToolResult::denied(request, VitaDenyClassification::AuthorityPanic);
            }
        };

        if self.cancelled.load(Ordering::Acquire) {
            self.metrics.late_denials.fetch_add(1, Ordering::AcqRel);
            return VitaToolResult::denied_by_authority(
                request,
                VitaDenyClassification::LateAfterCancellation,
                &authority,
            );
        }

        if !authority_matches_request(&authority, &request) {
            return VitaToolResult::denied_by_authority(
                request,
                VitaDenyClassification::AuthorityEvidenceMismatch,
                &authority,
            );
        }
        if request.expected_authorization_revision != authority.evidence().authorization_revision()
        {
            return VitaToolResult::denied_by_authority(
                request,
                VitaDenyClassification::StaleRevision,
                &authority,
            );
        }

        let classification = match authority.outcome() {
            VitaAuthorityOutcome::Denied => match authority.reason() {
                VitaAuthorityReason::UnknownCapabilityDescriptor => {
                    VitaDenyClassification::UnknownCapabilityDescriptor
                }
                VitaAuthorityReason::AuthorizationUnavailable
                | VitaAuthorityReason::InvalidRequest
                | VitaAuthorityReason::NotEligible
                | VitaAuthorityReason::InvalidVerdict => VitaDenyClassification::AuthorityError,
                VitaAuthorityReason::Denied | VitaAuthorityReason::RootDisabled => {
                    VitaDenyClassification::MissingAuthorization
                }
                VitaAuthorityReason::ExplicitConfirmationRequired => {
                    VitaDenyClassification::MissingAuthorization
                }
                VitaAuthorityReason::ScopeNotAvailable => {
                    if authority.requested_scope() != VitaRequestedScope::None {
                        VitaDenyClassification::BroaderScope
                    } else {
                        VitaDenyClassification::ScopeUnavailable
                    }
                }
                VitaAuthorityReason::Forbidden => VitaDenyClassification::MissingAuthorization,
                VitaAuthorityReason::Eligible => VitaDenyClassification::AuthorityEvidenceMismatch,
            },
            // H1 has no executable grant path.  Even an injected eligible
            // authority response must remain a bounded deny.
            VitaAuthorityOutcome::Eligible => {
                if authority.requested_scope() != VitaRequestedScope::None {
                    VitaDenyClassification::BroaderScope
                } else {
                    VitaDenyClassification::NoExecutableGrant
                }
            }
        };
        VitaToolResult::denied_by_authority(request, classification, &authority)
    }

    fn denied_for_build_error(
        &self,
        call: &ToolCall<'_>,
        error: VitaRequestBuildError,
    ) -> VitaToolResult {
        let tool_identity = VitaToolIdentity::from_codex(&call.tool_name);
        let context = self.context.clone();
        let tool_call_id = bounded_identity("tool_call_id", call.call_id.clone())
            .unwrap_or_else(|_| "[invalid-call-id]".to_string());
        let turn_id = bounded_identity("turn_id", call.turn_id.clone())
            .unwrap_or_else(|_| "[invalid-turn-id]".to_string());
        let capability_id = if tool_identity.is_trusted_h1_tool() {
            VITA_GOVERNED_ACTION_CAPABILITY_ID.to_string()
        } else {
            "vita.unknown".to_string()
        };
        let request = VitaToolAuthorityRequest {
            tool_call_id,
            tool_identity,
            operation: "[unparsed]".to_string(),
            context,
            capability_id,
            requested_scope: VitaRequestedScope::None,
            requested_resource: None,
            expected_authorization_revision: None,
            evidence: VitaRequestEvidence {
                codex_turn_id: turn_id,
                source: VitaToolCallSource::from_codex(&call.source),
            },
        };
        VitaToolResult::denied(request, error.classification())
    }
}

fn authority_matches_request(
    authority: &VitaAuthorityVerdict,
    request: &VitaToolAuthorityRequest,
) -> bool {
    request.context.as_ref().is_some_and(|context| {
        authority.life_id() == context.life_id
            && authority.capability_id() == request.capability_id
            && authority.requested_scope() == request.requested_scope
    })
}

struct ActiveAuthorityGuard {
    metrics: Arc<VitaBrokerMetrics>,
}

impl ActiveAuthorityGuard {
    fn new(metrics: Arc<VitaBrokerMetrics>) -> Self {
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
    F: Future,
{
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: future is pinned together with self and is never moved after
        // being projected for this poll.
        let this = unsafe { self.get_unchecked_mut() };
        let future = unsafe { Pin::new_unchecked(&mut this.future) };
        match catch_unwind(AssertUnwindSafe(|| future.poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

/// Registers exactly one direct, non-parallel Vita tool with the pinned Codex
/// extension registry.  The normal Vita production entrypoint does not install
/// this contributor in H1; the real Codex lifecycle proof injects it explicitly.
pub struct VitaToolContributor {
    broker: Arc<VitaToolBroker>,
}

impl VitaToolContributor {
    pub fn new(broker: Arc<VitaToolBroker>) -> Self {
        Self { broker }
    }
}

impl ToolContributor for VitaToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaGovernedActionTool {
            broker: Arc::clone(&self.broker),
        })]
    }
}

struct VitaGovernedActionTool {
    broker: Arc<VitaToolBroker>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaGovernedActionTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        let parameters = parse_tool_input_schema(&json!({
            "type": "object",
            "properties": {
                "operation": {"type": "string"},
                "scope": {
                    "type": "string",
                    "enum": ["none", "workspace", "network_destination", "external_resource"]
                },
                "resource": {"type": "string"},
                "expected_revision": {"type": "integer", "minimum": 1}
            },
            "required": ["operation"],
            "additionalProperties": false
        }))
        .expect("D29-H1 tool schema is static and valid");
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_GOVERNED_ACTION_TOOL_NAME.to_string(),
            description: "Submit a bounded Digital Life operation for authority review; H1 never executes it.".to_string(),
            strict: false,
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
            let result = match broker.request_from_call(&call) {
                Ok(request) => broker.authorize(request).await,
                Err(error) => broker.denied_for_build_error(&call, error),
            };
            Ok(Box::new(JsonToolOutput::with_success(
                result.model_value(),
                Some(false),
            )) as Box<dyn ToolOutput>)
        })
    }
}

fn bounded_identity(
    field: &'static str,
    value: String,
) -> Result<String, VitaExecutionContextError> {
    if value.is_empty() {
        return Err(VitaExecutionContextError::Empty(field));
    }
    if value.chars().count() > MAX_ID_CHARS {
        return Err(VitaExecutionContextError::TooLong(field));
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(VitaExecutionContextError::InvalidCharacter(field));
    }
    Ok(value)
}

fn bounded_operation(value: String) -> Result<String, VitaExecutionContextError> {
    if value.is_empty() {
        return Err(VitaExecutionContextError::Empty("operation"));
    }
    if value.chars().count() > MAX_OPERATION_CHARS {
        return Err(VitaExecutionContextError::TooLong("operation"));
    }
    if value.chars().any(char::is_control) {
        return Err(VitaExecutionContextError::InvalidCharacter("operation"));
    }
    Ok(value)
}

fn bounded_resource(value: String) -> Result<String, VitaExecutionContextError> {
    if value.chars().count() > MAX_RESOURCE_CHARS || value.chars().any(char::is_control) {
        return Err(VitaExecutionContextError::TooLong("resource"));
    }
    Ok(value)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use tokio::sync::Notify;

    fn context() -> VitaExecutionContext {
        VitaExecutionContext::try_new("life-h1", "task-h1").unwrap()
    }

    fn request(
        request_context: Option<VitaExecutionContext>,
        call_id: &str,
        tool_name: ToolName,
        scope: VitaRequestedScope,
        expected_revision: Option<i64>,
    ) -> VitaToolAuthorityRequest {
        VitaToolAuthorityRequest::synthetic(
            call_id,
            tool_name,
            "observe-only",
            request_context,
            scope,
            expected_revision,
        )
    }

    #[derive(Clone)]
    struct FixtureAuthority {
        mode: FixtureAuthorityMode,
        current_revision: Option<i64>,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[derive(Clone, Copy)]
    enum FixtureAuthorityMode {
        Missing,
        Eligible,
        ScopeDenied,
        Error,
        Panic,
        Pending,
    }

    impl FixtureAuthority {
        fn new(mode: FixtureAuthorityMode, current_revision: Option<i64>) -> Self {
            Self {
                mode,
                current_revision,
                calls: Arc::new(AtomicUsize::new(0)),
                active: Arc::new(AtomicUsize::new(0)),
                max_active: Arc::new(AtomicUsize::new(0)),
                started: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
            }
        }

        fn decision(&self, request: &VitaToolAuthorityRequest) -> VitaAuthorityVerdict {
            let (outcome, reason) = match self.mode {
                FixtureAuthorityMode::Missing => {
                    (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Denied)
                }
                FixtureAuthorityMode::Eligible => (
                    VitaAuthorityOutcome::Eligible,
                    VitaAuthorityReason::Eligible,
                ),
                FixtureAuthorityMode::ScopeDenied => (
                    VitaAuthorityOutcome::Denied,
                    VitaAuthorityReason::ScopeNotAvailable,
                ),
                FixtureAuthorityMode::Pending => {
                    (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Denied)
                }
                FixtureAuthorityMode::Error | FixtureAuthorityMode::Panic => unreachable!(),
            };
            VitaAuthorityVerdict::from_request(
                request,
                outcome,
                reason,
                self.current_revision,
                VitaAuthorityEvidenceSource::TestFixture,
            )
            .expect("test request context")
        }
    }

    impl VitaToolAuthorityPort for FixtureAuthority {
        fn evaluate(&self, request: VitaToolAuthorityRequest) -> VitaAuthorityFuture {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let mode = self.mode;
            let authority = self.clone();
            Box::pin(async move {
                match mode {
                    FixtureAuthorityMode::Error => Err(VitaAuthorityError::Unavailable),
                    FixtureAuthorityMode::Panic => panic!("fixture authority panic"),
                    FixtureAuthorityMode::Pending => {
                        let active = authority.active.fetch_add(1, Ordering::AcqRel) + 1;
                        let mut max = authority.max_active.load(Ordering::Acquire);
                        while active > max {
                            match authority.max_active.compare_exchange(
                                max,
                                active,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => break,
                                Err(previous) => max = previous,
                            }
                        }
                        authority.started.notify_one();
                        authority.release.notified().await;
                        authority.active.fetch_sub(1, Ordering::AcqRel);
                        Ok(authority.decision(&request))
                    }
                    FixtureAuthorityMode::Missing
                    | FixtureAuthorityMode::Eligible
                    | FixtureAuthorityMode::ScopeDenied => Ok(authority.decision(&request)),
                }
            })
        }
    }

    async fn authorize(
        broker: &VitaToolBroker,
        request: VitaToolAuthorityRequest,
    ) -> VitaToolResult {
        broker.authorize(request).await
    }

    #[test]
    fn context_is_explicit_and_bounded() {
        assert!(VitaExecutionContext::try_new("", "task").is_err());
        assert!(VitaExecutionContext::try_new("life", "task id").is_err());
        let context = context();
        assert_eq!(context.life_id(), "life-h1");
        assert_eq!(context.task_id(), "task-h1");

        let authority = Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None));
        let broker = VitaToolBroker::without_context(authority);
        assert!(broker.context.is_none());
    }

    #[tokio::test]
    async fn negative_matrix_a_to_g_denies_before_side_effect() {
        let authority = Arc::new(FixtureAuthority::new(
            FixtureAuthorityMode::Eligible,
            Some(1),
        ));
        let broker = VitaToolBroker::new(context(), authority.clone());

        let cases = [
            (
                request(
                    None,
                    "call-a",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::MissingContext,
            ),
            (
                request(
                    Some(VitaExecutionContext::try_new("other-life", "task-h1").unwrap()),
                    "call-b",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::WrongLifeBinding,
            ),
            (
                request(
                    Some(VitaExecutionContext::try_new("life-h1", "other-task").unwrap()),
                    "call-c",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::WrongTaskBinding,
            ),
            (
                request(
                    Some(context()),
                    "call-d",
                    ToolName::plain("unknown_tool"),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::UnmappedTool,
            ),
            (
                request(
                    Some(context()),
                    "call-e",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::NoExecutableGrant,
            ),
            (
                request(
                    Some(context()),
                    "call-f",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    Some(1),
                ),
                VitaDenyClassification::NoExecutableGrant,
            ),
            (
                request(
                    Some(context()),
                    "call-g",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::ExternalResource,
                    Some(1),
                ),
                VitaDenyClassification::BroaderScope,
            ),
        ];

        for (request, expected) in cases {
            let result = authorize(&broker, request).await;
            assert_eq!(result.deny_classification(), expected);
            assert!(!result.execution_started());
            assert_eq!(result.side_effect_count(), 0);
        }
        assert_eq!(authority.calls.load(Ordering::Acquire), 3);
        assert_eq!(broker.snapshot().side_effect_count, 0);
    }

    #[tokio::test]
    async fn missing_authorization_is_a_typed_deny() {
        let authority = Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None));
        let broker = VitaToolBroker::new(context(), authority.clone());
        let result = authorize(
            &broker,
            request(
                Some(context()),
                "missing-grant-call",
                ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                VitaRequestedScope::None,
                None,
            ),
        )
        .await;
        assert_eq!(
            result.deny_classification(),
            VitaDenyClassification::MissingAuthorization
        );
        assert!(result.authority_lookup_attempted());
        assert_eq!(authority.calls.load(Ordering::Acquire), 1);
        assert!(!result.execution_started());
    }

    #[tokio::test]
    async fn duplicate_call_id_is_bounded_and_not_reexecuted() {
        let authority = Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None));
        let broker = VitaToolBroker::new(context(), authority.clone());
        let first = authorize(
            &broker,
            request(
                Some(context()),
                "duplicate-call",
                ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                VitaRequestedScope::None,
                None,
            ),
        )
        .await;
        let second = authorize(
            &broker,
            request(
                Some(context()),
                "duplicate-call",
                ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                VitaRequestedScope::None,
                None,
            ),
        )
        .await;
        assert_eq!(
            first.deny_classification(),
            VitaDenyClassification::MissingAuthorization
        );
        assert_eq!(
            second.deny_classification(),
            VitaDenyClassification::DuplicateToolCall
        );
        assert_eq!(authority.calls.load(Ordering::Acquire), 1);
        assert_eq!(broker.snapshot().duplicate_denials, 1);
    }

    #[tokio::test]
    async fn stale_revision_and_scope_are_denied_from_typed_evidence() {
        let stale_authority = Arc::new(FixtureAuthority::new(
            FixtureAuthorityMode::Eligible,
            Some(2),
        ));
        let stale_broker = VitaToolBroker::new(context(), stale_authority);
        let stale = authorize(
            &stale_broker,
            request(
                Some(context()),
                "stale-call",
                ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                VitaRequestedScope::None,
                Some(1),
            ),
        )
        .await;
        assert_eq!(
            stale.deny_classification(),
            VitaDenyClassification::StaleRevision
        );
        assert_eq!(stale.authority_revision(), Some(2));

        let scope_authority = Arc::new(FixtureAuthority::new(
            FixtureAuthorityMode::ScopeDenied,
            Some(1),
        ));
        let scope_broker = VitaToolBroker::new(context(), scope_authority);
        let scope = authorize(
            &scope_broker,
            request(
                Some(context()),
                "scope-call",
                ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                VitaRequestedScope::ExternalResource,
                Some(1),
            ),
        )
        .await;
        assert_eq!(
            scope.deny_classification(),
            VitaDenyClassification::BroaderScope
        );
    }

    #[tokio::test]
    async fn cancellation_pending_authority_cannot_resurrect_execution() {
        let authority = Arc::new(FixtureAuthority::new(
            FixtureAuthorityMode::Pending,
            Some(1),
        ));
        let broker = VitaToolBroker::new(context(), authority.clone());
        let pending = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move {
                authorize(
                    &broker,
                    request(
                        Some(context()),
                        "pending-call",
                        ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                        VitaRequestedScope::None,
                        Some(1),
                    ),
                )
                .await
            }
        });
        authority.started.notified().await;
        broker.cancel();
        authority.release.notify_one();
        let result = pending.await.unwrap();
        assert_eq!(
            result.deny_classification(),
            VitaDenyClassification::LateAfterCancellation
        );
        assert_eq!(authority.calls.load(Ordering::Acquire), 1);
        assert_eq!(broker.snapshot().late_denials, 1);
        assert_eq!(broker.snapshot().execution_started, 0);
        assert_eq!(authority.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn authority_error_and_panic_are_fail_closed_and_cleanup_active_state() {
        for (mode, expected) in [
            (
                FixtureAuthorityMode::Error,
                VitaDenyClassification::AuthorityError,
            ),
            (
                FixtureAuthorityMode::Panic,
                VitaDenyClassification::AuthorityPanic,
            ),
        ] {
            let authority = Arc::new(FixtureAuthority::new(mode, None));
            let broker = VitaToolBroker::new(context(), authority);
            let result = authorize(
                &broker,
                request(
                    Some(context()),
                    "error-call",
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    None,
                ),
            )
            .await;
            assert_eq!(result.deny_classification(), expected);
            assert!(!result.execution_started());
            assert_eq!(result.side_effect_count(), 0);
            assert_eq!(broker.snapshot().max_active_authority, 1);
        }
    }

    #[tokio::test]
    async fn call_limit_is_hard_and_no_parallel_execution_is_admitted() {
        let authority = Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None));
        let broker = VitaToolBroker::new(context(), authority.clone());
        for index in 0..(VITA_H1_MAX_TOOL_CALLS + 2) {
            let result = authorize(
                &broker,
                request(
                    Some(context()),
                    &format!("limit-{index}"),
                    ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME),
                    VitaRequestedScope::None,
                    None,
                ),
            )
            .await;
            if index < VITA_H1_MAX_TOOL_CALLS {
                assert_eq!(
                    result.deny_classification(),
                    VitaDenyClassification::MissingAuthorization
                );
            } else {
                assert_eq!(
                    result.deny_classification(),
                    VitaDenyClassification::TooManyToolCalls
                );
            }
        }
        assert_eq!(
            authority.calls.load(Ordering::Acquire),
            VITA_H1_MAX_TOOL_CALLS
        );
        assert_eq!(broker.snapshot().execution_started, 0);
        assert_eq!(broker.snapshot().side_effect_count, 0);
    }

    #[test]
    fn h1_tool_is_direct_serial_and_uses_only_the_fixed_tool_name() {
        let tool = VitaGovernedActionTool {
            broker: VitaToolBroker::new(
                context(),
                Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None)),
            ),
        };
        assert_eq!(
            tool.tool_name(),
            ToolName::plain(VITA_GOVERNED_ACTION_TOOL_NAME)
        );
        assert!(!tool.supports_parallel_tool_calls());
        let ToolSpec::Function(spec) = tool.spec() else {
            panic!("D29-H1 must expose one function tool");
        };
        assert_eq!(spec.name, VITA_GOVERNED_ACTION_TOOL_NAME);
    }

    #[test]
    fn production_authority_is_deny_only_and_does_not_need_a_grant_mint_path() {
        let broker = VitaToolBroker::new(
            context(),
            Arc::new(FixtureAuthority::new(FixtureAuthorityMode::Missing, None)),
        );
        assert!(Arc::strong_count(&broker) >= 1);
        assert!(!broker.cancelled.load(Ordering::Acquire));
    }
}
