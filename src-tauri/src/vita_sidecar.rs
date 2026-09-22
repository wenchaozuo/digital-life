//! D29-H8-R1 Host boundary for the process-isolated Vita sidecar.
//!
//! The Host owns the lifecycle, the D28 SQLite read, confirmation state, and
//! the short-lived grant ledger.  Vita receives only the bounded protocol
//! DTOs; no provider credential, SQLite handle, or Codex crate crosses this
//! module boundary.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime, State};
use vita_agent_protocol as protocol;

#[cfg(windows)]
use crate::secrets::{SecretIdentifier, SecretStore, WindowsCredentialSecretStore};
use crate::{
    capability::CapabilityRegistry,
    model::profile::{credential_purpose, ModelProfileRepository, ModelProviderKind, ModelPurpose},
    storage::{StorageError, StorageService, CAPABILITY_AUTHORITY_RESTART_REQUIRED},
};

fn capability_authorization_gate_error(error: StorageError) -> String {
    match error.code.as_str() {
        CAPABILITY_AUTHORITY_RESTART_REQUIRED => CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string(),
        "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE" => error.code,
        _ => "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string(),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VitaSidecarStartRequest {
    /// The Life ID observed by the caller.  This is an optimistic stale-intent
    /// fence only; the Host reads and owns the current Life at command entry.
    pub life_id: String,
    pub task_id: String,
    pub workspace_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarStartResponse {
    pub session_id: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VitaTurnStartRequest {
    pub prompt: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaTurnStartResponse {
    pub turn_id: String,
    pub accepted: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VitaProviderReadiness {
    NoActiveProfile,
    CredentialMissing,
    IneligibleUrl,
    Ready,
    SidecarNotRunning,
    SidecarRestartRequired,
    TurnActive,
}

/// Display-safe readiness for the one production governed capability exposed
/// by the Vita panel.  This is intentionally separate from provider readiness:
/// a healthy provider does not imply that the D30 authorization root is on.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VitaCapabilityReadiness {
    RootEnabled,
    RootDisabled,
    AuthorizationMissing,
    AuthorizationUnavailable,
    LifeRestartRequired,
}

/// Display-only projection of one trusted registry entry.  This is never an
/// authority token: every tool lane independently performs its own fresh
/// Host-side evaluation before it can obtain a grant.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VitaCapabilityState {
    pub capability_id: String,
    pub readiness: VitaCapabilityReadiness,
    pub revision: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarPendingSummary {
    pub pending_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub workspace_summary: String,
    pub expires_at_unix_ms: u64,
}

/// Read-only restart evidence surfaced by Vita before any recovery action is
/// selected.  The Host exposes only this bounded summary; target bytes and
/// journal material remain inside Vita's retained namespace.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarRecoveryPendingSummary {
    pub transaction_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub relative_path: String,
    pub current_sha256: String,
    pub restore_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarStatusResponse {
    pub running: bool,
    pub provider_readiness: VitaProviderReadiness,
    pub capability_readiness: VitaCapabilityReadiness,
    pub capability_states: Vec<VitaCapabilityState>,
    pub session_life_id: Option<String>,
    pub current_life_id: Option<String>,
    pub session_id: Option<String>,
    pub pending: Option<VitaSidecarPendingSummary>,
    pub recovery_pending: Vec<VitaSidecarRecoveryPendingSummary>,
    pub recovery_result: Option<protocol::RecoveryResult>,
    pub active_turn_id: Option<String>,
    pub turn_phase: Option<protocol::TurnPhase>,
    pub assistant_text: Option<String>,
    pub turn_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarActionResponse {
    pub accepted: bool,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum D32HostCanaryMode {
    Positive,
    GrantReplay,
    RevokeBeforeRevalidation,
    LifeBeforeRevalidation,
    CancelBeforeRevalidation,
    MigrationBeforeRevalidation,
    ExecutableIdentityTamper,
    EnvironmentProfileTamper,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32HostCanaryMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "" | "positive" | "Positive" => Ok(Self::Positive),
            "grant-replay" | "grant_replay" | "GrantReplay" => Ok(Self::GrantReplay),
            "revoke"
            | "revoke-before-revalidation"
            | "revoke_before_revalidation"
            | "Revoke"
            | "RevokeBeforeRevalidation" => Ok(Self::RevokeBeforeRevalidation),
            "life"
            | "life-before-revalidation"
            | "life_before_revalidation"
            | "Life"
            | "LifeBeforeRevalidation" => Ok(Self::LifeBeforeRevalidation),
            "cancel"
            | "cancel-before-revalidation"
            | "cancel_before_revalidation"
            | "Cancel"
            | "CancelBeforeRevalidation" => Ok(Self::CancelBeforeRevalidation),
            "migration"
            | "migration-before-revalidation"
            | "migration_before_revalidation"
            | "Migration"
            | "MigrationBeforeRevalidation" => Ok(Self::MigrationBeforeRevalidation),
            "executable-identity-tamper"
            | "executable_identity_tamper"
            | "ExecutableIdentityTamper" => Ok(Self::ExecutableIdentityTamper),
            "environment-profile-tamper"
            | "environment_profile_tamper"
            | "EnvironmentProfileTamper" => Ok(Self::EnvironmentProfileTamper),
            other => Err(format!(
                "D32_A_NOT_EXECUTABLE: unsupported canary mode '{other}'"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::GrantReplay => "grant-replay",
            Self::RevokeBeforeRevalidation => "revoke-before-revalidation",
            Self::LifeBeforeRevalidation => "life-before-revalidation",
            Self::CancelBeforeRevalidation => "cancel-before-revalidation",
            Self::MigrationBeforeRevalidation => "migration-before-revalidation",
            Self::ExecutableIdentityTamper => "executable-identity-tamper",
            Self::EnvironmentProfileTamper => "environment-profile-tamper",
        }
    }

    fn expects_deny(self) -> bool {
        !matches!(self, Self::Positive)
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
const D32_STAGE_COUNTER_MAX: u8 = 16;

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum D32HostCanaryStage {
    Layout,
    Catalog,
    Sandbox,
    ActionPrepare,
    ScopeAuthority,
    Populate,
    ConfirmationBridge,
    Grant,
    Revalidate,
    Evidence,
    Cleanup,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32HostCanaryStage {
    const ALL: [Self; 11] = [
        Self::Layout,
        Self::Catalog,
        Self::Sandbox,
        Self::ActionPrepare,
        Self::ScopeAuthority,
        Self::Populate,
        Self::ConfirmationBridge,
        Self::Grant,
        Self::Revalidate,
        Self::Evidence,
        Self::Cleanup,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Layout => "layout",
            Self::Catalog => "catalog",
            Self::Sandbox => "sandbox",
            Self::ActionPrepare => "action_prepare",
            Self::ScopeAuthority => "scope_authority",
            Self::Populate => "populate",
            Self::ConfirmationBridge => "confirmation_bridge",
            Self::Grant => "grant",
            Self::Revalidate => "revalidate",
            Self::Evidence => "evidence",
            Self::Cleanup => "cleanup",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "layout" => Some(Self::Layout),
            "catalog" => Some(Self::Catalog),
            "sandbox" => Some(Self::Sandbox),
            "action_prepare" => Some(Self::ActionPrepare),
            "scope_authority" => Some(Self::ScopeAuthority),
            "populate" => Some(Self::Populate),
            "confirmation_bridge" => Some(Self::ConfirmationBridge),
            "grant" => Some(Self::Grant),
            "revalidate" => Some(Self::Revalidate),
            "evidence" => Some(Self::Evidence),
            "cleanup" => Some(Self::Cleanup),
            _ => None,
        }
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum D32StageFailureCode {
    OperationFailed,
    NotObserved,
    Fixture,
    LedgerCapacity,
    NativeDenied,
    WorkerJoin,
    ReplayMetric,
    Cancellation,
    InvalidCall,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32StageFailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::OperationFailed => "operation_failed",
            Self::NotObserved => "not_observed",
            Self::Fixture => "fixture",
            Self::LedgerCapacity => "ledger_capacity",
            Self::NativeDenied => "native_denied",
            Self::WorkerJoin => "worker_join",
            Self::ReplayMetric => "replay_metric",
            Self::Cancellation => "cancellation",
            Self::InvalidCall => "invalid_call",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "operation_failed" => Some(Self::OperationFailed),
            "not_observed" => Some(Self::NotObserved),
            "fixture" => Some(Self::Fixture),
            "ledger_capacity" => Some(Self::LedgerCapacity),
            "native_denied" => Some(Self::NativeDenied),
            "worker_join" => Some(Self::WorkerJoin),
            "replay_metric" => Some(Self::ReplayMetric),
            "cancellation" => Some(Self::Cancellation),
            "invalid_call" => Some(Self::InvalidCall),
            _ => None,
        }
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32StageTelemetryCounters {
    pub started: u8,
    pub passed: u8,
    pub denied: u8,
    pub failed: u8,
    pub last_failure_code: Option<String>,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32StageTelemetrySnapshot {
    pub layout: D32StageTelemetryCounters,
    pub catalog: D32StageTelemetryCounters,
    pub sandbox: D32StageTelemetryCounters,
    pub action_prepare: D32StageTelemetryCounters,
    pub scope_authority: D32StageTelemetryCounters,
    pub populate: D32StageTelemetryCounters,
    pub confirmation_bridge: D32StageTelemetryCounters,
    pub grant: D32StageTelemetryCounters,
    pub revalidate: D32StageTelemetryCounters,
    pub evidence: D32StageTelemetryCounters,
    pub cleanup: D32StageTelemetryCounters,
    pub bridge_sent: u8,
    pub bridge_replied: u8,
    pub bridge_pending: u8,
    pub bridge_pending_active: bool,
    pub bridge_state: String,
    pub bridge_decision: String,
    pub bridge_confirmed: u8,
    pub bridge_denied: u8,
    pub bridge_cancelled: u8,
    pub bridge_timed_out: u8,
    pub bridge_failed: u8,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl Default for D32StageTelemetrySnapshot {
    fn default() -> Self {
        Self {
            layout: D32StageTelemetryCounters::default(),
            catalog: D32StageTelemetryCounters::default(),
            sandbox: D32StageTelemetryCounters::default(),
            action_prepare: D32StageTelemetryCounters::default(),
            scope_authority: D32StageTelemetryCounters::default(),
            populate: D32StageTelemetryCounters::default(),
            confirmation_bridge: D32StageTelemetryCounters::default(),
            grant: D32StageTelemetryCounters::default(),
            revalidate: D32StageTelemetryCounters::default(),
            evidence: D32StageTelemetryCounters::default(),
            cleanup: D32StageTelemetryCounters::default(),
            bridge_sent: 0,
            bridge_replied: 0,
            bridge_pending: 0,
            bridge_pending_active: false,
            bridge_state: "idle".to_string(),
            bridge_decision: "none".to_string(),
            bridge_confirmed: 0,
            bridge_denied: 0,
            bridge_cancelled: 0,
            bridge_timed_out: 0,
            bridge_failed: 0,
        }
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32StageTelemetrySnapshot {
    fn counters_mut(&mut self, stage: D32HostCanaryStage) -> &mut D32StageTelemetryCounters {
        match stage {
            D32HostCanaryStage::Layout => &mut self.layout,
            D32HostCanaryStage::Catalog => &mut self.catalog,
            D32HostCanaryStage::Sandbox => &mut self.sandbox,
            D32HostCanaryStage::ActionPrepare => &mut self.action_prepare,
            D32HostCanaryStage::ScopeAuthority => &mut self.scope_authority,
            D32HostCanaryStage::Populate => &mut self.populate,
            D32HostCanaryStage::ConfirmationBridge => &mut self.confirmation_bridge,
            D32HostCanaryStage::Grant => &mut self.grant,
            D32HostCanaryStage::Revalidate => &mut self.revalidate,
            D32HostCanaryStage::Evidence => &mut self.evidence,
            D32HostCanaryStage::Cleanup => &mut self.cleanup,
        }
    }

    fn increment(counter: &mut u8) {
        *counter = counter.saturating_add(1).min(D32_STAGE_COUNTER_MAX);
    }

    fn mark_started(&mut self, stage: D32HostCanaryStage) {
        Self::increment(&mut self.counters_mut(stage).started);
    }

    fn mark_passed(&mut self, stage: D32HostCanaryStage) {
        Self::increment(&mut self.counters_mut(stage).passed);
    }

    fn mark_denied(&mut self, stage: D32HostCanaryStage) {
        Self::increment(&mut self.counters_mut(stage).denied);
    }

    fn mark_failed(&mut self, stage: D32HostCanaryStage, code: D32StageFailureCode) {
        let counters = self.counters_mut(stage);
        Self::increment(&mut counters.failed);
        counters.last_failure_code = Some(code.as_str().to_string());
    }

    fn mark_failed_at_least(&mut self, stage: D32HostCanaryStage, code: D32StageFailureCode) {
        let counters = self.counters_mut(stage);
        counters.failed = counters.failed.max(1).min(D32_STAGE_COUNTER_MAX);
        counters.last_failure_code = Some(code.as_str().to_string());
    }

    fn mark_denied_at_least(&mut self, stage: D32HostCanaryStage) {
        let counters = self.counters_mut(stage);
        counters.denied = counters.denied.max(1).min(D32_STAGE_COUNTER_MAX);
    }

    fn merge_vita_stage_trace(&mut self, trace: &[D32VitaStageTrace]) {
        for entry in trace {
            let counters = self.counters_mut(entry.stage);
            counters.started = counters
                .started
                .max(entry.started)
                .min(D32_STAGE_COUNTER_MAX);
            counters.passed = counters.passed.max(entry.passed).min(D32_STAGE_COUNTER_MAX);
            counters.failed = counters.failed.max(entry.failed).min(D32_STAGE_COUNTER_MAX);
        }
    }

    fn mark_vita_failure_event(&mut self, stage: D32HostCanaryStage, code: D32StageFailureCode) {
        if matches!(
            code,
            D32StageFailureCode::NotObserved | D32StageFailureCode::Fixture
        ) {
            self.mark_denied_at_least(stage);
        } else {
            self.mark_failed_at_least(stage, code);
        }
    }

    fn mark_vita_failure(&mut self, diagnostic: &D32VitaSafeStageDiagnostic) {
        self.merge_vita_stage_trace(&diagnostic.stage_trace);
        let mut marked = false;
        if let (Some(stage), Some(code)) = (diagnostic.primary_stage, diagnostic.primary_code) {
            self.mark_vita_failure_event(stage, code);
            marked = true;
        }
        if let (Some(stage), Some(code)) = (diagnostic.secondary_stage, diagnostic.secondary_code) {
            self.mark_vita_failure_event(stage, code);
            marked = true;
        }
        if !marked {
            self.mark_vita_failure_event(diagnostic.stage, diagnostic.code);
        }
        self.merge_vita_bridge(
            diagnostic.bridge_sent,
            diagnostic.bridge_pending,
            diagnostic.bridge_replied,
            diagnostic.bridge_pending_active,
            &diagnostic.bridge_decision,
            diagnostic.bridge_confirmed,
            diagnostic.bridge_denied,
            diagnostic.bridge_cancelled,
            diagnostic.bridge_timed_out,
            diagnostic.bridge_failed,
        );
    }

    fn bridge_sent(&mut self) {
        Self::increment(&mut self.bridge_sent);
        self.bridge_state = "sent".to_string();
    }

    fn bridge_pending(&mut self) {
        if !self.bridge_pending_active {
            Self::increment(&mut self.bridge_pending);
        }
        self.bridge_pending_active = true;
        self.bridge_state = "pending".to_string();
    }

    fn bridge_replied(&mut self, decision: D32BridgeDecision) {
        Self::increment(&mut self.bridge_replied);
        self.bridge_pending_active = false;
        self.bridge_state = "replied".to_string();
        self.bridge_decision = decision.as_str().to_string();
        match decision {
            D32BridgeDecision::Confirm => Self::increment(&mut self.bridge_confirmed),
            D32BridgeDecision::Deny => Self::increment(&mut self.bridge_denied),
            D32BridgeDecision::Cancel => Self::increment(&mut self.bridge_cancelled),
            D32BridgeDecision::Timeout => Self::increment(&mut self.bridge_timed_out),
            D32BridgeDecision::Error => Self::increment(&mut self.bridge_failed),
        }
    }

    fn merge_vita_bridge(
        &mut self,
        sent: u8,
        pending: u8,
        replied: u8,
        pending_active: bool,
        decision: &str,
        confirmed: u8,
        denied: u8,
        cancelled: u8,
        timed_out: u8,
        failed: u8,
    ) {
        self.bridge_sent = self.bridge_sent.max(sent).min(D32_STAGE_COUNTER_MAX);
        self.bridge_pending = self.bridge_pending.max(pending).min(D32_STAGE_COUNTER_MAX);
        self.bridge_replied = self.bridge_replied.max(replied).min(D32_STAGE_COUNTER_MAX);
        self.bridge_pending_active = pending_active;
        self.bridge_decision = decision.to_string();
        self.bridge_confirmed = self
            .bridge_confirmed
            .max(confirmed)
            .min(D32_STAGE_COUNTER_MAX);
        self.bridge_denied = self.bridge_denied.max(denied).min(D32_STAGE_COUNTER_MAX);
        self.bridge_cancelled = self
            .bridge_cancelled
            .max(cancelled)
            .min(D32_STAGE_COUNTER_MAX);
        self.bridge_timed_out = self
            .bridge_timed_out
            .max(timed_out)
            .min(D32_STAGE_COUNTER_MAX);
        self.bridge_failed = self.bridge_failed.max(failed).min(D32_STAGE_COUNTER_MAX);
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum D32BridgeDecision {
    Confirm,
    Deny,
    Cancel,
    Timeout,
    Error,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32BridgeDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Deny => "deny",
            Self::Cancel => "cancel",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32HostCanaryTraceSnapshot {
    pub authority_evaluate: u64,
    pub confirmation_required: u64,
    pub issue_grant: u64,
    pub revalidate_grant: u64,
    pub grant_revalidated_allowed: u64,
    pub grant_revalidated_denied: u64,
    pub grant_denial_code: Option<String>,
    pub turn_completed: u64,
    pub turn_failed: u64,
    pub action_cancelled: u64,
    pub replay_checked: bool,
    pub replay_denied: bool,
    pub replay_exact_request_count: u64,
    pub replay_exact_session_count: u64,
    pub replay_first_allowed: u64,
    pub replay_second_denied: u64,
    pub replay_wire_responses: u64,
    pub pre_native_fence_seen: bool,
    pub tamper_denied: bool,
    pub revoke_applied: bool,
    pub life_switch_applied: bool,
    pub isolated_migration_applied: bool,
    pub exact_capability: bool,
    pub exact_tool: bool,
    pub exact_profile: bool,
    pub exact_cargo_check: bool,
    pub binding_fields_validated: bool,
    pub native_evidence_run_id: Option<String>,
    pub native_evidence_session_id: Option<String>,
    pub native_evidence_life_id: Option<String>,
    pub native_evidence_task_id: Option<String>,
    pub native_evidence_turn_id: Option<String>,
    pub native_evidence_tool_call_id: Option<String>,
    pub native_diagnostic: Option<D32NativeSafeDiagnostic>,
    pub stage_telemetry: D32StageTelemetrySnapshot,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32NativeSafeDiagnostic {
    pub phase: String,
    pub round: String,
    pub attempts: Option<u8>,
    pub http_status: Option<u16>,
    pub error_code: String,
    pub output_kind: String,
    pub content_type_is_json: bool,
    pub gateway_requests: u8,
    pub provider_results: u8,
    pub sse_created: u8,
    pub sse_failed: u8,
    pub sse_completed: u8,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32CleanupOutcome {
    pub attempted: bool,
    pub validated: bool,
    pub removed: bool,
    pub unsafe_left: bool,
    pub error: Option<String>,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn d32_cleanup_summary(cleanup: &D32CleanupOutcome) -> String {
    format!(
        "attempted={} validated={} removed={} unsafe_left={} error_present={}",
        cleanup.attempted,
        cleanup.validated,
        cleanup.removed,
        cleanup.unsafe_left,
        cleanup.error.is_some(),
    )
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn d32_host_error_code(error: &str) -> &'static str {
    if error.contains("cleanup") {
        "cleanup"
    } else if error.contains("clear") {
        "clear"
    } else if error.contains("trace") {
        "trace"
    } else if error.contains("evidence") {
        "evidence"
    } else if error.contains("turn") || error.contains("provider") {
        "turn"
    } else {
        "host_failure"
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn d32_failure_context(
    control: &D32HostCanaryControl,
    error: &str,
    cleanup: Option<&D32CleanupOutcome>,
    clear_failed: bool,
) -> String {
    let trace = control.trace.snapshot();
    let cleanup = cleanup.map_or_else(|| "none".to_string(), d32_cleanup_summary);
    format!(
        "D32_A_HOST_FAILURE: error_code={} clear_failed={} d32_stage_telemetry={} d32_native_diagnostic={} d32_cleanup={}",
        d32_host_error_code(error),
        clear_failed,
        d32_stage_telemetry_summary(&trace),
        d32_native_diagnostic_summary(&trace),
        cleanup,
    )
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32HostCanaryReport {
    pub mode: String,
    pub status: String,
    pub trace: D32HostCanaryTraceSnapshot,
    pub native_evidence: D32NativeEvidenceReport,
    pub terminal_phase: Option<protocol::TurnPhase>,
    pub turn_error: Option<String>,
    pub native_diagnostic: Option<D32NativeSafeDiagnostic>,
    pub cleanup: D32CleanupOutcome,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct D32NativeEvidenceReport {
    pub record: serde_json::Value,
    pub sha256: String,
    pub identity: String,
    pub bytes: u64,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn parse_d32_native_safe_diagnostic(message: &str) -> Option<D32NativeSafeDiagnostic> {
    const PREFIX: &str = "D32 native Responses rejected";
    let start = message.find(PREFIX)? + PREFIX.len();
    let mut fields = std::collections::HashMap::new();
    for token in message[start..].split_ascii_whitespace() {
        let (key, value) = token.split_once('=')?;
        if fields.insert(key, value).is_some() {
            return None;
        }
    }
    let allowed_phase = |value: &str| {
        matches!(
            value,
            "policy_gate"
                | "request_contract"
                | "second_round_request"
                | "credential_resolution"
                | "dns"
                | "connect"
                | "transport"
                | "http_status"
                | "response_headers"
                | "response_json"
                | "response_model"
                | "expected_tool"
                | "finish_reason"
                | "turn_terminal"
        )
    };
    let allowed_error_code = |value: &str| {
        matches!(
            value,
            "policy_mismatch"
                | "capability"
                | "request_invalid"
                | "credential"
                | "dns"
                | "connect"
                | "transport"
                | "http_status"
                | "content_type"
                | "invalid_json"
                | "response_shape"
                | "response_identity"
                | "output_shape"
                | "usage_shape"
                | "output_kind"
                | "output_contract"
                | "request_contract"
                | "output_text"
                | "expected_tool"
                | "finish_reason"
                | "turn_failed"
        )
    };
    let allowed_output_kind = |value: &str| {
        matches!(
            value,
            "none" | "unknown" | "function_call" | "message" | "output_text"
        )
    };
    let phase = fields
        .get("phase")
        .copied()
        .filter(|value| allowed_phase(value))?;
    let round = fields
        .get("round")
        .copied()
        .filter(|value| matches!(*value, "initial_request" | "final_request" | "unknown"))?;
    let error_code = fields
        .get("error_code")
        .copied()
        .filter(|value| allowed_error_code(value))?;
    let output_kind = fields
        .get("output_kind")
        .copied()
        .filter(|value| allowed_output_kind(value))?;
    let parse_optional_u16 = |key: &str| {
        let value = fields.get(key).copied()?;
        if value == "none" {
            return Some(None);
        }
        value
            .parse::<u16>()
            .ok()
            .filter(|status| (100..=599).contains(status))
            .map(Some)
    };
    let parse_counter = |key: &str| {
        fields
            .get(key)
            .copied()?
            .parse::<u8>()
            .ok()
            .filter(|value| *value <= 16)
    };
    let attempts = {
        let value = fields.get("attempts").copied()?;
        if value == "none" {
            None
        } else {
            Some(value.parse::<u8>().ok().filter(|value| *value <= 16)?)
        }
    };
    let http_status = parse_optional_u16("http_status")?;
    let content_type_is_json = match fields.get("content_type_is_json").copied()? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    Some(D32NativeSafeDiagnostic {
        phase: phase.to_string(),
        round: round.to_string(),
        attempts,
        http_status,
        error_code: error_code.to_string(),
        output_kind: output_kind.to_string(),
        content_type_is_json,
        gateway_requests: parse_counter("gateway_requests")?,
        provider_results: parse_counter("provider_results")?,
        sse_created: parse_counter("sse_created")?,
        sse_failed: parse_counter("sse_failed")?,
        sse_completed: parse_counter("sse_completed")?,
    })
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct D32VitaStageTrace {
    stage: D32HostCanaryStage,
    started: u8,
    passed: u8,
    failed: u8,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct D32VitaSafeStageDiagnostic {
    stage: D32HostCanaryStage,
    code: D32StageFailureCode,
    primary_stage: Option<D32HostCanaryStage>,
    primary_code: Option<D32StageFailureCode>,
    secondary_stage: Option<D32HostCanaryStage>,
    secondary_code: Option<D32StageFailureCode>,
    stage_trace: Vec<D32VitaStageTrace>,
    bridge_sent: u8,
    bridge_pending: u8,
    bridge_replied: u8,
    bridge_pending_active: bool,
    bridge_decision: String,
    bridge_confirmed: u8,
    bridge_denied: u8,
    bridge_cancelled: u8,
    bridge_timed_out: u8,
    bridge_failed: u8,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn parse_d32_vita_stage_trace(value: &str) -> Option<Vec<D32VitaStageTrace>> {
    if value == "none" {
        return Some(Vec::new());
    }
    let mut seen = std::collections::HashSet::new();
    let mut trace = Vec::new();
    for item in value.split(',') {
        let (stage, counters) = item.split_once(':')?;
        let stage = D32HostCanaryStage::parse(stage)?;
        if !seen.insert(stage.as_str()) {
            return None;
        }
        let values = counters.split('/').collect::<Vec<_>>();
        if values.len() != 3 {
            return None;
        }
        let parse_counter = |value: &str| {
            value
                .parse::<u8>()
                .ok()
                .filter(|value| *value <= D32_STAGE_COUNTER_MAX)
        };
        trace.push(D32VitaStageTrace {
            stage,
            started: parse_counter(values[0])?,
            passed: parse_counter(values[1])?,
            failed: parse_counter(values[2])?,
        });
    }
    if trace.len() != D32HostCanaryStage::ALL.len()
        || D32HostCanaryStage::ALL
            .iter()
            .any(|stage| !seen.contains(stage.as_str()))
    {
        return None;
    }
    Some(trace)
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn parse_d32_vita_safe_stage_diagnostic(message: &str) -> Option<D32VitaSafeStageDiagnostic> {
    const PREFIX: &str = "D32 Vita stage failure";
    let start = message.find(PREFIX)? + PREFIX.len();
    let mut fields = std::collections::HashMap::new();
    for token in message[start..].split_ascii_whitespace() {
        let (key, value) = token.split_once('=')?;
        if !matches!(
            key,
            "stage"
                | "code"
                | "primary_stage"
                | "primary_code"
                | "secondary_stage"
                | "secondary_code"
                | "stage_trace"
                | "bridge_sent"
                | "bridge_pending"
                | "bridge_replied"
                | "bridge_pending_active"
                | "bridge_decision"
                | "bridge_confirmed"
                | "bridge_denied"
                | "bridge_cancelled"
                | "bridge_timed_out"
                | "bridge_failed"
        ) || fields.insert(key, value).is_some()
        {
            return None;
        }
    }
    let stage = D32HostCanaryStage::parse(fields.get("stage").copied()?)?;
    let code = D32StageFailureCode::parse(fields.get("code").copied()?)?;
    let primary_stage = match (
        fields.get("primary_stage").copied(),
        fields.get("primary_code").copied(),
    ) {
        (None, None) => (Some(stage), Some(code)),
        (Some("none"), Some("none")) => (None, None),
        (Some(stage), Some(code)) => (
            Some(D32HostCanaryStage::parse(stage)?),
            Some(D32StageFailureCode::parse(code)?),
        ),
        _ => return None,
    };
    let secondary_stage = match (
        fields.get("secondary_stage").copied(),
        fields.get("secondary_code").copied(),
    ) {
        (None, None) | (Some("none"), Some("none")) => (None, None),
        (Some(stage), Some(code)) => (
            Some(D32HostCanaryStage::parse(stage)?),
            Some(D32StageFailureCode::parse(code)?),
        ),
        _ => return None,
    };
    let stage_trace =
        parse_d32_vita_stage_trace(fields.get("stage_trace").copied().unwrap_or("none"))?;
    let bridge_pending_active = match fields.get("bridge_pending_active").copied()? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    let bridge_decision = fields.get("bridge_decision").copied()?;
    if !matches!(
        bridge_decision,
        "none" | "confirm" | "deny" | "cancel" | "timeout" | "error"
    ) {
        return None;
    }
    let bounded = |key: &str| {
        fields
            .get(key)
            .copied()?
            .parse::<u8>()
            .ok()
            .filter(|value| *value <= D32_STAGE_COUNTER_MAX)
    };
    Some(D32VitaSafeStageDiagnostic {
        stage,
        code,
        primary_stage: primary_stage.0,
        primary_code: primary_stage.1,
        secondary_stage: secondary_stage.0,
        secondary_code: secondary_stage.1,
        stage_trace,
        bridge_sent: bounded("bridge_sent")?,
        bridge_pending: bounded("bridge_pending")?,
        bridge_replied: bounded("bridge_replied")?,
        bridge_pending_active,
        bridge_decision: bridge_decision.to_string(),
        bridge_confirmed: bounded("bridge_confirmed")?,
        bridge_denied: bounded("bridge_denied")?,
        bridge_cancelled: bounded("bridge_cancelled")?,
        bridge_timed_out: bounded("bridge_timed_out")?,
        bridge_failed: bounded("bridge_failed")?,
    })
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn d32_native_diagnostic_summary(trace: &D32HostCanaryTraceSnapshot) -> String {
    let Some(diagnostic) = trace.native_diagnostic.as_ref() else {
        return "none".to_string();
    };
    format!(
        "phase={} round={} attempts={} http_status={} error_code={} output_kind={} content_type_is_json={} gateway_requests={} provider_results={} sse_created={} sse_failed={} sse_completed={}",
        diagnostic.phase,
        diagnostic.round,
        diagnostic
            .attempts
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        diagnostic
            .http_status
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        diagnostic.error_code,
        diagnostic.output_kind,
        diagnostic.content_type_is_json,
        diagnostic.gateway_requests,
        diagnostic.provider_results,
        diagnostic.sse_created,
        diagnostic.sse_failed,
        diagnostic.sse_completed,
    )
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
fn d32_stage_telemetry_summary(trace: &D32HostCanaryTraceSnapshot) -> String {
    serde_json::to_string(&trace.stage_telemetry)
        .unwrap_or_else(|_| "{\"serialization\":\"failed\"}".to_string())
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
#[derive(Default)]
pub(crate) struct D32HostCanaryTrace {
    snapshot: Mutex<D32HostCanaryTraceSnapshot>,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32HostCanaryTrace {
    fn update(&self, update: impl FnOnce(&mut D32HostCanaryTraceSnapshot)) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            update(&mut snapshot);
        }
    }

    fn snapshot(&self) -> D32HostCanaryTraceSnapshot {
        self.snapshot
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    fn stage_started(&self, stage: D32HostCanaryStage) {
        self.update(|snapshot| snapshot.stage_telemetry.mark_started(stage));
    }

    fn stage_passed(&self, stage: D32HostCanaryStage) {
        self.update(|snapshot| snapshot.stage_telemetry.mark_passed(stage));
    }

    fn stage_denied(&self, stage: D32HostCanaryStage) {
        self.update(|snapshot| snapshot.stage_telemetry.mark_denied(stage));
    }

    fn stage_failed(&self, stage: D32HostCanaryStage, code: D32StageFailureCode) {
        self.update(|snapshot| snapshot.stage_telemetry.mark_failed(stage, code));
    }

    fn bridge_sent(&self) {
        self.update(|snapshot| snapshot.stage_telemetry.bridge_sent());
    }

    fn bridge_pending(&self) {
        self.update(|snapshot| snapshot.stage_telemetry.bridge_pending());
    }

    fn bridge_replied(&self, decision: D32BridgeDecision) {
        self.update(|snapshot| snapshot.stage_telemetry.bridge_replied(decision));
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
pub(crate) struct D32HostCanaryControl {
    pub(crate) mode: D32HostCanaryMode,
    pub(crate) trace: Arc<D32HostCanaryTrace>,
    cancel_signal: Arc<(Mutex<bool>, std::sync::Condvar)>,
    cancel_barrier: Arc<std::sync::Barrier>,
    revoke_restore_revision: Mutex<Option<i64>>,
    replay_capture_enabled: Mutex<bool>,
    replay_captured_response: Mutex<Option<protocol::GrantRevalidated>>,
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl D32HostCanaryControl {
    fn new(mode: D32HostCanaryMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            trace: Arc::new(D32HostCanaryTrace::default()),
            cancel_signal: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
            cancel_barrier: Arc::new(std::sync::Barrier::new(2)),
            revoke_restore_revision: Mutex::new(None),
            replay_capture_enabled: Mutex::new(false),
            replay_captured_response: Mutex::new(None),
        })
    }

    fn wait_for_cancel_signal(&self) {
        let (signal, wake) = &*self.cancel_signal;
        let Ok(mut signal) = signal.lock() else {
            return;
        };
        while !*signal {
            signal = match wake.wait(signal) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        }
    }

    fn signal_cancel_worker(&self) {
        let (signal, wake) = &*self.cancel_signal;
        if let Ok(mut signal) = signal.lock() {
            *signal = true;
            wake.notify_one();
        }
    }

    fn cancel_barrier(&self) -> Arc<std::sync::Barrier> {
        Arc::clone(&self.cancel_barrier)
    }

    fn set_revoke_restore_revision(&self, revision: i64) {
        if let Ok(mut value) = self.revoke_restore_revision.lock() {
            *value = Some(revision);
        }
    }

    fn take_revoke_restore_revision(&self) -> Option<i64> {
        self.revoke_restore_revision
            .lock()
            .ok()
            .and_then(|mut value| value.take())
    }

    fn begin_replay_capture(&self) -> Result<(), String> {
        let mut enabled = self
            .replay_capture_enabled
            .lock()
            .map_err(|_| "D32 replay capture lock was poisoned".to_string())?;
        let captured = self
            .replay_captured_response
            .lock()
            .map_err(|_| "D32 replay response lock was poisoned".to_string())?;
        if *enabled || captured.is_some() {
            return Err("D32 replay capture was already active".to_string());
        }
        *enabled = true;
        Ok(())
    }

    fn capture_replay_response(
        &self,
        response: &protocol::GrantRevalidated,
    ) -> Result<bool, String> {
        let enabled = self
            .replay_capture_enabled
            .lock()
            .map_err(|_| "D32 replay capture lock was poisoned".to_string())?;
        if !*enabled {
            return Ok(false);
        }
        drop(enabled);
        let mut captured = self
            .replay_captured_response
            .lock()
            .map_err(|_| "D32 replay response lock was poisoned".to_string())?;
        if captured.is_some() {
            return Err("D32 replay produced more than one response".to_string());
        }
        *captured = Some(response.clone());
        Ok(true)
    }

    fn finish_replay_capture(&self) -> Result<protocol::GrantRevalidated, String> {
        let mut enabled = self
            .replay_capture_enabled
            .lock()
            .map_err(|_| "D32 replay capture lock was poisoned".to_string())?;
        *enabled = false;
        drop(enabled);
        self.replay_captured_response
            .lock()
            .map_err(|_| "D32 replay response lock was poisoned".to_string())?
            .take()
            .ok_or_else(|| "D32 replay produced no captured response".to_string())
    }
}

pub struct VitaSidecarCoordinator {
    authority_storage: Arc<StorageService>,
    registry: CapabilityRegistry,
    #[cfg(windows)]
    credential_store: WindowsCredentialSecretStore,
    #[cfg(all(windows, test))]
    test_provider_override: Mutex<Option<protocol::ProviderConfiguration>>,
    #[cfg(windows)]
    inner: Mutex<WindowsCoordinatorState>,
    #[cfg(all(windows, feature = "d32-a-host-canary"))]
    d32_host_canary: Mutex<Option<Arc<D32HostCanaryControl>>>,
    #[cfg(not(windows))]
    inner: Mutex<()>,
}

impl VitaSidecarCoordinator {
    pub(crate) fn new(
        authority_storage: Arc<StorageService>,
        registry: CapabilityRegistry,
    ) -> Self {
        Self {
            authority_storage,
            registry,
            #[cfg(windows)]
            credential_store: WindowsCredentialSecretStore::new(),
            #[cfg(all(windows, test))]
            test_provider_override: Mutex::new(None),
            #[cfg(windows)]
            inner: Mutex::new(WindowsCoordinatorState::default()),
            #[cfg(all(windows, feature = "d32-a-host-canary"))]
            d32_host_canary: Mutex::new(None),
            #[cfg(not(windows))]
            inner: Mutex::new(()),
        }
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary"))]
impl VitaSidecarCoordinator {
    pub(crate) fn configure_d32_host_canary(
        &self,
        control: Arc<D32HostCanaryControl>,
    ) -> Result<(), String> {
        let mut configured = self
            .d32_host_canary
            .lock()
            .map_err(|_| "D32 Host canary control lock was poisoned".to_string())?;
        if configured.is_some() {
            return Err("D32 Host canary control was already configured".to_string());
        }
        *configured = Some(control);
        Ok(())
    }

    fn d32_host_canary_control(&self) -> Result<Option<Arc<D32HostCanaryControl>>, String> {
        self.d32_host_canary
            .lock()
            .map(|control| control.clone())
            .map_err(|_| "D32 Host canary control lock was poisoned".to_string())
    }

    pub(crate) fn clear_d32_host_canary(&self) -> Result<(), String> {
        let mut configured = self
            .d32_host_canary
            .lock()
            .map_err(|_| "D32 Host canary control lock was poisoned".to_string())?;
        configured.take();
        Ok(())
    }

    #[cfg(all(windows, feature = "d32-a-host-canary", not(test)))]
    pub(crate) fn d32_a_close_authority_storage_for_canary(&self) -> Result<(), String> {
        self.authority_storage.d32_a_close_for_canary()
    }
}

#[cfg(all(windows, feature = "d32-a-host-canary", not(test)))]
pub(crate) fn run_d32_a_host_integration(
    app: &mut tauri::App<tauri::Wry>,
    mode: &str,
) -> Result<D32HostCanaryReport, String> {
    windows::run_d32_a_host_integration_impl(app, mode)
}

/// Perform the canary's provider gate before the production Tauri setup hook
/// opens the writable Host storage connection.  This keeps a missing-provider
/// canary invocation read-only with respect to the real app-data directory.
#[cfg(all(windows, feature = "d32-a-host-canary", not(test)))]
pub(crate) fn d32_a_preflight_chat_provider(identifier: &str, mode: &str) -> Result<(), String> {
    windows::d32_a_preflight_chat_provider(identifier, mode)
}

/// Owns the canary-only filesystem projection and scoped path overrides.  The
/// real Host app-data/resource namespaces remain read-only audit targets; all
/// writable state used by the production builder is redirected below one
/// process-unique temporary root.
#[cfg(all(windows, feature = "d32-a-host-canary", not(test)))]
pub(crate) struct D32HostIntegrationEnvironment {
    inner: windows::D32HostIntegrationEnvironment,
}

#[cfg(all(windows, feature = "d32-a-host-canary", not(test)))]
impl D32HostIntegrationEnvironment {
    pub(crate) fn prepare(identifier: &str) -> Result<Self, String> {
        windows::D32HostIntegrationEnvironment::prepare(identifier).map(|inner| Self { inner })
    }

    pub(crate) fn verify_real_roots_unchanged(&self) -> Result<(), String> {
        self.inner
            .verify_real_roots_unchanged()
            .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())
    }

    pub(crate) fn establish_stable_baseline(&mut self) -> Result<(), String> {
        self.inner
            .establish_stable_baseline()
            .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), String> {
        self.inner
            .cleanup()
            .map_err(|_| "D32_A_HOST_FAILURE: cleanup_failed".to_string())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    #[cfg(feature = "d32-a-host-canary")]
    use crate::capability::activation::apply_transition_for_host_canary;
    use crate::capability::authorization::{
        evaluate_capability_authorization, evaluate_capability_authorization_in_scope,
        CapabilityAuthorizationDecisionKind, CapabilityAuthorizationErrorCode,
        CapabilityAuthorizationRepository, CapabilityEvaluationErrorCode, RequestedCapabilityScope,
    };
    use crate::capability::descriptor::{
        CapabilityId, ScopeRequirement, PRODUCTION_CARGO_CHECK_CAPABILITY_ID,
        PRODUCTION_CARGO_CHECK_PROFILE_ID, PRODUCTION_CARGO_CHECK_TOOL_NAME,
        PRODUCTION_GIT_STATUS_CAPABILITY_ID, PRODUCTION_GIT_STATUS_PROFILE_ID,
        PRODUCTION_GIT_STATUS_TOOL_NAME, PRODUCTION_WORKSPACE_READ_CAPABILITY_ID,
        PRODUCTION_WORKSPACE_READ_TOOL_NAME, PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
        PRODUCTION_WORKSPACE_RECOVER_PROFILE_ID, PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
        PRODUCTION_WORKSPACE_REPLACE_PROFILE_ID, PRODUCTION_WORKSPACE_REPLACE_TOOL_NAME,
    };
    use crate::execution_enclave::{CodexRuntimeError, VitaSidecarProcess};
    use protocol::{
        AuthorityEvaluate, AuthorityScopeReply, ConfirmationDecision, ConfirmationReply,
        ConfirmationRequired, ExecuteRecovery, GrantIssued, GrantRevalidated, HostMessage,
        InitializeSession, IssueGrant, ProcessBinding, ProcessGrant, RecoveryAuthorityEvaluate,
        RecoveryAuthorityReply, RecoveryConfirmationReply, RecoveryConfirmationRequired,
        RecoveryGrant, RecoveryGrantIssued, RecoveryGrantRevalidated, RecoveryIssueGrant,
        RecoveryRevalidateGrant, RevalidateGrant, VitaMessage, WorkspaceReadAuthorityEvaluate,
        WorkspaceReadAuthorityReply, WorkspaceReadConfirmationReply,
        WorkspaceReadConfirmationRequired, WorkspaceReadGrant, WorkspaceReadGrantIssued,
        WorkspaceReadGrantRevalidated, WorkspaceReadIssueGrant, WorkspaceReadReleaseCheck,
        WorkspaceReadReleaseChecked, WorkspaceReadRevalidateGrant,
        WorkspaceReplaceAuthorityEvaluate, WorkspaceReplaceAuthorityReply,
        WorkspaceReplaceConfirmationReply, WorkspaceReplaceConfirmationRequired,
        WorkspaceReplaceGrant, WorkspaceReplaceGrantIssued, WorkspaceReplaceGrantRevalidated,
        WorkspaceReplaceIssueGrant, WorkspaceReplaceRevalidateGrant, CODEX_PROTOCOL_SCHEMA_HASH,
        CODEX_UPSTREAM_COMMIT, PROTOCOL_VERSION, RUNTIME_ID,
    };
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::{Component, Path, PathBuf, Prefix};
    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Condvar, Weak};
    use std::thread::{self, JoinHandle};
    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    use std::time::Instant;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tauri::{AppHandle, Manager, State};
    use vita_agent_protocol as protocol;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileIdBothDirectoryInformation, FileRenameInformation, NtCreateFile, NtQueryDirectoryFile,
        NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION,
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, HANDLE, INVALID_HANDLE_VALUE,
        NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_NO_MORE_ENTRIES,
        STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileDispositionInfo, GetDriveTypeW, GetFileInformationByHandle,
        SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING,
        SYNCHRONIZE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_REMOTE;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    // H7-C's fixed Git-status program identity is the profile identity.  The
    // generic H7 fixture program id is deliberately not accepted on this
    // production capability lane.
    const PROGRAM_ID: &str = PRODUCTION_GIT_STATUS_PROFILE_ID;
    const CARGO_PROGRAM_ID: &str = "cargo-check-v1";
    const CARGO_NO_GIT_METADATA_FENCE: &str = "d32-no-git-fence-v1";
    const CARGO_ENVIRONMENT_POLICY_HASH: &str =
        "f45206b70dabb5c144d0ba95b966e97da91a1f284b2449a8e4bc96fade55ba3a";
    const CARGO_ARGV_HASH: &str =
        "51f73634568f17211b3f8305649cfd9391a1dd52c05b2469add4317fbc8603c8";
    const D32_EXECUTION_ROOT_NAME: &str = "d32-cargo-check-v1";
    const D32_SOURCE_DIR_NAME: &str = "source";
    const D32_TOOLCHAIN_MIRROR_ROOT_NAME: &str = "d32-toolchains";
    const D32_RUNS_DIR_NAME: &str = "runs";
    const D32_NATIVE_EVIDENCE_VERSION: u32 = 2;
    const D32_NATIVE_EVIDENCE_DIR_NAME: &str = ".d32-native-evidence-v2";
    const D32_NATIVE_EVIDENCE_MAX_BYTES: u64 = 64 * 1024;
    const D32_CARGO_SELECTION_FILE_NAME: &str = ".d32-cargo-selection-v1.json";
    const D32_TOOLCHAIN_FILE_MAX_BYTES: u64 = protocol::D32_MANIFEST_MAX_FILE_BYTES;
    const D32_TOOLCHAIN_TOTAL_MAX_BYTES: u64 = protocol::D32_MANIFEST_MAX_TOTAL_BYTES;
    const D32_TOOLCHAIN_MAX_FILES: usize = protocol::D32_MANIFEST_MAX_FILES;
    // NtQueryDirectoryFile requires FILE_LIST_DIRECTORY on the retained
    // directory handle.  Keep this explicit instead of reopening the
    // directory by pathname for manifest/catalog authority.
    const D32_FILE_LIST_DIRECTORY: u32 = 0x0001;
    const D32_AUDIT_MAX_ENTRIES: usize = 262_144;
    const D32_AUDIT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    const D32_AUDIT_MAX_PATH_BYTES: usize = protocol::MAX_PATH_BYTES;
    const D32_AUDIT_MAX_NAME_BYTES: usize = protocol::MAX_PATH_BYTES;
    const D32_AUDIT_MAX_NAMESPACE_BYTES: u64 = D32_AUDIT_MAX_BYTES;
    // All D32 tree walkers fail closed before an attacker-controlled nested
    // directory can consume the Windows thread stack.
    const D32_TREE_MAX_DEPTH: usize = 256;
    const D32_RETAINED_READ_CHUNK_BYTES: usize = 64 * 1024;
    const D32_IMAGE_HASH_MAX_BYTES: u64 = 256 * 1024 * 1024;
    const GRANT_LIFETIME_MS: u64 = 30_000;
    // Cargo authority validation rechecks the app-owned toolchain mirror by
    // streaming its bounded manifest.  Keep confirmation expiry bounded, but
    // allow the fixed production Cargo lane enough time to complete that
    // Host-owned evidence check on a cold machine.
    const HOST_CONFIRMATION_TTL_MS: u64 = 120_000;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_PENDING: usize = 1;

    /// Stream a retained file with a strict `max_bytes + 1` read ceiling.
    ///
    /// The extra byte is read into the bounded heap buffer so a concurrent
    /// growth is detected at the boundary, but it is never delivered to the
    /// consumer. Hash and copy consumers therefore cannot process bytes
    /// outside their frozen limit.
    fn read_retained_bounded<R, F>(
        reader: &mut R,
        max_bytes: u64,
        buffer: &mut [u8],
        mut consume: F,
    ) -> Result<u64, String>
    where
        R: Read,
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        if buffer.is_empty() {
            return Err("D32 retained read buffer was empty".to_string());
        }
        let read_limit = max_bytes
            .checked_add(1)
            .ok_or_else(|| "D32 retained file bound overflowed".to_string())?;
        let mut limited = reader.take(read_limit);
        let mut total = 0_u64;
        loop {
            let remaining = max_bytes
                .checked_sub(total)
                .ok_or_else(|| "D32 retained file exceeded its bound".to_string())?;
            let read_capacity = if remaining >= buffer.len() as u64 {
                buffer.len()
            } else {
                usize::try_from(
                    remaining
                        .checked_add(1)
                        .ok_or_else(|| "D32 retained file bound overflowed".to_string())?,
                )
                .map_err(|_| "D32 retained file bound was not representable".to_string())?
            };
            let read = limited
                .read(&mut buffer[..read_capacity])
                .map_err(|_| "D32 retained file read failed".to_string())?;
            if read == 0 {
                break;
            }
            let read = u64::try_from(read)
                .map_err(|_| "D32 retained file read was not representable".to_string())?;
            if read > remaining {
                return Err("D32 retained file exceeded its bound".to_string());
            }
            consume(&buffer[..read as usize])?;
            total = total
                .checked_add(read)
                .ok_or_else(|| "D32 retained file exceeded its bound".to_string())?;
        }
        Ok(total)
    }

    #[cfg(feature = "d32-a-host-canary")]
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct D32NativeEvidenceRecord {
        version: u32,
        run_id: String,
        session_id: String,
        life_id: String,
        task_id: String,
        turn_id: String,
        tool_call_id: String,
        capability_id: String,
        program_id: String,
        profile_id: String,
        status: String,
        process_created: bool,
        process_created_count: u64,
        thread_resumed: bool,
        thread_resumed_count: u64,
        user_code_started: bool,
        user_code_started_count: u64,
        process_exit: bool,
        process_exit_verified: bool,
        process_exit_count: u64,
        exit_code: Option<u32>,
        process_tree_observed: bool,
        process_tree_observation_count: u64,
        process_tree_remaining: u64,
        process_tree_observer_failed: bool,
        job_termination_attempted: bool,
        job_terminated: bool,
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn validate_d32_native_evidence_record(
        record: &D32NativeEvidenceRecord,
        mode: D32HostCanaryMode,
    ) -> Result<(), String> {
        if record.version != D32_NATIVE_EVIDENCE_VERSION {
            return Err("D32 native evidence version was not supported".to_string());
        }
        let bool_counts = [
            (record.process_created, record.process_created_count),
            (record.thread_resumed, record.thread_resumed_count),
            (record.user_code_started, record.user_code_started_count),
            (record.process_exit_verified, record.process_exit_count),
        ];
        if bool_counts
            .iter()
            .any(|(value, count)| *count != u64::from(*value))
            || record.process_exit != record.process_exit_verified
            || record.process_tree_observed != (record.process_tree_observation_count != 0)
            || record.process_tree_remaining != 0
            || record.process_tree_observer_failed
        {
            return Err("D32 native evidence lifecycle counters were inconsistent".to_string());
        }
        let positive = mode == D32HostCanaryMode::Positive;
        if positive {
            if record.status != "started_and_exited"
                || !record.process_created
                || !record.thread_resumed
                || !record.user_code_started
                || record.exit_code != Some(0)
                || !record.process_exit_verified
                || !record.process_tree_observed
                || record.process_tree_observation_count == 0
            {
                return Err("D32 native evidence positive lifecycle was incomplete".to_string());
            }
        } else if record.status != "denied"
            || record.process_created
            || record.thread_resumed
            || record.user_code_started
            || record.exit_code.is_some()
            || record.process_exit_verified
            || record.process_tree_observed
            || record.process_tree_observation_count != 0
            || record.job_termination_attempted
            || record.job_terminated
        {
            return Err("D32 native evidence negative lane was not pre-native denied".to_string());
        }
        Ok(())
    }
    // Active grants are bounded, but successful single-use grants are removed
    // immediately after final revalidation, so this is not a session lifetime
    // limit.
    const MAX_GRANTS: usize = 64;
    const REQUEST_REPLAY_WINDOW: usize = 128;
    const SIDECAR_RESOURCE_NAME: &str = "vita-agent.exe";
    const RUNTIME_LIFE_CHANGED: &str = "CAPABILITY_RUNTIME_LIFE_CHANGED";
    const LIFE_RESTART_REQUIRED: &str = "SIDECAR_LIFE_RESTART_REQUIRED";
    const LIFE_UNAVAILABLE: &str = "CAPABILITY_RUNTIME_LIFE_UNAVAILABLE";
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    /// Host-owned evidence for the fixed D32 Cargo profile.  The process
    /// binding is intentionally protocol-frozen and cannot carry another
    /// toolchain field, so this evidence stays inside the Host session and is
    /// compared against every Cargo binding before a grant can be consumed.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct HostCargoCheckProfileEvidence {
        executable_identity: String,
        executable_sha256: String,
        rustc_identity: String,
        rustc_sha256: String,
        rustdoc_identity: String,
        rustdoc_sha256: String,
        toolchain_root_identity: String,
        toolchain_manifest_hash: String,
        staged_working_directory_identity: String,
        environment_policy_hash: String,
        profile_id: String,
    }

    /// The executable image is selected by the Host before Vita starts.  The
    /// marker is app-owned state, not user/provider input; Vita may only
    /// consume the exact path and digest that the Host published here.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct HostCargoSelection {
        path: String,
        sha256: String,
        toolchain_path: String,
        toolchain_manifest_sha256: String,
    }

    /// Host-owned authority retained across Vita startup.  The serialized
    /// selection marker is only a locator for Vita; it is never the source of
    /// the Host's expected executable evidence.
    #[derive(Clone, Debug)]
    struct HostPublishedCargoProfile {
        selection: HostCargoSelection,
        expected_profile_evidence: HostCargoCheckProfileEvidence,
    }

    /// The wire marker is only a locator.  During Host startup the selected
    /// toolchain and its `bin` directory stay backed by the exact retained
    /// handles that were used for selection; later mirror preparation consumes
    /// this capability instead of reopening the user-profile path.
    struct HostCargoSelectionAuthority {
        selection: HostCargoSelection,
        toolchain_retained: D32RetainedDirectory,
        toolchain_bin_retained: D32RetainedDirectory,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct HostFileIdentity {
        volume_serial: u32,
        file_index: u64,
        file_size: u64,
        directory: bool,
        reparse: bool,
    }

    impl HostFileIdentity {
        fn image_wire(self) -> String {
            format!(
                "{:08x}-{:016x}-{:016x}",
                self.volume_serial, self.file_index, self.file_size
            )
        }

        fn namespace_wire(self) -> String {
            format!(
                "{}-{:08x}-{:016x}",
                if self.directory { "directory" } else { "file" },
                self.volume_serial,
                self.file_index
            )
        }
    }

    fn host_wide_path(path: &Path) -> Result<Vec<u16>, String> {
        let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if value.iter().any(|unit| *unit == 0) {
            return Err("D32 Host path contained an embedded NUL".to_string());
        }
        value.push(0);
        Ok(value)
    }

    fn host_file_identity(path: &Path, expect_directory: bool) -> Result<HostFileIdentity, String> {
        let wide = host_wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(format!(
                "D32 Host identity could not open {}: {}",
                path.display(),
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let read = unsafe { GetFileInformationByHandle(raw, &mut information) != 0 };
        unsafe {
            CloseHandle(raw);
        }
        if !read {
            return Err(format!(
                "D32 Host identity could not read {}",
                path.display()
            ));
        }
        let directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let reparse = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if reparse || directory != expect_directory {
            return Err(format!(
                "D32 Host identity was not the expected non-reparse {}: {}",
                if expect_directory {
                    "directory"
                } else {
                    "file"
                },
                path.display()
            ));
        }
        Ok(HostFileIdentity {
            volume_serial: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
            file_size: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
            directory,
            reparse,
        })
    }

    struct D32RetainedHandle(HANDLE);

    impl D32RetainedHandle {
        fn new(handle: HANDLE) -> Result<Self, String> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(format!(
                    "D32 Host native handle creation failed: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ))
            } else {
                Ok(Self(handle))
            }
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn into_raw(self) -> HANDLE {
            let handle = self.0;
            std::mem::forget(self);
            handle
        }
    }

    impl Drop for D32RetainedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    fn d32_duplicate_handle(handle: HANDLE) -> Result<D32RetainedHandle, String> {
        let mut duplicate = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 || duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
            if !duplicate.is_null() && duplicate != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(duplicate);
                }
            }
            return Err(format!(
                "D32 Host retained handle duplication failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }
        D32RetainedHandle::new(duplicate)
    }

    // A retained handle is a process-local kernel reference.  The wrapper is
    // moved only behind Arc within this module and is never serialized.
    unsafe impl Send for D32RetainedHandle {}

    unsafe impl Sync for D32RetainedHandle {}

    #[derive(Clone)]
    struct D32PreparedNamespace {
        parent: Arc<D32RetainedHandle>,
        leaf: Arc<D32RetainedHandle>,
        leaf_name: OsString,
        leaf_share_access: u32,
        identity: HostFileIdentity,
    }

    impl D32PreparedNamespace {
        fn prepare(path: &Path, directory: bool) -> Result<Self, String> {
            let leaf_share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            if !path.is_absolute() {
                return Err("D32 Host namespace path was not absolute".to_string());
            }
            let mut normal_components = Vec::new();
            for component in path.components() {
                match component {
                    Component::Prefix(prefix)
                        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
                    Component::RootDir => {}
                    Component::Normal(value) => normal_components.push(value.to_os_string()),
                    _ => return Err("D32 Host namespace path had an unsafe component".to_string()),
                }
            }
            let drive_letter = match path.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                    _ => {
                        return Err("D32 Host namespace path had no local drive anchor".to_string())
                    }
                },
                _ => return Err("D32 Host namespace path had no local drive anchor".to_string()),
            };
            if normal_components.is_empty() {
                return Err("D32 Host namespace path had no leaf component".to_string());
            }
            let drive_root = PathBuf::from(format!("{}:\\", drive_letter as char));
            if unsafe { GetDriveTypeW(host_wide_path(&drive_root)?.as_ptr()) } == DRIVE_REMOTE {
                return Err("D32 Host namespace path was on a remote drive".to_string());
            }
            let root = Arc::new(d32_open_namespace_drive_anchor(&drive_root)?);
            let mut parent = Arc::clone(&root);
            let leaf_name = normal_components
                .last()
                .cloned()
                .ok_or_else(|| "D32 Host namespace leaf was missing".to_string())?;
            for (index, component) in normal_components.iter().enumerate() {
                let is_leaf = index + 1 == normal_components.len();
                let handle = Arc::new(if is_leaf && !directory {
                    d32_open_namespace_relative_with_share(
                        &parent,
                        component,
                        false,
                        leaf_share_access,
                    )
                    .map_err(d32_namespace_error)?
                } else {
                    d32_open_namespace_relative_with_share(
                        &parent,
                        component,
                        true,
                        leaf_share_access,
                    )
                    .map_err(d32_namespace_error)?
                });
                let identity = d32_handle_identity(handle.raw())?;
                if identity.reparse
                    || identity.directory != (if is_leaf { directory } else { true })
                {
                    return Err(
                        "D32 Host namespace component was reparse or wrong kind".to_string()
                    );
                }
                if is_leaf {
                    return Ok(Self {
                        parent,
                        leaf: handle,
                        leaf_name,
                        leaf_share_access,
                        identity,
                    });
                }
                parent = handle;
            }
            Err("D32 Host namespace leaf acquisition failed".to_string())
        }

        fn rebind_leaf(&self) -> Result<Arc<D32RetainedHandle>, String> {
            let handle = Arc::new(if self.identity.directory {
                d32_open_namespace_relative_with_share(
                    &self.parent,
                    &self.leaf_name,
                    true,
                    self.leaf_share_access,
                )
                .map_err(d32_namespace_error)?
            } else {
                d32_open_namespace_relative_with_share(
                    &self.parent,
                    &self.leaf_name,
                    false,
                    self.leaf_share_access,
                )
                .map_err(d32_namespace_error)?
            });
            let identity = d32_handle_identity(handle.raw())?;
            if identity != self.identity || identity.reparse {
                return Err("D32 Host namespace leaf identity changed".to_string());
            }
            Ok(handle)
        }
    }

    /// A retained regular file whose authority is the parent handle plus its
    /// fixed leaf name.  The display path is kept only for diagnostics and
    /// command-line projection; identity/revalidation never reopens it by
    /// pathname.
    #[derive(Clone)]
    struct D32RetainedFile {
        namespace: D32PreparedNamespace,
        display_path: PathBuf,
    }

    impl D32RetainedFile {
        fn open(path: &Path) -> Result<Self, String> {
            let namespace = D32PreparedNamespace::prepare(path, false)?;
            Self::from_namespace(path.to_path_buf(), namespace)
        }

        fn from_namespace(
            display_path: PathBuf,
            namespace: D32PreparedNamespace,
        ) -> Result<Self, String> {
            if namespace.identity.directory || namespace.identity.reparse {
                return Err("D32 Host retained file was not a non-reparse regular file".to_string());
            }
            Ok(Self {
                namespace,
                display_path,
            })
        }

        fn from_child(
            parent: &D32RetainedDirectory,
            name: &OsStr,
            handle: D32RetainedHandle,
        ) -> Result<Self, String> {
            let handle = Arc::new(handle);
            let identity = d32_handle_identity(handle.raw())?;
            if identity.directory || identity.reparse {
                return Err("D32 Host retained file was not a non-reparse regular file".to_string());
            }
            Self::from_namespace(
                parent.raw_path.join(name),
                D32PreparedNamespace {
                    parent: Arc::clone(&parent.namespace.leaf),
                    leaf: handle,
                    leaf_name: name.to_os_string(),
                    leaf_share_access: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    identity,
                },
            )
        }

        fn identity(&self) -> HostFileIdentity {
            self.namespace.identity
        }

        fn revalidate(&self, description: &str) -> Result<(), String> {
            let retained_identity = d32_handle_identity(self.namespace.leaf.raw())?;
            if retained_identity != self.namespace.identity
                || retained_identity.reparse
                || retained_identity.directory
            {
                return Err(format!("{description} retained file identity changed"));
            }
            let rebound = self.namespace.rebind_leaf()?;
            let rebound_identity = d32_handle_identity(rebound.raw())?;
            if rebound_identity != self.namespace.identity
                || rebound_identity.reparse
                || rebound_identity.directory
            {
                return Err(format!("{description} retained file name binding changed"));
            }
            Ok(())
        }

        fn read_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, String> {
            self.revalidate("D32 retained file before read")?;
            let duplicate = d32_duplicate_handle(self.namespace.leaf.raw())?;
            let mut file = unsafe { File::from_raw_handle(duplicate.into_raw() as RawHandle) };
            file.seek(SeekFrom::Start(0)).map_err(|_| {
                format!(
                    "D32 Host retained file could not seek: {}",
                    self.display_path.display()
                )
            })?;
            let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
                format!(
                    "D32 Host retained file bound overflowed: {}",
                    self.display_path.display()
                )
            })?;
            // The caller supplies a frozen D32 bound (currently the 256 KiB
            // Git-config limit).  Allocate at most that bound and read one
            // bounded extra byte so growth beyond the bound fails closed.
            let mut bytes = Vec::with_capacity(max_bytes);
            let mut limited = Read::by_ref(&mut file).take(read_limit as u64);
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            loop {
                let remaining = max_bytes.saturating_sub(bytes.len());
                let read_capacity = remaining
                    .checked_add(1)
                    .ok_or_else(|| {
                        format!(
                            "D32 Host retained file bound overflowed: {}",
                            self.display_path.display()
                        )
                    })?
                    .min(buffer.len());
                let read = limited.read(&mut buffer[..read_capacity]).map_err(|_| {
                    format!(
                        "D32 Host retained file could not read: {}",
                        self.display_path.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                if read > remaining {
                    return Err(format!(
                        "D32 Host retained file exceeded its bound: {}",
                        self.display_path.display()
                    ));
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            let after = d32_handle_identity(file.as_raw_handle() as HANDLE)?;
            if after != self.namespace.identity || after.file_size != bytes.len() as u64 {
                return Err(format!(
                    "D32 Host retained file changed during read: {}",
                    self.display_path.display()
                ));
            }
            drop(file);
            self.revalidate("D32 retained file after read")?;
            Ok(bytes)
        }
    }

    #[derive(Clone)]
    struct D32RetainedDirectory {
        namespace: D32PreparedNamespace,
        raw_path: PathBuf,
        raw_identity: HostFileIdentity,
        canonical_identity: HostFileIdentity,
    }

    impl D32RetainedDirectory {
        fn open(path: &Path) -> Result<Self, String> {
            let namespace = D32PreparedNamespace::prepare(path, true)?;
            Self::from_namespace(path.to_path_buf(), namespace)
        }

        fn from_namespace(
            raw_path: PathBuf,
            namespace: D32PreparedNamespace,
        ) -> Result<Self, String> {
            host_verify_no_reparse_path(&raw_path, &raw_path)?;
            let raw_identity = host_file_identity(&raw_path, true)?;
            let canonical_path = fs::canonicalize(&raw_path).map_err(|_| {
                "D32 Host retained directory could not be canonicalized".to_string()
            })?;
            host_verify_no_reparse_path(&canonical_path, &canonical_path)?;
            let canonical_identity = host_file_identity(&canonical_path, true)?;
            if raw_identity != canonical_identity
                || raw_identity != namespace.identity
                || namespace.identity.reparse
            {
                return Err(
                    "D32 Host retained directory raw/canonical identity disagreed".to_string(),
                );
            }
            Ok(Self {
                namespace,
                raw_path,
                raw_identity,
                canonical_identity,
            })
        }

        fn from_retained_namespace(
            raw_path: PathBuf,
            namespace: D32PreparedNamespace,
        ) -> Result<Self, String> {
            let identity = namespace.identity;
            if !identity.directory || identity.reparse {
                return Err("D32 Host retained child was not a non-reparse directory".to_string());
            }
            Ok(Self {
                raw_path,
                raw_identity: identity,
                canonical_identity: identity,
                namespace,
            })
        }

        fn path(&self) -> &Path {
            &self.raw_path
        }

        fn identity(&self) -> HostFileIdentity {
            self.raw_identity
        }

        fn revalidate(&self, description: &str) -> Result<(), String> {
            let retained = self.namespace.rebind_leaf()?;
            let retained_identity = d32_handle_identity(retained.raw())?;
            if retained_identity != self.namespace.identity
                || retained_identity != self.raw_identity
                || retained_identity != self.canonical_identity
                || retained_identity.reparse
                || !retained_identity.directory
            {
                return Err(format!("{description} retained root identity changed"));
            }
            Ok(())
        }

        fn open_or_create_child(&self, name: &OsStr) -> Result<Self, String> {
            self.open_child(name, FILE_OPEN_IF)
        }

        fn open_or_create_mutable_child(
            &self,
            name: &OsStr,
        ) -> Result<D32MutableStagingDirectory, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained parent before mutable staging child create")?;
            let handle = self
                .open_child_result(
                    name,
                    FILE_OPEN_IF,
                    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                )
                .map_err(d32_namespace_error)?;
            let child = D32MutableStagingDirectory::from_parent(
                Arc::clone(&self.namespace.leaf),
                self.raw_path.clone(),
                name,
                handle,
            )?;
            self.revalidate("D32 retained parent after mutable staging child create")?;
            Ok(child)
        }

        fn open_existing_child(&self, name: &OsStr) -> Result<Self, String> {
            self.open_child(name, FILE_OPEN)
        }

        fn open_existing_child_if_present(&self, name: &OsStr) -> Result<Option<Self>, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before child probe")?;
            match self.open_child_result(
                name,
                FILE_OPEN,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | D32_FILE_LIST_DIRECTORY | SYNCHRONIZE,
            ) {
                Ok(handle) => Ok(Some(self.finish_child(name, handle)?)),
                Err(D32NamespaceOpenError::Missing(_)) => Ok(None),
                Err(D32NamespaceOpenError::Failed(status)) => Err(format!(
                    "D32 retained child directory probe failed: {status}"
                )),
            }
        }

        fn open_existing_file(&self, name: &OsStr) -> Result<D32RetainedFile, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file open")?;
            let handle = self
                .open_file(
                    name,
                    FILE_OPEN,
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(d32_namespace_error)?;
            let file = D32RetainedFile::from_child(self, name, handle)?;
            self.revalidate("D32 retained root after file open")?;
            Ok(file)
        }

        fn open_existing_file_if_present(
            &self,
            name: &OsStr,
        ) -> Result<Option<D32RetainedFile>, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before optional file probe")?;
            let handle = match self.open_file(
                name,
                FILE_OPEN,
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ) {
                Ok(handle) => handle,
                Err(D32NamespaceOpenError::Missing(_)) => return Ok(None),
                Err(D32NamespaceOpenError::Failed(status)) => {
                    return Err(format!("D32 retained optional file probe failed: {status}"))
                }
            };
            let file = D32RetainedFile::from_child(self, name, handle)?;
            self.revalidate("D32 retained root after optional file probe")?;
            Ok(Some(file))
        }

        fn child_is_directory(&self, name: &OsStr) -> Result<bool, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before child kind probe")?;
            let handle = d32_open_namespace_relative_with_options(
                &self.namespace.leaf,
                name,
                false,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )
            .map_err(d32_namespace_error)?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity.reparse {
                return Err("D32 retained child kind probe found a reparse point".to_string());
            }
            Ok(identity.directory)
        }

        fn open_child(&self, name: &OsStr, create_disposition: u32) -> Result<Self, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before child create")?;
            let handle = self
                .open_child_result(
                    name,
                    create_disposition,
                    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                )
                .map_err(d32_namespace_error)?;
            let child = self.finish_child(name, handle)?;
            self.revalidate("D32 retained root after child create")?;
            Ok(child)
        }

        fn open_child_result(
            &self,
            name: &OsStr,
            create_disposition: u32,
            desired_access: u32,
        ) -> Result<D32RetainedHandle, D32NamespaceOpenError> {
            d32_open_namespace_relative_with_options(
                &self.namespace.leaf,
                name,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                create_disposition,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                desired_access | D32_FILE_LIST_DIRECTORY,
            )
        }

        fn finish_child(&self, name: &OsStr, handle: D32RetainedHandle) -> Result<Self, String> {
            let handle = Arc::new(handle);
            let identity = d32_handle_identity(handle.raw())?;
            if !identity.directory || identity.reparse {
                return Err("D32 retained child directory was not non-reparse".to_string());
            }
            let child_path = self.raw_path.join(name);
            let child_namespace = D32PreparedNamespace {
                parent: Arc::clone(&self.namespace.leaf),
                leaf: handle,
                leaf_name: name.to_os_string(),
                leaf_share_access: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                identity,
            };
            let child = Self::from_retained_namespace(child_path, child_namespace)?;
            Ok(child)
        }

        fn open_file(
            &self,
            name: &OsStr,
            create_disposition: u32,
            desired_access: u32,
        ) -> Result<D32RetainedHandle, D32NamespaceOpenError> {
            d32_validate_child_name(name)
                .map_err(|_| D32NamespaceOpenError::Failed(STATUS_OBJECT_NAME_NOT_FOUND))?;
            d32_open_namespace_relative_with_options(
                &self.namespace.leaf,
                name,
                false,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                create_disposition,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                desired_access,
            )
        }

        fn probe_file(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<Option<HostFileIdentity>, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file probe")?;
            let result = match self.open_file(
                name,
                FILE_OPEN,
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ) {
                Ok(handle) => {
                    let identity = d32_handle_identity(handle.raw())?;
                    if identity.directory || identity.reparse || identity.file_size > max_bytes {
                        return Err("D32 retained file was not a bounded regular file".to_string());
                    }
                    Some(identity)
                }
                Err(D32NamespaceOpenError::Missing(_)) => None,
                Err(D32NamespaceOpenError::Failed(status)) => {
                    return Err(format!("D32 retained file probe failed: {status}"));
                }
            };
            self.revalidate("D32 retained root after file probe")?;
            Ok(result)
        }

        fn read_file(&self, name: &OsStr, max_bytes: usize) -> Result<Vec<u8>, String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file read")?;
            let handle = self
                .open_file(
                    name,
                    FILE_OPEN,
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained file open failed: {status}")
                    }
                })?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity.directory || identity.reparse || identity.file_size > max_bytes as u64 {
                return Err("D32 retained file exceeded its bound or was unsafe".to_string());
            }
            let mut file = unsafe { File::from_raw_handle(handle.into_raw() as RawHandle) };
            file.seek(SeekFrom::Start(0))
                .map_err(|_| "D32 retained file seek failed".to_string())?;
            let read_limit = max_bytes
                .checked_add(1)
                .ok_or_else(|| "D32 retained file bound overflowed".to_string())?;
            let mut bytes = Vec::with_capacity(max_bytes);
            let mut limited = Read::by_ref(&mut file).take(read_limit as u64);
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            loop {
                let remaining = max_bytes.saturating_sub(bytes.len());
                let read_capacity = remaining
                    .checked_add(1)
                    .ok_or_else(|| "D32 retained file bound overflowed".to_string())?
                    .min(buffer.len());
                let read = limited
                    .read(&mut buffer[..read_capacity])
                    .map_err(|_| "D32 retained file read failed".to_string())?;
                if read == 0 {
                    break;
                }
                if read > remaining {
                    return Err("D32 retained file exceeded its bound".to_string());
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            let after = d32_handle_identity(file.as_raw_handle() as HANDLE)?;
            if after != identity || after.file_size != bytes.len() as u64 {
                return Err("D32 retained file identity changed during read".to_string());
            }
            drop(file);
            self.revalidate("D32 retained root after file read")?;
            Ok(bytes)
        }

        fn hash_file(&self, name: &OsStr, max_bytes: usize) -> Result<String, String> {
            let bytes = self.read_file(name, max_bytes)?;
            Ok(format!("{:x}", Sha256::digest(bytes)))
        }

        fn hash_file_with_identity(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<(HostFileIdentity, [u8; 32]), String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file hash")?;
            let handle = self
                .open_file(
                    name,
                    FILE_OPEN,
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained file hash open failed: {status}")
                    }
                })?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity.directory || identity.reparse || identity.file_size > max_bytes {
                return Err(
                    "D32 retained file hash target was unsafe or exceeded its bound".to_string(),
                );
            }
            let mut file = unsafe { File::from_raw_handle(handle.into_raw() as RawHandle) };
            file.seek(SeekFrom::Start(0))
                .map_err(|_| "D32 retained file hash seek failed".to_string())?;
            let mut digest = Sha256::new();
            // Keep the bounded I/O buffer on the heap.  This method runs on
            // the default Windows thread stack; a 1 MiB stack array can
            // exhaust that stack before the first statement executes.
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let total = read_retained_bounded(&mut file, max_bytes, &mut buffer, |chunk| {
                digest.update(chunk);
                Ok(())
            })?;
            let after = d32_handle_identity(file.as_raw_handle() as HANDLE)?;
            if after != identity || after.file_size != total {
                return Err("D32 retained file identity changed during hash".to_string());
            }
            drop(file);
            self.revalidate("D32 retained root after file hash")?;
            Ok((identity, digest.finalize().into()))
        }

        fn copy_file_from(
            &self,
            source: &D32RetainedDirectory,
            source_name: &OsStr,
            destination_name: &OsStr,
            max_bytes: u64,
        ) -> Result<(), String> {
            d32_validate_child_name(source_name)?;
            d32_validate_child_name(destination_name)?;
            source.revalidate("D32 retained source before copy")?;
            self.revalidate("D32 retained destination before copy")?;
            let source_handle = source
                .open_file(
                    source_name,
                    FILE_OPEN,
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained source copy open failed: {status}")
                    }
                })?;
            let source_identity = d32_handle_identity(source_handle.raw())?;
            if source_identity.directory
                || source_identity.reparse
                || source_identity.file_size > max_bytes
            {
                return Err(
                    "D32 retained source copy target was unsafe or exceeded its bound".to_string(),
                );
            }
            let destination_handle = self
                .open_file(
                    destination_name,
                    FILE_CREATE,
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | FILE_READ_ATTRIBUTES
                        | DELETE
                        | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained destination copy create failed: {status}")
                    }
                })?;
            let destination_identity = d32_handle_identity(destination_handle.raw())?;
            if destination_identity.directory
                || destination_identity.reparse
                || destination_identity.file_size != 0
            {
                return Err(
                    "D32 retained destination copy file was unexpectedly reused".to_string()
                );
            }
            let mut source_file =
                unsafe { File::from_raw_handle(source_handle.into_raw() as RawHandle) };
            let mut destination_file =
                unsafe { File::from_raw_handle(destination_handle.into_raw() as RawHandle) };
            // Keep the bounded I/O buffer on the heap; see the hash path
            // above for the Windows default-stack constraint.
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let copied =
                read_retained_bounded(&mut source_file, max_bytes, &mut buffer, |chunk| {
                    destination_file
                        .write_all(chunk)
                        .map_err(|_| "D32 retained destination copy write failed".to_string())
                })?;
            if copied != source_identity.file_size {
                return Err("D32 retained source changed during copy".to_string());
            }
            destination_file
                .flush()
                .map_err(|_| "D32 retained destination copy flush failed".to_string())?;
            destination_file
                .sync_all()
                .map_err(|_| "D32 retained destination copy sync failed".to_string())?;
            let source_after = d32_handle_identity(source_file.as_raw_handle() as HANDLE)?;
            let destination_after =
                d32_handle_identity(destination_file.as_raw_handle() as HANDLE)?;
            if source_after != source_identity
                || destination_after.file_index != destination_identity.file_index
                || destination_after.file_size != copied
            {
                return Err("D32 retained source or destination changed during copy".to_string());
            }
            drop(source_file);
            drop(destination_file);
            source.revalidate("D32 retained source after copy")?;
            self.revalidate("D32 retained destination after copy")
        }

        fn enumerate_children(&self) -> Result<Vec<OsString>, String> {
            self.revalidate("D32 retained directory before enumeration")?;
            let mut names = Vec::new();
            let mut restart_scan = true;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let mut status_block = IO_STATUS_BLOCK::default();
                let status = unsafe {
                    NtQueryDirectoryFile(
                        self.namespace.leaf.raw(),
                        std::ptr::null_mut(),
                        None,
                        std::ptr::null(),
                        &mut status_block,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        FileIdBothDirectoryInformation,
                        true,
                        std::ptr::null(),
                        restart_scan,
                    )
                };
                if status == STATUS_NO_MORE_FILES || status == STATUS_NO_MORE_ENTRIES {
                    break;
                }
                if status < 0 {
                    return Err(format!(
                        "D32 retained directory enumeration failed: NTSTATUS 0x{:08X}",
                        status as u32
                    ));
                }
                let returned = usize::try_from(status_block.Information)
                    .ok()
                    .filter(|length| *length <= buffer.len())
                    .ok_or_else(|| {
                        "D32 retained directory enumeration returned an invalid byte count"
                            .to_string()
                    })?;
                if returned == 0 {
                    return Err(
                        "D32 retained directory enumeration returned no entry bytes".to_string()
                    );
                }
                parse_host_directory_names(&buffer, returned, &mut names)?;
                restart_scan = false;
                if names.len() > 8192 {
                    return Err("D32 retained directory exceeded its child bound".to_string());
                }
            }
            self.revalidate("D32 retained directory after enumeration")?;
            Ok(names)
        }

        fn create_new_file(&self, name: &OsStr, bytes: &[u8]) -> Result<(), String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file create")?;
            let handle = self
                .open_file(
                    name,
                    FILE_CREATE,
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | FILE_READ_ATTRIBUTES
                        | DELETE
                        | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained file create failed: {status}")
                    }
                })?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity.directory || identity.reparse || identity.file_size != 0 {
                return Err("D32 retained file create unexpectedly reused state".to_string());
            }
            let mut file = unsafe { File::from_raw_handle(handle.into_raw() as RawHandle) };
            file.write_all(bytes)
                .map_err(|_| "D32 retained file write failed".to_string())?;
            file.flush()
                .map_err(|_| "D32 retained file flush failed".to_string())?;
            file.sync_all()
                .map_err(|_| "D32 retained file sync failed".to_string())?;
            let after = d32_handle_identity(file.as_raw_handle() as HANDLE)?;
            if after.file_index != identity.file_index || after.file_size != bytes.len() as u64 {
                return Err("D32 retained file identity changed during create".to_string());
            }
            drop(file);
            self.revalidate("D32 retained root after file create")
        }

        fn rename_file(
            &self,
            source: &OsStr,
            destination: &OsStr,
            replace_if_exists: bool,
        ) -> Result<(), String> {
            d32_validate_child_name(source)?;
            d32_validate_child_name(destination)?;
            self.revalidate("D32 retained root before file replace")?;
            let _ = self.probe_file(destination, D32_NATIVE_EVIDENCE_MAX_BYTES)?;
            let handle = self
                .open_file(
                    source,
                    FILE_OPEN,
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | FILE_READ_ATTRIBUTES
                        | DELETE
                        | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained source open failed: {status}")
                    }
                })?;
            let name = destination.encode_wide().collect::<Vec<_>>();
            let file_name_length = name
                .len()
                .checked_mul(size_of::<u16>())
                .and_then(|length| u32::try_from(length).ok())
                .ok_or_else(|| "D32 retained file rename name was too long".to_string())?;
            let bytes = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
                .checked_add(file_name_length as usize)
                .ok_or_else(|| "D32 retained file rename buffer was too large".to_string())?;
            let mut buffer = vec![0_u8; bytes];
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            let mut status_block = IO_STATUS_BLOCK::default();
            unsafe {
                (*info).Anonymous.ReplaceIfExists = replace_if_exists;
                (*info).RootDirectory = self.namespace.leaf.raw();
                (*info).FileNameLength = file_name_length;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (*info).FileName.as_mut_ptr(),
                    name.len(),
                );
                let status = NtSetInformationFile(
                    handle.raw(),
                    &mut status_block,
                    info.cast(),
                    buffer.len() as u32,
                    FileRenameInformation,
                );
                if status < 0 {
                    return Err(format!(
                        "D32 retained handle-relative rename failed: NTSTATUS 0x{:08X}",
                        status as u32
                    ));
                }
            }
            drop(handle);
            self.revalidate("D32 retained root after file replace")
        }

        fn remove_file(&self, name: &OsStr) -> Result<(), String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before file removal")?;
            let handle = self
                .open_file(name, FILE_OPEN, FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE)
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 retained file removal open failed: {status}")
                    }
                })?;
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe {
                SetFileInformationByHandle(
                    handle.raw(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == 0
            {
                return Err(format!(
                    "D32 retained handle-relative file removal failed: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }
            drop(handle);
            self.revalidate("D32 retained root after file removal")
        }

        fn remove_directory(&self, name: &OsStr) -> Result<(), String> {
            d32_validate_child_name(name)?;
            self.revalidate("D32 retained root before directory removal")?;
            let handle = self
                .open_child_result(
                    name,
                    FILE_OPEN,
                    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | DELETE | SYNCHRONIZE,
                )
                .map_err(d32_namespace_error)?;
            let identity = d32_handle_identity(handle.raw())?;
            if !identity.directory || identity.reparse {
                return Err("D32 retained directory removal target was unsafe".to_string());
            }
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe {
                SetFileInformationByHandle(
                    handle.raw(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == 0
            {
                return Err(format!(
                    "D32 retained directory removal failed: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }
            drop(handle);
            self.revalidate("D32 retained root after directory removal")
        }

        fn remove_contents(&self) -> Result<(), String> {
            fn remove_at_depth(current: &D32RetainedDirectory, depth: usize) -> Result<(), String> {
                if depth > D32_TREE_MAX_DEPTH {
                    return Err(
                        "D32 retained directory removal exceeded its path-depth bound".to_string(),
                    );
                }
                for name in current.enumerate_children()? {
                    if current.child_is_directory(&name)? {
                        let child = current.open_existing_child(&name)?;
                        remove_at_depth(&child, depth.saturating_add(1))?;
                        current.remove_directory(&name)?;
                    } else {
                        current.remove_file(&name)?;
                    }
                }
                current.revalidate("D32 retained directory after contents removal")
            }
            remove_at_depth(self, 0)
        }

        fn remove_self(&self) -> Result<(), String> {
            self.remove_contents()?;
            let handle = d32_open_namespace_relative_with_options(
                &self.namespace.parent,
                &self.namespace.leaf_name,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | DELETE | SYNCHRONIZE,
            )
            .map_err(d32_namespace_error)?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity != self.namespace.identity || identity.reparse || !identity.directory {
                return Err("D32 retained directory identity changed before removal".to_string());
            }
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe {
                SetFileInformationByHandle(
                    handle.raw(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == 0
            {
                return Err(format!(
                    "D32 retained directory removal failed: {}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }
            drop(handle);
            Ok(())
        }

        fn remove_child_tree_if_present(&self, name: &OsStr) -> Result<bool, String> {
            let Some(child) = self.open_existing_child_if_present(name)? else {
                return Ok(false);
            };
            child.remove_self()?;
            Ok(true)
        }

        fn rename_directory(
            &self,
            source: &OsStr,
            destination: &OsStr,
            replace_if_exists: bool,
        ) -> Result<(), String> {
            d32_validate_child_name(source)?;
            d32_validate_child_name(destination)?;
            self.revalidate("D32 retained root before directory rename")?;
            let handle = d32_open_namespace_relative_with_options(
                &self.namespace.leaf,
                source,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
            )
            .map_err(d32_namespace_error)?;
            let name = destination.encode_wide().collect::<Vec<_>>();
            let file_name_length = name
                .len()
                .checked_mul(size_of::<u16>())
                .and_then(|length| u32::try_from(length).ok())
                .ok_or_else(|| "D32 retained directory rename name was too long".to_string())?;
            let bytes = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
                .checked_add(file_name_length as usize)
                .ok_or_else(|| "D32 retained directory rename buffer was too large".to_string())?;
            let mut buffer = vec![0_u8; bytes];
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            let mut status_block = IO_STATUS_BLOCK::default();
            unsafe {
                (*info).Anonymous.ReplaceIfExists = replace_if_exists;
                (*info).RootDirectory = self.namespace.leaf.raw();
                (*info).FileNameLength = file_name_length;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (*info).FileName.as_mut_ptr(),
                    name.len(),
                );
                let status = NtSetInformationFile(
                    handle.raw(),
                    &mut status_block,
                    info.cast(),
                    buffer.len() as u32,
                    FileRenameInformation,
                );
                if status < 0 {
                    return Err(format!(
                        "D32 retained handle-relative directory rename failed: NTSTATUS 0x{:08X}",
                        status as u32
                    ));
                }
            }
            drop(handle);
            self.revalidate("D32 retained root after directory rename")
        }
    }

    /// A sealed mirror directory deliberately exposes only retained read
    /// operations.  Mutating operations stay on `D32RetainedDirectory` for
    /// app-owned state and on `D32MutableStagingDirectory` for the bounded
    /// pre-seal copy phase; callers cannot write through this mirror view.
    #[derive(Clone)]
    struct D32SealedDirectory {
        retained: D32RetainedDirectory,
    }

    impl D32SealedDirectory {
        fn from_retained(retained: D32RetainedDirectory) -> Result<Self, String> {
            retained.revalidate("D32 sealed mirror before publication")?;
            Ok(Self { retained })
        }

        fn into_retained_for_cleanup(self) -> D32RetainedDirectory {
            self.retained
        }

        fn path(&self) -> &Path {
            self.retained.path()
        }

        fn identity(&self) -> HostFileIdentity {
            self.retained.identity()
        }
    }

    trait D32ReadDirectory: Sized {
        fn revalidate(&self, description: &str) -> Result<(), String>;
        fn open_existing_child(&self, name: &OsStr) -> Result<Self, String>;
        fn probe_file(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<Option<HostFileIdentity>, String>;
        fn read_file(&self, name: &OsStr, max_bytes: usize) -> Result<Vec<u8>, String>;
        fn hash_file(&self, name: &OsStr, max_bytes: usize) -> Result<String, String>;
        fn hash_file_with_identity(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<(HostFileIdentity, [u8; 32]), String>;
        fn enumerate_children(&self) -> Result<Vec<OsString>, String>;
    }

    impl D32ReadDirectory for D32RetainedDirectory {
        fn revalidate(&self, description: &str) -> Result<(), String> {
            D32RetainedDirectory::revalidate(self, description)
        }

        fn open_existing_child(&self, name: &OsStr) -> Result<Self, String> {
            D32RetainedDirectory::open_existing_child(self, name)
        }

        fn probe_file(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<Option<HostFileIdentity>, String> {
            D32RetainedDirectory::probe_file(self, name, max_bytes)
        }

        fn read_file(&self, name: &OsStr, max_bytes: usize) -> Result<Vec<u8>, String> {
            D32RetainedDirectory::read_file(self, name, max_bytes)
        }

        fn hash_file(&self, name: &OsStr, max_bytes: usize) -> Result<String, String> {
            D32RetainedDirectory::hash_file(self, name, max_bytes)
        }

        fn hash_file_with_identity(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<(HostFileIdentity, [u8; 32]), String> {
            D32RetainedDirectory::hash_file_with_identity(self, name, max_bytes)
        }

        fn enumerate_children(&self) -> Result<Vec<OsString>, String> {
            D32RetainedDirectory::enumerate_children(self)
        }
    }

    impl D32ReadDirectory for D32SealedDirectory {
        fn revalidate(&self, description: &str) -> Result<(), String> {
            self.retained.revalidate(description)
        }

        fn open_existing_child(&self, name: &OsStr) -> Result<Self, String> {
            D32SealedDirectory::from_retained(self.retained.open_existing_child(name)?)
        }

        fn probe_file(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<Option<HostFileIdentity>, String> {
            self.retained.probe_file(name, max_bytes)
        }

        fn read_file(&self, name: &OsStr, max_bytes: usize) -> Result<Vec<u8>, String> {
            self.retained.read_file(name, max_bytes)
        }

        fn hash_file(&self, name: &OsStr, max_bytes: usize) -> Result<String, String> {
            self.retained.hash_file(name, max_bytes)
        }

        fn hash_file_with_identity(
            &self,
            name: &OsStr,
            max_bytes: u64,
        ) -> Result<(HostFileIdentity, [u8; 32]), String> {
            self.retained.hash_file_with_identity(name, max_bytes)
        }

        fn enumerate_children(&self) -> Result<Vec<OsString>, String> {
            self.retained.enumerate_children()
        }
    }

    /// A destination directory during mirror construction.  Its handle is
    /// handle-relative and its namespace anchor is checked for volume/file
    /// continuity, while directory allocation size is intentionally allowed
    /// to grow until `seal` captures the final full identity.  No mutable
    /// staging value is ever exposed after sealing.
    #[derive(Clone)]
    struct D32MutableStagingDirectory {
        parent: Arc<D32RetainedHandle>,
        leaf: Arc<D32RetainedHandle>,
        leaf_name: OsString,
        raw_path: PathBuf,
        namespace_anchor: HostFileIdentity,
    }

    impl D32MutableStagingDirectory {
        fn from_parent(
            parent: Arc<D32RetainedHandle>,
            parent_path: PathBuf,
            leaf_name: &OsStr,
            handle: D32RetainedHandle,
        ) -> Result<Self, String> {
            let identity = d32_handle_identity(handle.raw())?;
            if !identity.directory || identity.reparse {
                return Err("D32 mutable staging child was not a non-reparse directory".to_string());
            }
            Ok(Self {
                parent,
                raw_path: parent_path.join(leaf_name),
                leaf: Arc::new(handle),
                leaf_name: leaf_name.to_os_string(),
                namespace_anchor: identity,
            })
        }

        fn path(&self) -> &Path {
            &self.raw_path
        }

        fn ensure_namespace(&self, description: &str) -> Result<(), String> {
            let identity = d32_handle_identity(self.leaf.raw())?;
            if identity.volume_serial != self.namespace_anchor.volume_serial
                || identity.file_index != self.namespace_anchor.file_index
                || !identity.directory
                || identity.reparse
            {
                return Err(format!(
                    "{description} mutable staging namespace changed: {}",
                    self.raw_path.display()
                ));
            }
            Ok(())
        }

        fn open_or_create_child(&self, name: &OsStr) -> Result<Self, String> {
            d32_validate_child_name(name)?;
            self.ensure_namespace("D32 mutable staging parent before child create")?;
            let handle = d32_open_namespace_relative_with_options(
                &self.leaf,
                name,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN_IF,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | D32_FILE_LIST_DIRECTORY | SYNCHRONIZE,
            )
            .map_err(d32_namespace_error)?;
            let child =
                Self::from_parent(Arc::clone(&self.leaf), self.raw_path.clone(), name, handle)?;
            self.ensure_namespace("D32 mutable staging parent after child create")?;
            Ok(child)
        }

        fn copy_file_from(
            &self,
            source: &D32RetainedDirectory,
            source_name: &OsStr,
            destination_name: &OsStr,
            max_bytes: u64,
        ) -> Result<(), String> {
            d32_validate_child_name(source_name)?;
            d32_validate_child_name(destination_name)?;
            source.revalidate("D32 retained source before mutable staging copy")?;
            self.ensure_namespace("D32 mutable staging destination before copy")?;
            let source_handle = source
                .open_file(
                    source_name,
                    FILE_OPEN,
                    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|error| match error {
                    D32NamespaceOpenError::Missing(status)
                    | D32NamespaceOpenError::Failed(status) => {
                        format!("D32 mutable staging source copy open failed: {status}")
                    }
                })?;
            let source_identity = d32_handle_identity(source_handle.raw())?;
            if source_identity.directory
                || source_identity.reparse
                || source_identity.file_size > max_bytes
            {
                return Err(
                    "D32 mutable staging source copy target was unsafe or exceeded its bound"
                        .to_string(),
                );
            }
            let destination_handle = d32_open_namespace_relative_with_options(
                &self.leaf,
                destination_name,
                false,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | FILE_READ_ATTRIBUTES
                    | DELETE
                    | SYNCHRONIZE,
            )
            .map_err(|error| match error {
                D32NamespaceOpenError::Missing(status) | D32NamespaceOpenError::Failed(status) => {
                    format!("D32 mutable staging destination copy create failed: {status}")
                }
            })?;
            let destination_identity = d32_handle_identity(destination_handle.raw())?;
            if destination_identity.directory
                || destination_identity.reparse
                || destination_identity.file_size != 0
            {
                return Err(
                    "D32 mutable staging destination file was unexpectedly reused".to_string(),
                );
            }
            let mut source_file =
                unsafe { File::from_raw_handle(source_handle.into_raw() as RawHandle) };
            let mut destination_file =
                unsafe { File::from_raw_handle(destination_handle.into_raw() as RawHandle) };
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let copied =
                read_retained_bounded(&mut source_file, max_bytes, &mut buffer, |chunk| {
                    destination_file
                        .write_all(chunk)
                        .map_err(|_| "D32 mutable staging destination write failed".to_string())
                })?;
            if copied != source_identity.file_size {
                return Err("D32 mutable staging source changed during copy".to_string());
            }
            destination_file
                .flush()
                .map_err(|_| "D32 mutable staging destination flush failed".to_string())?;
            destination_file
                .sync_all()
                .map_err(|_| "D32 mutable staging destination sync failed".to_string())?;
            let source_after = d32_handle_identity(source_file.as_raw_handle() as HANDLE)?;
            let destination_after =
                d32_handle_identity(destination_file.as_raw_handle() as HANDLE)?;
            if source_after != source_identity
                || destination_after.file_index != destination_identity.file_index
                || destination_after.file_size != copied
            {
                return Err(
                    "D32 mutable staging source or destination changed during copy".to_string(),
                );
            }
            drop(source_file);
            drop(destination_file);
            source.revalidate("D32 retained source after mutable staging copy")?;
            self.ensure_namespace("D32 mutable staging destination after copy")
        }

        fn seal(self) -> Result<D32SealedDirectory, String> {
            self.ensure_namespace("D32 mutable staging before seal")?;
            let handle = d32_open_namespace_relative_with_options(
                &self.parent,
                &self.leaf_name,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | D32_FILE_LIST_DIRECTORY | SYNCHRONIZE,
            )
            .map_err(d32_namespace_error)?;
            let identity = d32_handle_identity(handle.raw())?;
            if identity.volume_serial != self.namespace_anchor.volume_serial
                || identity.file_index != self.namespace_anchor.file_index
                || !identity.directory
                || identity.reparse
            {
                return Err(format!(
                    "D32 mutable staging namespace changed before seal: {}",
                    self.raw_path.display()
                ));
            }
            let retained = D32RetainedDirectory::from_retained_namespace(
                self.raw_path,
                D32PreparedNamespace {
                    parent: self.parent,
                    leaf: Arc::new(handle),
                    leaf_name: self.leaf_name,
                    leaf_share_access: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    identity,
                },
            )?;
            D32SealedDirectory::from_retained(retained)
        }

        fn remove_for_cleanup(self) -> Result<(), String> {
            self.seal()?.into_retained_for_cleanup().remove_self()
        }
    }

    fn parse_host_directory_names(
        buffer: &[u8],
        returned: usize,
        names: &mut Vec<OsString>,
    ) -> Result<(), String> {
        // The flexible `FileName` member is followed by alignment padding in
        // the Rust representation.  The kernel record header ends at the
        // actual field offset, not at `size_of::<T>() - sizeof(WCHAR)`.
        let header_bytes = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        let mut offset = 0usize;
        while offset < returned {
            if returned - offset < header_bytes {
                return Err("D32 retained directory entry header was truncated".to_string());
            }
            let entry =
                unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_ID_BOTH_DIR_INFORMATION) };
            let name_length = usize::try_from(entry.FileNameLength)
                .map_err(|_| "D32 retained directory name length overflow".to_string())?;
            if name_length % size_of::<u16>() != 0
                || name_length / size_of::<u16>() > 32_767
                || header_bytes
                    .checked_add(name_length)
                    .and_then(|length| offset.checked_add(length))
                    .filter(|end| *end <= returned)
                    .is_none()
            {
                return Err("D32 retained directory entry name was outside the buffer".to_string());
            }
            let name = unsafe {
                std::slice::from_raw_parts(entry.FileName.as_ptr(), name_length / size_of::<u16>())
            };
            let name = OsString::from_wide(name);
            if name != OsStr::new(".") && name != OsStr::new("..") {
                names.push(name);
            }
            let next = usize::try_from(entry.NextEntryOffset)
                .map_err(|_| "D32 retained directory entry offset overflow".to_string())?;
            if next == 0 {
                break;
            }
            if next < header_bytes
                || offset
                    .checked_add(next)
                    .filter(|end| *end <= returned)
                    .is_none()
            {
                return Err("D32 retained directory entry offset was invalid".to_string());
            }
            offset += next;
        }
        Ok(())
    }

    enum D32NamespaceOpenError {
        Missing(NTSTATUS),
        Failed(NTSTATUS),
    }

    fn d32_namespace_error(error: D32NamespaceOpenError) -> String {
        match error {
            D32NamespaceOpenError::Missing(status) | D32NamespaceOpenError::Failed(status) => {
                format!("D32 Host handle-relative namespace open failed: {status}")
            }
        }
    }

    fn d32_validate_child_name(name: &OsStr) -> Result<(), String> {
        if name.is_empty()
            || name == OsStr::new(".")
            || name == OsStr::new("..")
            || name.to_string_lossy().chars().any(|character| {
                character == '/' || character == '\\' || character == ':' || character == '\0'
            })
        {
            return Err("D32 retained child name was not one safe component".to_string());
        }
        Ok(())
    }

    fn d32_open_namespace_drive_anchor(path: &Path) -> Result<D32RetainedHandle, String> {
        let raw = unsafe {
            CreateFileW(
                host_wide_path(path)?.as_ptr(),
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | D32_FILE_LIST_DIRECTORY | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let handle = D32RetainedHandle::new(raw)?;
        let identity = d32_handle_identity(handle.raw())?;
        if !identity.directory || identity.reparse {
            return Err("D32 Host drive anchor was not a non-reparse directory".to_string());
        }
        Ok(handle)
    }

    fn d32_open_namespace_relative_with_share(
        parent: &Arc<D32RetainedHandle>,
        component: &OsStr,
        directory: bool,
        share_access: u32,
    ) -> Result<D32RetainedHandle, D32NamespaceOpenError> {
        let desired_access = if directory {
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | D32_FILE_LIST_DIRECTORY | SYNCHRONIZE
        } else {
            FILE_GENERIC_READ | SYNCHRONIZE
        };
        let create_options = if directory {
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        };
        d32_open_namespace_relative_with_options(
            parent,
            component,
            directory,
            share_access,
            FILE_OPEN,
            create_options,
            desired_access,
        )
    }

    fn d32_open_namespace_relative_with_options(
        parent: &Arc<D32RetainedHandle>,
        component: &OsStr,
        _directory: bool,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        desired_access: u32,
    ) -> Result<D32RetainedHandle, D32NamespaceOpenError> {
        let mut name = component.encode_wide().collect::<Vec<_>>();
        let byte_length = name
            .len()
            .checked_mul(2)
            .ok_or(D32NamespaceOpenError::Failed(STATUS_OBJECT_NAME_NOT_FOUND))?;
        if byte_length > u16::MAX as usize {
            return Err(D32NamespaceOpenError::Failed(STATUS_OBJECT_NAME_NOT_FOUND));
        }
        let unicode_name = UNICODE_STRING {
            Length: byte_length as u16,
            MaximumLength: byte_length as u16,
            Buffer: name.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.raw(),
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut raw = std::ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
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
        if status < 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
            if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(raw);
                }
            }
            return Err(
                if matches!(
                    status,
                    STATUS_NO_SUCH_FILE
                        | STATUS_OBJECT_NAME_NOT_FOUND
                        | STATUS_OBJECT_PATH_NOT_FOUND
                ) {
                    D32NamespaceOpenError::Missing(status)
                } else {
                    D32NamespaceOpenError::Failed(status)
                },
            );
        }
        D32RetainedHandle::new(raw).map_err(|_| D32NamespaceOpenError::Failed(-1))
    }

    fn d32_handle_identity(handle: HANDLE) -> Result<HostFileIdentity, String> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(format!(
                "D32 Host retained identity read failed: {}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }
        Ok(HostFileIdentity {
            volume_serial: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
            file_size: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
            directory: information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            reparse: information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        })
    }

    /// Materialize the read-only source directory indexes before any retained
    /// namespace baseline is captured.  Windows may report a directory's
    /// allocation size changing from zero to one cluster on its first full
    /// enumeration; that is mutable directory metadata, not a replacement of
    /// the namespace leaf.  The later retained handles still enforce the
    /// complete identity (including regular-file size) and all revalidations
    /// remain fail-closed.
    fn d32_stage_directory_tree_before_capture(
        path: &Path,
        depth: usize,
        entries: &mut usize,
        bytes: &mut u64,
    ) -> Result<(), String> {
        if depth > D32_TREE_MAX_DEPTH {
            return Err("D32 Host source directory exceeded its depth bound".to_string());
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            format!(
                "D32 Host source directory metadata unavailable: {}",
                path.display()
            )
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
            return Err(format!(
                "D32 Host source directory was not a non-reparse directory: {}",
                path.display()
            ));
        }
        for entry in fs::read_dir(path).map_err(|_| {
            format!(
                "D32 Host source directory could not be enumerated: {}",
                path.display()
            )
        })? {
            let entry = entry.map_err(|_| {
                format!(
                    "D32 Host source directory entry could not be read: {}",
                    path.display()
                )
            })?;
            let entry_path = entry.path();
            let entry_metadata = fs::symlink_metadata(&entry_path).map_err(|_| {
                format!(
                    "D32 Host source directory entry metadata unavailable: {}",
                    entry_path.display()
                )
            })?;
            if entry_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "D32 Host source directory contained a reparse entry: {}",
                    entry_path.display()
                ));
            }
            *entries = entries
                .checked_add(1)
                .ok_or_else(|| "D32 Host source directory entry bound overflowed".to_string())?;
            if *entries > D32_TOOLCHAIN_MAX_FILES {
                return Err("D32 Host source directory exceeded its entry bound".to_string());
            }
            if entry_metadata.is_dir() {
                d32_stage_directory_tree_before_capture(
                    &entry_path,
                    depth.saturating_add(1),
                    entries,
                    bytes,
                )?;
            } else if entry_metadata.is_file() {
                *bytes = bytes
                    .checked_add(entry_metadata.len())
                    .ok_or_else(|| "D32 Host source directory byte bound overflowed".to_string())?;
                if *bytes > D32_TOOLCHAIN_TOTAL_MAX_BYTES {
                    return Err("D32 Host source directory exceeded its byte bound".to_string());
                }
            } else {
                return Err(format!(
                    "D32 Host source directory contained an unsupported entry: {}",
                    entry_path.display()
                ));
            }
        }
        Ok(())
    }

    fn host_hash_file(path: &Path, max_bytes: u64) -> Result<String, String> {
        let mut file = File::open(path)
            .map_err(|_| format!("D32 Host executable hash could not open {}", path.display()))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let read = file.read(&mut buffer).map_err(|_| {
                format!("D32 Host executable hash could not read {}", path.display())
            })?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > max_bytes {
                return Err(format!(
                    "D32 Host executable exceeded its bounded hash limit: {}",
                    path.display()
                ));
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_native_evidence_directory(
        app_data_root_retained: &D32RetainedDirectory,
    ) -> Result<D32RetainedDirectory, String> {
        app_data_root_retained
            .revalidate("D32 native evidence app-data root before child create")?;
        let directory = app_data_root_retained
            .open_or_create_child(OsStr::new(D32_NATIVE_EVIDENCE_DIR_NAME))?;
        app_data_root_retained
            .revalidate("D32 native evidence app-data root after child create")?;
        directory.revalidate("D32 native evidence directory after open")?;
        Ok(directory)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_prepare_native_evidence(
        app_data_root_retained: &D32RetainedDirectory,
    ) -> Result<(), String> {
        let directory = d32_native_evidence_directory(app_data_root_retained)?;
        directory.revalidate("D32 native evidence directory before prepare")?;
        if !directory.enumerate_children()?.is_empty() {
            return Err("D32 native evidence directory was stale or had extra entries".to_string());
        }
        directory.revalidate("D32 native evidence directory after prepare")?;
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_read_native_evidence(
        app_data_root_retained: &D32RetainedDirectory,
        trace: &D32HostCanaryTraceSnapshot,
        mode: D32HostCanaryMode,
    ) -> Result<D32NativeEvidenceReport, String> {
        let directory = d32_native_evidence_directory(app_data_root_retained)?;
        directory.revalidate("D32 native evidence directory before read")?;
        let expected_run_id = trace
            .native_evidence_run_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host run binding was missing".to_string())?;
        let expected_session_id = trace
            .native_evidence_session_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host session binding was missing".to_string())?;
        let expected_life_id = trace
            .native_evidence_life_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host Life binding was missing".to_string())?;
        let expected_task_id = trace
            .native_evidence_task_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host task binding was missing".to_string())?;
        let expected_turn_id = trace
            .native_evidence_turn_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host turn binding was missing".to_string())?;
        let expected_tool_call_id = trace
            .native_evidence_tool_call_id
            .as_deref()
            .ok_or_else(|| "D32 native evidence Host tool-call binding was missing".to_string())?;
        if d32_run_id(expected_session_id, expected_turn_id, expected_tool_call_id)
            != expected_run_id
        {
            return Err("D32 native evidence Host run binding hash was inconsistent".to_string());
        }
        let expected_name = format!("{expected_run_id}.json");
        let expected_name = OsStr::new(&expected_name);
        let names = directory.enumerate_children()?;
        if names.len() != 1 || names.first() != Some(&expected_name.to_os_string()) {
            return Err("D32 native evidence directory contained stale or extra state".to_string());
        }
        let identity_before = directory
            .probe_file(expected_name, D32_NATIVE_EVIDENCE_MAX_BYTES)?
            .ok_or_else(|| "D32 native evidence file was missing".to_string())?;
        let bytes = directory.read_file(expected_name, D32_NATIVE_EVIDENCE_MAX_BYTES as usize)?;
        let hash = directory.hash_file(expected_name, D32_NATIVE_EVIDENCE_MAX_BYTES as usize)?;
        let identity_after = directory
            .probe_file(expected_name, D32_NATIVE_EVIDENCE_MAX_BYTES)?
            .ok_or_else(|| "D32 native evidence file disappeared during read".to_string())?;
        if identity_before != identity_after {
            return Err("D32 native evidence file identity changed during read".to_string());
        }
        let reread_hash = format!("{:x}", Sha256::digest(&bytes));
        if hash != reread_hash {
            return Err("D32 native evidence handle-relative hash disagreed".to_string());
        }
        let record: D32NativeEvidenceRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "D32 native evidence JSON was invalid or had extra fields".to_string())?;
        if record.run_id != expected_run_id
            || record.session_id != expected_session_id
            || record.life_id != expected_life_id
            || record.task_id != expected_task_id
            || record.turn_id != expected_turn_id
            || record.tool_call_id != expected_tool_call_id
            || record.capability_id != PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            || record.program_id != CARGO_PROGRAM_ID
            || record.profile_id != PRODUCTION_CARGO_CHECK_PROFILE_ID
        {
            return Err("D32 native evidence binding did not match Host authority".to_string());
        }
        validate_d32_native_evidence_record(&record, mode)?;
        directory.revalidate("D32 native evidence directory after read")?;
        Ok(D32NativeEvidenceReport {
            record: serde_json::to_value(record)
                .map_err(|_| "D32 native evidence report serialization failed".to_string())?,
            sha256: hash,
            identity: identity_before.image_wire(),
            bytes: bytes.len() as u64,
        })
    }

    fn host_metadata_is_reparse(metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_symlink()
            || (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    fn d32_audit_path_bytes(path: &Path) -> Result<usize, String> {
        let bytes = path
            .as_os_str()
            .encode_wide()
            .count()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| "D32 Host audit path length overflowed".to_string())?;
        if bytes > D32_AUDIT_MAX_PATH_BYTES {
            return Err("D32 Host audit path exceeded its bound".to_string());
        }
        Ok(bytes)
    }

    fn d32_audit_name_bytes(name: &OsStr) -> Result<usize, String> {
        let bytes = name
            .encode_wide()
            .count()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| "D32 Host audit name length overflowed".to_string())?;
        if bytes > D32_AUDIT_MAX_NAME_BYTES {
            return Err("D32 Host audit name exceeded its bound".to_string());
        }
        Ok(bytes)
    }

    fn d32_audit_namespace_bytes_add(total: &mut u64, amount: usize) -> Result<(), String> {
        let amount = u64::try_from(amount)
            .map_err(|_| "D32 Host audit namespace byte bound overflowed".to_string())?;
        *total = total
            .checked_add(amount)
            .ok_or_else(|| "D32 Host audit namespace byte bound overflowed".to_string())?;
        if *total > D32_AUDIT_MAX_NAMESPACE_BYTES {
            return Err("D32 Host audit namespace exceeded its byte bound".to_string());
        }
        Ok(())
    }

    fn host_verify_no_reparse_path(root: &Path, path: &Path) -> Result<(), String> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "D32 Host app-owned path escaped its root".to_string())?;
        let mut current = root.to_path_buf();
        let root_metadata = fs::symlink_metadata(root)
            .map_err(|_| "D32 Host app-owned root metadata was unavailable".to_string())?;
        if host_metadata_is_reparse(&root_metadata) {
            return Err("D32 Host app-owned root was a reparse point".to_string());
        }
        for component in relative.components() {
            current.push(component.as_os_str());
            let metadata = fs::symlink_metadata(&current).map_err(|_| {
                format!(
                    "D32 Host app-owned path metadata was unavailable: {}",
                    current.display()
                )
            })?;
            if host_metadata_is_reparse(&metadata) {
                return Err(format!(
                    "D32 Host app-owned path contained a reparse point: {}",
                    current.display()
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn host_canonical_directory_fence(path: &Path, description: &str) -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err(format!("{description} was not absolute"));
        }
        host_verify_no_reparse_path(path, path)
            .map_err(|error| format!("{description} raw no-reparse fence failed: {error}"))?;
        let raw_identity = host_file_identity(path, true)
            .map_err(|error| format!("{description} raw identity fence failed: {error}"))?;
        let canonical = fs::canonicalize(path)
            .map_err(|_| format!("{description} could not be canonicalized"))?;
        host_verify_no_reparse_path(&canonical, &canonical)
            .map_err(|error| format!("{description} canonical no-reparse fence failed: {error}"))?;
        let canonical_identity = host_file_identity(&canonical, true)
            .map_err(|error| format!("{description} canonical identity fence failed: {error}"))?;
        if raw_identity != canonical_identity {
            return Err(format!("{description} raw/canonical identity disagreed"));
        }
        Ok(canonical)
    }

    fn host_verify_no_reparse_tree(root: &Path) -> Result<(), String> {
        host_verify_no_reparse_tree_with_limits(
            root,
            D32_AUDIT_MAX_ENTRIES,
            D32_AUDIT_MAX_BYTES,
            D32_TREE_MAX_DEPTH,
        )
    }

    fn host_verify_no_reparse_tree_with_limits(
        root: &Path,
        max_entries: usize,
        max_file_bytes: u64,
        max_depth: usize,
    ) -> Result<(), String> {
        let root_path_bytes = d32_audit_path_bytes(root)?;
        host_verify_no_reparse_path(root, root)?;
        let mut pending = Vec::with_capacity(1);
        pending.push((root.to_path_buf(), 0_usize));
        let mut entries_seen = 1_usize;
        let mut file_bytes = 0_u64;
        let mut discovered_file_bytes = 0_u64;
        let mut path_bytes = 0_u64;
        let mut name_bytes = 0_u64;
        d32_audit_namespace_bytes_add(&mut path_bytes, root_path_bytes)?;
        while let Some((current, depth)) = pending.pop() {
            if depth > max_depth {
                return Err("D32 Host app-owned tree exceeded its path-depth bound".to_string());
            }
            if pending.len() >= max_entries {
                return Err("D32 Host app-owned tree exceeded its pending-entry bound".to_string());
            }
            if entries_seen > max_entries {
                return Err("D32 Host app-owned tree exceeded its entry bound".to_string());
            }
            let metadata = fs::symlink_metadata(&current).map_err(|_| {
                format!(
                    "D32 Host app-owned tree metadata was unavailable: {}",
                    current.display()
                )
            })?;
            if host_metadata_is_reparse(&metadata) {
                return Err(format!(
                    "D32 Host app-owned tree contained a reparse point: {}",
                    current.display()
                ));
            }
            if metadata.is_file() {
                file_bytes = file_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| "D32 Host app-owned tree byte bound overflowed".to_string())?;
                if file_bytes > max_file_bytes {
                    return Err("D32 Host app-owned tree exceeded its byte bound".to_string());
                }
            }
            if metadata.is_dir() {
                let mut children = Vec::new();
                for child in fs::read_dir(&current).map_err(|_| {
                    format!(
                        "D32 Host app-owned tree enumeration failed: {}",
                        current.display()
                    )
                })? {
                    if children.len() >= max_entries {
                        return Err(
                            "D32 Host app-owned tree exceeded its per-directory entry bound"
                                .to_string(),
                        );
                    }
                    let child = child
                        .map_err(|_| "D32 Host app-owned tree enumeration failed".to_string())?;
                    let child_name = child.file_name();
                    let child_name_bytes = d32_audit_name_bytes(&child_name)?;
                    d32_audit_namespace_bytes_add(&mut name_bytes, child_name_bytes)?;
                    let child_depth = depth.checked_add(1).ok_or_else(|| {
                        "D32 Host app-owned tree path-depth bound overflowed".to_string()
                    })?;
                    if child_depth > max_depth {
                        return Err(
                            "D32 Host app-owned tree exceeded its path-depth bound".to_string()
                        );
                    }
                    let child_path = child.path();
                    let child_path_bytes = d32_audit_path_bytes(&child_path)?;
                    d32_audit_namespace_bytes_add(&mut path_bytes, child_path_bytes)?;
                    let child_metadata = fs::symlink_metadata(&child_path).map_err(|_| {
                        format!(
                            "D32 Host app-owned tree metadata was unavailable: {}",
                            child_path.display()
                        )
                    })?;
                    if host_metadata_is_reparse(&child_metadata) {
                        return Err(format!(
                            "D32 Host app-owned tree contained a reparse point: {}",
                            child_path.display()
                        ));
                    }
                    if child_metadata.is_file() {
                        discovered_file_bytes = discovered_file_bytes
                            .checked_add(child_metadata.len())
                            .ok_or_else(|| {
                                "D32 Host app-owned tree byte bound overflowed".to_string()
                            })?;
                        if discovered_file_bytes > max_file_bytes {
                            return Err(
                                "D32 Host app-owned tree exceeded its byte bound".to_string()
                            );
                        }
                    }
                    let discovered = entries_seen.checked_add(1).ok_or_else(|| {
                        "D32 Host app-owned tree entry bound overflowed".to_string()
                    })?;
                    if discovered > max_entries {
                        return Err("D32 Host app-owned tree exceeded its entry bound".to_string());
                    }
                    entries_seen = discovered;
                    children.push((child_path, child_name, child_depth));
                }
                // The stack is LIFO; reverse the deterministic name order so
                // traversal remains stable without collecting an unbounded
                // directory listing.
                children.sort_unstable_by(|left, right| left.1.cmp(&right.1));
                for (child_path, _child_name, child_depth) in children.into_iter().rev() {
                    if pending.len() >= max_entries {
                        return Err(
                            "D32 Host app-owned tree exceeded its pending-entry bound".to_string()
                        );
                    }
                    pending.push((child_path, child_depth));
                }
            }
        }
        Ok(())
    }

    fn host_validate_existing_tree_without_reparse_retained<D: D32ReadDirectory>(
        root: &D,
    ) -> Result<(), String> {
        fn visit<D: D32ReadDirectory>(
            current: &D,
            depth: usize,
            entries: &mut usize,
        ) -> Result<(), String> {
            if depth > 256 {
                return Err("D32 Host stale tree exceeded its path-depth bound".to_string());
            }
            for name in current.enumerate_children()? {
                *entries = entries.saturating_add(1);
                if *entries > D32_TOOLCHAIN_MAX_FILES + 16_384 {
                    return Err("D32 Host stale tree exceeded its entry bound".to_string());
                }
                if let Ok(child) = current.open_existing_child(&name) {
                    visit(&child, depth.saturating_add(1), entries)?;
                } else if current.probe_file(&name, u64::MAX)?.is_none() {
                    return Err("D32 Host stale tree contained an unsupported entry".to_string());
                }
            }
            Ok(())
        }

        root.revalidate("D32 Host stale tree before validation")?;
        let mut entries = 0usize;
        visit(root, 0, &mut entries)?;
        root.revalidate("D32 Host stale tree after validation")
    }

    fn host_retained_has_toolchain_images<D: D32ReadDirectory>(root: &D) -> bool {
        let Ok(bin) = root.open_existing_child(OsStr::new("bin")) else {
            return false;
        };
        ["cargo.exe", "rustc.exe", "rustdoc.exe"]
            .into_iter()
            .all(|name| {
                bin.probe_file(OsStr::new(name), D32_TOOLCHAIN_FILE_MAX_BYTES)
                    .is_ok_and(|value| value.is_some())
            })
    }

    // Keep this representation byte-for-byte compatible with Vita's frozen
    // production `toolchain_manifest_hash`: directories are not entries and
    // each file is represented only by its slash-normalized relative path and
    // content digest.  Enumeration, metadata, and hashing are all rooted in
    // the same retained directory capability.
    type HostToolchainManifestEntry = (Vec<u8>, [u8; 32]);

    fn host_collect_toolchain_manifest<D: D32ReadDirectory>(
        retained: &D,
        relative_prefix: PathBuf,
        entries: &mut Vec<HostToolchainManifestEntry>,
        file_count: &mut usize,
        total_bytes: &mut u64,
        depth: usize,
    ) -> Result<(), String> {
        if depth > D32_TREE_MAX_DEPTH {
            return Err("D32 Host toolchain manifest exceeded its path-depth bound".to_string());
        }
        retained.revalidate("D32 Host manifest directory before enumeration")?;
        for name in retained.enumerate_children()? {
            let relative = relative_prefix.join(&name);
            if let Ok(child) = retained.open_existing_child(&name) {
                host_collect_toolchain_manifest(
                    &child,
                    relative,
                    entries,
                    file_count,
                    total_bytes,
                    depth.saturating_add(1),
                )?;
            } else {
                let (identity, digest) =
                    retained.hash_file_with_identity(&name, D32_TOOLCHAIN_FILE_MAX_BYTES)?;
                *file_count = file_count.saturating_add(1);
                *total_bytes = total_bytes.saturating_add(identity.file_size);
                if *file_count > D32_TOOLCHAIN_MAX_FILES
                    || *total_bytes > D32_TOOLCHAIN_TOTAL_MAX_BYTES
                {
                    return Err("D32 Host toolchain manifest exceeded its bound".to_string());
                }
                let relative = relative
                    .to_str()
                    .ok_or_else(|| "D32 Host toolchain manifest path was not UTF-8".to_string())?
                    .replace('\\', "/")
                    .into_bytes();
                entries.push((relative, digest));
            }
        }
        retained.revalidate("D32 Host manifest directory after enumeration")
    }

    fn host_toolchain_manifest_hash_retained<D: D32ReadDirectory>(
        retained: &D,
    ) -> Result<String, String> {
        retained.revalidate("D32 Host toolchain root before manifest")?;
        let mut entries = Vec::new();
        let mut file_count = 0usize;
        let mut total_bytes = 0_u64;
        host_collect_toolchain_manifest(
            retained,
            PathBuf::new(),
            &mut entries,
            &mut file_count,
            &mut total_bytes,
            0,
        )?;
        let digest = protocol::d32_manifest_hash_hex(&mut entries)
            .map_err(|_| "D32 Host toolchain manifest canonical encoding failed".to_string())?;
        retained.revalidate("D32 Host toolchain root after manifest")?;
        Ok(digest)
    }

    #[cfg(test)]
    fn host_toolchain_manifest_hash(root: &Path) -> Result<String, String> {
        let retained = D32RetainedDirectory::open(root)?;
        host_toolchain_manifest_hash_retained(&retained)
    }

    fn host_copy_toolchain_tree(
        source: &D32RetainedDirectory,
        destination: &D32MutableStagingDirectory,
        files: &mut usize,
        bytes: &mut u64,
        depth: usize,
    ) -> Result<D32SealedDirectory, String> {
        if depth > D32_TREE_MAX_DEPTH {
            return Err("D32 Host toolchain mirror exceeded its path-depth bound".to_string());
        }
        source.revalidate("D32 Host source before toolchain copy")?;
        destination.ensure_namespace("D32 Host mutable destination before toolchain copy")?;
        for name in source.enumerate_children()? {
            if let Ok(source_child) = source.open_existing_child(&name) {
                let destination_child = destination.open_or_create_child(&name)?;
                let _sealed_child = host_copy_toolchain_tree(
                    &source_child,
                    &destination_child,
                    files,
                    bytes,
                    depth.saturating_add(1),
                )?;
            } else {
                let identity = source
                    .probe_file(&name, D32_TOOLCHAIN_FILE_MAX_BYTES)?
                    .ok_or_else(|| {
                        "D32 Host toolchain mirror encountered an unsupported entry".to_string()
                    })?;
                *files = files.saturating_add(1);
                *bytes = bytes.saturating_add(identity.file_size);
                if *files > D32_TOOLCHAIN_MAX_FILES || *bytes > D32_TOOLCHAIN_TOTAL_MAX_BYTES {
                    return Err("D32 Host toolchain mirror exceeded its bound".to_string());
                }
                destination.copy_file_from(source, &name, &name, D32_TOOLCHAIN_FILE_MAX_BYTES)?;
            }
        }
        source.revalidate("D32 Host source after toolchain copy")?;
        destination.ensure_namespace("D32 Host mutable destination after toolchain copy")?;
        destination.clone().seal()
    }

    fn host_staging_error(error: String, cleanup: Result<(), String>) -> String {
        match cleanup {
            Ok(()) => format!("{error}; D32 staging cleanup validated and removed"),
            Err(cleanup_error) => format!("{error}; D32 staging cleanup failed: {cleanup_error}"),
        }
    }

    fn host_prepare_toolchain_mirror_retained(
        app_data_root_retained: &D32RetainedDirectory,
        selection: &HostCargoSelection,
        selected_root_retained: &D32RetainedDirectory,
    ) -> Result<PathBuf, String> {
        app_data_root_retained.revalidate("D32 Host app-data root before mirror preparation")?;
        let mirror_parent_retained = app_data_root_retained
            .open_or_create_child(OsStr::new(D32_TOOLCHAIN_MIRROR_ROOT_NAME))?;
        let mirror_parent = mirror_parent_retained.path().to_path_buf();
        app_data_root_retained.revalidate("D32 Host app-data root before mirror parent create")?;
        mirror_parent_retained.revalidate("D32 Host mirror parent after create")?;
        app_data_root_retained.revalidate("D32 Host app-data root after mirror parent create")?;
        let mirror_parent_identity = mirror_parent_retained.identity();
        let mirror = mirror_parent.join(&selection.toolchain_manifest_sha256);
        let existing_mirror = mirror_parent_retained
            .open_existing_child(OsStr::new(&selection.toolchain_manifest_sha256))
            .ok()
            .and_then(|retained| D32SealedDirectory::from_retained(retained).ok());
        let valid = match existing_mirror.as_ref() {
            Some(retained) => {
                retained.revalidate("D32 Host mirror cache hit")?;
                host_validate_existing_tree_without_reparse_retained(retained)?;
                let manifest_matches = match host_toolchain_manifest_hash_retained(retained) {
                    Ok(hash) => hash == selection.toolchain_manifest_sha256,
                    Err(_) => false,
                };
                let cargo_hash_matches = retained
                    .open_existing_child(OsStr::new("bin"))
                    .and_then(|bin| {
                        bin.hash_file_with_identity(
                            OsStr::new("cargo.exe"),
                            D32_IMAGE_HASH_MAX_BYTES,
                        )
                        .map(|(_, digest)| {
                            digest
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                                == selection.sha256
                        })
                    })
                    .unwrap_or(false);
                manifest_matches
                    && cargo_hash_matches
                    && host_retained_has_toolchain_images(retained)
            }
            None => false,
        };
        if !valid {
            drop(existing_mirror);
            let selected_root_identity = selected_root_retained.identity();
            let selected_bin_retained =
                selected_root_retained.open_existing_child(OsStr::new("bin"))?;
            let selected_cargo_identity = selected_bin_retained
                .probe_file(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)?
                .ok_or_else(|| "D32 Host Cargo image was unavailable".to_string())?;
            let selected_cargo_hash = selected_bin_retained
                .hash_file_with_identity(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)?
                .1;
            if selected_cargo_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                != selection.sha256
            {
                return Err("D32 Host selected Cargo image did not match selection".to_string());
            }
            // A verified app-owned mirror is authoritative for a cache hit;
            // only bind the selected source image when a fresh copy is
            // actually required.  This keeps source availability from
            // weakening the verified-mirror reuse path.
            mirror_parent_retained
                .remove_child_tree_if_present(OsStr::new(&selection.toolchain_manifest_sha256))?;
            let staging_name =
                OsString::from(format!(".{}.staging", selection.toolchain_manifest_sha256));
            mirror_parent_retained.remove_child_tree_if_present(&staging_name)?;
            let staging_mut = mirror_parent_retained.open_or_create_mutable_child(&staging_name)?;
            let mut files = 0usize;
            let mut bytes = 0u64;
            let copy_result = (|| {
                app_data_root_retained.revalidate("D32 Host app-data root before mirror copy")?;
                selected_root_retained.revalidate("D32 Host toolchain root before mirror copy")?;
                host_copy_toolchain_tree(
                    &selected_root_retained,
                    &staging_mut,
                    &mut files,
                    &mut bytes,
                    0,
                )
            })();
            let staging_sealed = match copy_result {
                Ok(sealed) => sealed,
                Err(error) => {
                    return Err(host_staging_error(error, staging_mut.remove_for_cleanup()));
                }
            };
            drop(staging_mut);
            let post_copy_result = (|| {
                app_data_root_retained.revalidate("D32 Host app-data root after mirror copy")?;
                selected_root_retained.revalidate("D32 Host toolchain root after mirror copy")?;
                if selected_root_retained.identity() != selected_root_identity
                    || selected_bin_retained
                        .probe_file(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)?
                        != Some(selected_cargo_identity)
                {
                    return Err("D32 Host toolchain source changed during mirror copy".to_string());
                }
                let manifest = host_toolchain_manifest_hash_retained(&staging_sealed)?;
                if manifest != selection.toolchain_manifest_sha256 {
                    return Err(
                        "D32 Host toolchain mirror manifest did not match selection".to_string()
                    );
                }
                app_data_root_retained
                    .revalidate("D32 Host app-data root before mirror finalize")?;
                mirror_parent_retained.revalidate("D32 Host mirror parent before finalize")?;
                Ok(())
            })();
            if let Err(error) = post_copy_result {
                return Err(host_staging_error(
                    error,
                    staging_sealed.into_retained_for_cleanup().remove_self(),
                ));
            }
            let staging_retained = staging_sealed.into_retained_for_cleanup();
            drop(staging_retained);
            if let Err(error) = mirror_parent_retained.rename_directory(
                &staging_name,
                OsStr::new(&selection.toolchain_manifest_sha256),
                false,
            ) {
                let cleanup = mirror_parent_retained
                    .open_existing_child(&staging_name)
                    .and_then(|orphan| orphan.remove_self());
                return Err(host_staging_error(error, cleanup));
            }
            app_data_root_retained.revalidate("D32 Host app-data root after mirror finalize")?;
        }
        app_data_root_retained.revalidate("D32 Host app-data root after mirror preparation")?;
        let mirror_retained = mirror_parent_retained
            .open_existing_child(OsStr::new(&selection.toolchain_manifest_sha256))?;
        let mirror_sealed = D32SealedDirectory::from_retained(mirror_retained)?;
        mirror_sealed.revalidate("D32 Host final toolchain mirror")?;
        if mirror_parent_retained.identity() != mirror_parent_identity {
            return Err("D32 Host toolchain mirror parent changed during preparation".to_string());
        }
        if host_toolchain_manifest_hash_retained(&mirror_sealed)?
            != selection.toolchain_manifest_sha256
        {
            return Err("D32 Host toolchain mirror changed after finalization".to_string());
        }
        Ok(mirror)
    }

    #[cfg(test)]
    fn host_prepare_toolchain_mirror(
        app_data_root: &Path,
        selection: &HostCargoSelection,
    ) -> Result<PathBuf, String> {
        let selected_root = host_canonical_directory_fence(
            Path::new(&selection.toolchain_path),
            "D32 Host toolchain root",
        )?;
        let selected_root_retained = D32RetainedDirectory::open(&selected_root)?;
        let app_data_root_retained = D32RetainedDirectory::open(app_data_root)?;
        host_prepare_toolchain_mirror_retained(
            &app_data_root_retained,
            selection,
            &selected_root_retained,
        )
    }

    fn host_select_cargo_image() -> Result<HostCargoSelectionAuthority, String> {
        let user_profile = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .ok_or_else(|| "D32 Host Rust toolchain root was unavailable".to_string())?;
        let toolchains = user_profile.join(".rustup").join("toolchains");
        let mut staged_entries = 0usize;
        let mut staged_bytes = 0u64;
        d32_stage_directory_tree_before_capture(
            &toolchains,
            0,
            &mut staged_entries,
            &mut staged_bytes,
        )?;
        let toolchains_retained = D32RetainedDirectory::open(&toolchains)?;
        toolchains_retained.revalidate("D32 Host toolchain root before selection")?;
        let mut candidates = Vec::new();
        for name in toolchains_retained.enumerate_children()? {
            if let Ok(candidate) = toolchains_retained.open_existing_child(&name) {
                if host_retained_has_toolchain_images(&candidate) {
                    candidates.push((candidate.path().to_path_buf(), candidate));
                }
            }
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let (toolchain_path, toolchain_retained) = candidates
            .into_iter()
            .next()
            .ok_or_else(|| "D32 Host Rust toolchain was unavailable".to_string())?;
        let toolchain_bin_retained = toolchain_retained.open_existing_child(OsStr::new("bin"))?;
        let cargo_path = toolchain_bin_retained.path().join("cargo.exe");
        let (_, cargo_digest) = toolchain_bin_retained
            .hash_file_with_identity(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)?;
        let sha256 = cargo_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for name in ["rustc.exe", "rustdoc.exe"] {
            toolchain_bin_retained
                .hash_file_with_identity(OsStr::new(name), D32_TOOLCHAIN_FILE_MAX_BYTES)?;
        }
        let toolchain_manifest_sha256 = host_toolchain_manifest_hash_retained(&toolchain_retained)?;
        toolchain_retained.revalidate("D32 Host selected toolchain after evidence")?;
        toolchain_bin_retained.revalidate("D32 Host selected toolchain bin after evidence")?;
        toolchains_retained.revalidate("D32 Host toolchain root after selection")?;
        Ok(HostCargoSelectionAuthority {
            selection: HostCargoSelection {
                path: cargo_path.to_string_lossy().into_owned(),
                sha256,
                toolchain_path: toolchain_path.to_string_lossy().into_owned(),
                toolchain_manifest_sha256,
            },
            toolchain_retained,
            toolchain_bin_retained,
        })
    }

    #[cfg(test)]
    fn host_cargo_selection_path(app_data_root: &Path) -> PathBuf {
        app_data_root.join(D32_CARGO_SELECTION_FILE_NAME)
    }

    fn host_write_cargo_selection_marker(
        root: &D32RetainedDirectory,
        payload: &[u8],
    ) -> Result<(), String> {
        let marker_name = OsStr::new(D32_CARGO_SELECTION_FILE_NAME);
        root.revalidate("D32 Host app-data root before marker write")?;
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|_| "D32 Host Cargo selection temporary identity unavailable".to_string())?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary_name =
            OsString::from(format!(".{D32_CARGO_SELECTION_FILE_NAME}.{}.tmp", suffix));
        let expected_hash = format!("{:x}", Sha256::digest(payload));
        let write_result = (|| {
            root.create_new_file(&temporary_name, payload)?;
            let temporary_bytes = root.read_file(&temporary_name, 16 * 1024)?;
            if root.hash_file(&temporary_name, 16 * 1024)? != expected_hash
                || temporary_bytes != payload
            {
                return Err(
                    "D32 Host Cargo selection temporary file changed before replace".to_string(),
                );
            }
            root.revalidate("D32 Host app-data root before marker replace")?;
            root.rename_file(&temporary_name, marker_name, true)?;
            let stored = root.read_file(marker_name, 16 * 1024)?;
            if stored != payload || root.hash_file(marker_name, 16 * 1024)? != expected_hash {
                return Err("D32 Host Cargo selection marker changed after replace".to_string());
            }
            root.revalidate("D32 Host app-data root after marker replace")?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = root.remove_file(&temporary_name);
        }
        write_result
    }

    fn host_publish_cargo_selection(
        app_data_root_retained: &D32RetainedDirectory,
    ) -> Result<HostPublishedCargoProfile, String> {
        validate_private_app_data_root(app_data_root_retained.path())?;
        // Select and verify the source toolchain independently on every Host
        // startup.  A marker left in app data by an earlier session is a Vita
        // locator, not durable authority, so it must never redefine the
        // expected executable evidence for this session.
        let selected = host_select_cargo_image()?;
        host_prepare_toolchain_mirror_retained(
            app_data_root_retained,
            &selected.selection,
            &selected.toolchain_retained,
        )?;
        selected
            .toolchain_bin_retained
            .revalidate("D32 Host selected toolchain bin before publication")?;
        let selection = selected.selection;
        let expected_profile_evidence =
            host_cargo_profile_evidence_for_selection(app_data_root_retained, &selection)?;
        let payload = serde_json::to_vec(&selection)
            .map_err(|_| "D32 Host Cargo selection serialization failed".to_string())?;
        host_write_cargo_selection_marker(app_data_root_retained, &payload)?;
        Ok(HostPublishedCargoProfile {
            selection,
            expected_profile_evidence,
        })
    }

    #[cfg(test)]
    fn host_publish_cargo_selection_path(
        app_data_root: &Path,
    ) -> Result<HostPublishedCargoProfile, String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let retained = D32RetainedDirectory::open(&app_data_root)?;
        host_publish_cargo_selection(&retained)
    }

    #[cfg(test)]
    fn host_clear_cargo_selection(app_data_root: &Path) -> Result<(), String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let root = D32RetainedDirectory::open(&app_data_root)?;
        let marker_name = OsStr::new(D32_CARGO_SELECTION_FILE_NAME);
        if root.probe_file(marker_name, 16 * 1024)?.is_some() {
            root.remove_file(marker_name)
                .map_err(|_| "D32 Host Cargo selection could not be cleared".to_string())?;
        }
        root.revalidate("D32 Host app-data root after marker cleanup")?;
        Ok(())
    }

    #[cfg(test)]
    fn host_read_cargo_selection_marker(
        app_data_root: &Path,
    ) -> Result<HostCargoSelection, String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let root = D32RetainedDirectory::open(&app_data_root)?;
        let marker_name = OsStr::new(D32_CARGO_SELECTION_FILE_NAME);
        let bytes = root.read_file(marker_name, 16 * 1024).map_err(|_| {
            "D32 Host Cargo selection exceeded its bound or could not be read".to_string()
        })?;
        let reread = root.read_file(marker_name, 16 * 1024)?;
        if bytes != reread {
            return Err("D32 Host Cargo selection changed during read".to_string());
        }
        root.revalidate("D32 Host app-data root after marker read")?;
        let selection: HostCargoSelection = serde_json::from_slice(&bytes)
            .map_err(|_| "D32 Host Cargo selection was malformed".to_string())?;
        if selection.sha256.len() != 64
            || selection
                .sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host Cargo selection hash was malformed".to_string());
        }
        if selection.toolchain_manifest_sha256.len() != 64
            || selection
                .toolchain_manifest_sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host toolchain selection hash was malformed".to_string());
        }
        if !PathBuf::from(&selection.path).is_absolute()
            || !PathBuf::from(&selection.toolchain_path).is_absolute()
        {
            return Err("D32 Host Cargo selection path was not absolute".to_string());
        }
        Ok(selection)
    }

    fn host_read_cargo_selection_marker_retained(
        root: &D32RetainedDirectory,
    ) -> Result<HostCargoSelection, String> {
        let marker_name = OsStr::new(D32_CARGO_SELECTION_FILE_NAME);
        root.revalidate("D32 Host app-data root before marker read")?;
        let bytes = root.read_file(marker_name, 16 * 1024).map_err(|_| {
            "D32 Host Cargo selection exceeded its bound or could not be read".to_string()
        })?;
        let reread = root.read_file(marker_name, 16 * 1024)?;
        if bytes != reread {
            return Err("D32 Host Cargo selection changed during read".to_string());
        }
        root.revalidate("D32 Host app-data root after marker read")?;
        let selection: HostCargoSelection = serde_json::from_slice(&bytes)
            .map_err(|_| "D32 Host Cargo selection was malformed".to_string())?;
        if selection.sha256.len() != 64
            || selection
                .sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host Cargo selection hash was malformed".to_string());
        }
        if selection.toolchain_manifest_sha256.len() != 64
            || selection
                .toolchain_manifest_sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host toolchain selection hash was malformed".to_string());
        }
        if !PathBuf::from(&selection.path).is_absolute()
            || !PathBuf::from(&selection.toolchain_path).is_absolute()
        {
            return Err("D32 Host Cargo selection path was not absolute".to_string());
        }
        Ok(selection)
    }

    fn host_cargo_profile_evidence_for_selection(
        app_data_root_retained: &D32RetainedDirectory,
        selection: &HostCargoSelection,
    ) -> Result<HostCargoCheckProfileEvidence, String> {
        app_data_root_retained.revalidate("D32 Host app-data root before profile evidence")?;
        // Every action is bound to the immutable app-owned mirror.  Do not
        // reread/hash the user-profile toolchain on the AuthorityEvaluate
        // path; Host publication already established this source evidence.
        let mirror_parent = app_data_root_retained
            .open_existing_child(OsStr::new(D32_TOOLCHAIN_MIRROR_ROOT_NAME))?;
        let toolchain_retained =
            mirror_parent.open_existing_child(OsStr::new(&selection.toolchain_manifest_sha256))?;
        let toolchain_sealed = D32SealedDirectory::from_retained(toolchain_retained)?;
        toolchain_sealed.revalidate("D32 Host toolchain mirror before profile evidence")?;
        let toolchain_bin_retained = toolchain_sealed.open_existing_child(OsStr::new("bin"))?;
        let cargo_identity = toolchain_bin_retained
            .probe_file(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)?
            .ok_or_else(|| "D32 Host mirror Cargo image was unavailable".to_string())?;
        let rustc_identity = toolchain_bin_retained
            .probe_file(OsStr::new("rustc.exe"), D32_TOOLCHAIN_FILE_MAX_BYTES)?
            .ok_or_else(|| "D32 Host mirror rustc image was unavailable".to_string())?;
        let rustdoc_identity = toolchain_bin_retained
            .probe_file(OsStr::new("rustdoc.exe"), D32_TOOLCHAIN_FILE_MAX_BYTES)?
            .ok_or_else(|| "D32 Host mirror rustdoc image was unavailable".to_string())?;
        let toolchain_identity = toolchain_sealed.identity();
        let toolchain_manifest_hash = host_toolchain_manifest_hash_retained(&toolchain_sealed)?;
        if toolchain_manifest_hash != selection.toolchain_manifest_sha256
            || toolchain_bin_retained
                .hash_file(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES as usize)?
                != selection.sha256
        {
            return Err("D32 Host toolchain mirror did not match selection".to_string());
        }
        let staged_cargo_hash = toolchain_bin_retained
            .hash_file(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES as usize)?;
        let evidence = HostCargoCheckProfileEvidence {
            executable_identity: cargo_identity.image_wire(),
            executable_sha256: staged_cargo_hash,
            rustc_identity: rustc_identity.image_wire(),
            rustc_sha256: toolchain_bin_retained.hash_file(
                OsStr::new("rustc.exe"),
                D32_TOOLCHAIN_FILE_MAX_BYTES as usize,
            )?,
            rustdoc_identity: rustdoc_identity.image_wire(),
            rustdoc_sha256: toolchain_bin_retained.hash_file(
                OsStr::new("rustdoc.exe"),
                D32_TOOLCHAIN_FILE_MAX_BYTES as usize,
            )?,
            toolchain_root_identity: toolchain_identity.namespace_wire(),
            toolchain_manifest_hash,
            staged_working_directory_identity: "per-action-fresh-run-v1".to_string(),
            environment_policy_hash: CARGO_ENVIRONMENT_POLICY_HASH.to_string(),
            profile_id: PRODUCTION_CARGO_CHECK_PROFILE_ID.to_string(),
        };
        toolchain_sealed.revalidate("D32 Host toolchain mirror after profile evidence")?;
        toolchain_bin_retained.revalidate("D32 Host toolchain bin after profile evidence")?;
        app_data_root_retained.revalidate("D32 Host app-data root after profile evidence")?;
        Ok(evidence)
    }

    #[cfg(test)]
    fn host_cargo_profile_evidence(
        app_data_root: &Path,
    ) -> Result<HostCargoCheckProfileEvidence, String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let root = D32RetainedDirectory::open(&app_data_root)?;
        let selection = host_read_cargo_selection_marker_retained(&root)?;
        host_cargo_profile_evidence_for_selection(&root, &selection)
    }

    fn host_finalize_published_cargo_profile_retained(
        app_data_root_retained: &D32RetainedDirectory,
        published: &HostPublishedCargoProfile,
    ) -> Result<HostCargoCheckProfileEvidence, String> {
        let current_selection = host_read_cargo_selection_marker_retained(app_data_root_retained)?;
        if current_selection != published.selection {
            return Err("D32 Host Cargo selection changed during Vita startup".to_string());
        }
        let current =
            host_cargo_profile_evidence_for_selection(app_data_root_retained, &current_selection)?;
        if current != published.expected_profile_evidence {
            return Err("D32 Host Cargo profile evidence changed during Vita startup".to_string());
        }
        Ok(published.expected_profile_evidence.clone())
    }

    #[cfg(test)]
    fn host_finalize_published_cargo_profile(
        app_data_root: &Path,
        published: &HostPublishedCargoProfile,
    ) -> Result<HostCargoCheckProfileEvidence, String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let root = D32RetainedDirectory::open(&app_data_root)?;
        host_finalize_published_cargo_profile_retained(&root, published)
    }

    fn d32_run_id(session_id: &str, turn_id: &str, tool_call_id: &str) -> String {
        format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{session_id}\u{1f}{turn_id}\u{1f}{tool_call_id}\u{1f}{PRODUCTION_CARGO_CHECK_PROFILE_ID}"
                )
                .as_bytes(),
            )
        )
    }

    #[cfg(test)]
    fn host_cargo_run_source_identity(
        app_data_root: &Path,
        binding: &ProcessBinding,
    ) -> Result<String, String> {
        let app_data_root =
            host_canonical_directory_fence(app_data_root, "D32 Host app-data root")?;
        let app_data_root_retained = D32RetainedDirectory::open(&app_data_root)?;
        host_cargo_run_source_identity_retained(&app_data_root_retained, binding)
    }

    fn host_cargo_run_source_identity_retained(
        app_data_root_retained: &D32RetainedDirectory,
        binding: &ProcessBinding,
    ) -> Result<String, String> {
        app_data_root_retained.revalidate("D32 Host app-data root before run-source read")?;
        let execution_root =
            app_data_root_retained.open_existing_child(OsStr::new(D32_EXECUTION_ROOT_NAME))?;
        let runs_root = execution_root.open_existing_child(OsStr::new(D32_RUNS_DIR_NAME))?;
        let run_root = runs_root.open_existing_child(OsStr::new(&d32_run_id(
            &binding.session_id,
            &binding.turn_id,
            &binding.tool_call_id,
        )))?;
        let source = run_root.open_existing_child(OsStr::new(D32_SOURCE_DIR_NAME))?;
        execution_root.revalidate("D32 Host execution root after run-source read")?;
        runs_root.revalidate("D32 Host runs root after run-source read")?;
        run_root.revalidate("D32 Host run root after run-source read")?;
        source.revalidate("D32 Host source root after run-source read")?;
        let identity = source.identity().namespace_wire();
        app_data_root_retained.revalidate("D32 Host app-data root after run-source read")?;
        Ok(identity)
    }

    /// The Host-side turn authority is the security decision point for
    /// provider credentials.  The UI-facing `active_turn_id` and
    /// `turn_phase` fields below are retained as a projection, but are never
    /// consulted to authorize a credential release.  Every credential request
    /// and the Active -> Cancelling transition takes this one mutex.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum HostTurnAuthority {
        Idle,
        Active(HostTurnActive),
        Cancelling(HostTurnActive),
        Terminal {
            turn_id: String,
            phase: protocol::TurnPhase,
        },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct HostTurnActive {
        turn_id: String,
        provider: protocol::ProviderConfiguration,
        binding: protocol::ProviderBinding,
        /// Codex owns this H7 turn namespace.  It is learned only from the
        /// first valid AuthorityEvaluate for this Host generation.
        h7_codex_turn_id: Option<String>,
    }

    fn active_chat_provider_configuration(
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
    ) -> Result<Option<protocol::ProviderConfiguration>, String> {
        let Some(active) = storage
            .get_active_profile(ModelPurpose::Chat)
            .map_err(|error| error.message)?
        else {
            return Ok(None);
        };
        let Some(profile) = storage
            .get_profile(&active.profile_id)
            .map_err(|error| error.message)?
        else {
            return Ok(None);
        };
        if profile.purpose != ModelPurpose::Chat
            || profile.provider_kind != ModelProviderKind::OpenaiCompatible
        {
            return Ok(None);
        }
        let credential_ref =
            SecretIdentifier::new(credential_purpose(ModelPurpose::Chat), profile.id.clone())
                .map_err(|_| "Vita Chat credential identifier was invalid".to_string())?;
        if !secrets
            .has_secret(&credential_ref)
            .map_err(|_| "Vita Chat credential availability could not be checked".to_string())?
        {
            return Ok(None);
        }
        Ok(Some(protocol::ProviderConfiguration {
            profile_id: profile.id.clone(),
            purpose: profile.purpose.as_str().to_string(),
            provider_kind: profile.provider_kind.as_str().to_string(),
            base_url: profile.base_url.clone(),
            model: profile.model_name.clone(),
            credential_ref: profile.id.clone(),
            credential_destination: profile.base_url,
        }))
    }

    #[cfg(any(test, feature = "d32-a-host-canary"))]
    /// D32's mandatory real-canary gate must fail closed when the active Chat
    /// provider is unavailable.  The normal production entry point retains
    /// its existing provider/readiness semantics; this helper is the harness
    /// preflight and negative-evidence assertion.
    fn require_production_provider(
        provider: Option<protocol::ProviderConfiguration>,
    ) -> Result<protocol::ProviderConfiguration, String> {
        let provider = provider.ok_or_else(|| {
            "D32_A_NOT_EXECUTABLE: active Chat provider profile or credential is unavailable"
                .to_string()
        })?;
        let endpoint = reqwest::Url::parse(&provider.base_url).map_err(|_| {
            "D32_A_NOT_EXECUTABLE: active Chat provider endpoint is invalid".to_string()
        })?;
        let host = endpoint.host_str().unwrap_or_default();
        let local_host_name = ["local", "host"].concat();
        let loopback_address = host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
        if endpoint.scheme() != "https"
            || host.is_empty()
            || host.eq_ignore_ascii_case(&local_host_name)
            || loopback_address
        {
            return Err(
                "D32_A_NOT_EXECUTABLE: active Chat provider endpoint must be HTTPS with a non-loopback host".to_string(),
            );
        }
        if provider.model.trim().is_empty() {
            return Err("D32_A_NOT_EXECUTABLE: active Chat provider model is missing".to_string());
        }
        Ok(provider)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    pub(super) fn d32_a_preflight_chat_provider(
        identifier: &str,
        mode: &str,
    ) -> Result<(), String> {
        D32HostCanaryMode::parse(mode)?;
        host_select_cargo_image()
            .map_err(|error| d32_not_executable(format!("toolchain preflight failed: {error}")))?;
        let app_data_root = std::env::var_os("D32_A_CANARY_APP_DATA_ROOT")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("APPDATA")
                    .map(PathBuf::from)
                    .map(|root| root.join(identifier))
            })
            .ok_or_else(|| d32_not_executable("Windows RoamingAppData root is unavailable"))?;
        let profile = crate::storage::d32_a_read_only_chat_provider_profile(&app_data_root)
            .map_err(|error| {
                d32_not_executable(format!("provider metadata read failed: {error:?}"))
            })?;
        let Some((profile_id, base_url, model)) = profile else {
            return Err(d32_not_executable(
                "active Chat provider profile or credential is unavailable",
            ));
        };
        let credential_ref =
            SecretIdentifier::new(credential_purpose(ModelPurpose::Chat), profile_id.clone())
                .map_err(|_| {
                    d32_not_executable("active Chat provider credential identifier is invalid")
                })?;
        let secrets = WindowsCredentialSecretStore::new();
        if !secrets.has_secret(&credential_ref).map_err(|_| {
            d32_not_executable("active Chat provider credential could not be checked")
        })? {
            return Err(d32_not_executable(
                "active Chat provider profile or credential is unavailable",
            ));
        }
        let provider = protocol::ProviderConfiguration {
            profile_id: profile_id.clone(),
            purpose: ModelPurpose::Chat.as_str().to_string(),
            provider_kind: ModelProviderKind::OpenaiCompatible.as_str().to_string(),
            base_url: base_url.clone(),
            model,
            credential_ref: profile_id,
            credential_destination: base_url,
        };
        require_production_provider(Some(provider)).map(|_| ())
    }

    fn current_chat_provider_configuration(
        coordinator: &VitaSidecarCoordinator,
    ) -> Result<Option<protocol::ProviderConfiguration>, String> {
        #[cfg(test)]
        if let Ok(provider) = coordinator.test_provider_override.lock() {
            if provider.is_some() {
                return Ok(provider.clone());
            }
        }
        active_chat_provider_configuration(
            &coordinator.authority_storage,
            &coordinator.credential_store,
        )
    }

    fn observed_current_life(
        storage: &StorageService,
        observed_life_id: &str,
    ) -> Result<crate::storage::LifeIdentityRecord, String> {
        let current = storage
            .get_current_life()
            .map_err(|_| LIFE_UNAVAILABLE.to_string())?
            .ok_or_else(|| LIFE_UNAVAILABLE.to_string())?;
        if current.id != observed_life_id {
            return Err(RUNTIME_LIFE_CHANGED.to_string());
        }
        Ok(current)
    }

    fn current_life_id(storage: &StorageService) -> Result<String, String> {
        storage
            .get_current_life()
            .map_err(|_| LIFE_UNAVAILABLE.to_string())?
            .map(|life| life.id)
            .ok_or_else(|| LIFE_UNAVAILABLE.to_string())
    }

    fn require_current_session_life(
        storage: &StorageService,
        session: &HostSessionState,
    ) -> Result<(), String> {
        let current_life_id = current_life_id(storage)?;
        if current_life_id != session.life_id {
            return Err(LIFE_RESTART_REQUIRED.to_string());
        }
        Ok(())
    }

    fn require_current_session_life_in_scope(
        authority: &crate::storage::CapabilityAuthorizationScope<'_>,
        session: &HostSessionState,
    ) -> Result<(), String> {
        let current_life_id = authority
            .current_life_id()
            .map_err(|_| LIFE_UNAVAILABLE.to_string())?
            .ok_or_else(|| LIFE_UNAVAILABLE.to_string())?;
        if current_life_id != session.life_id {
            return Err(LIFE_RESTART_REQUIRED.to_string());
        }
        Ok(())
    }

    fn requested_scope_for(requirement: ScopeRequirement) -> RequestedCapabilityScope {
        match requirement {
            ScopeRequirement::None => RequestedCapabilityScope::None,
            ScopeRequirement::WorkspaceRequired => RequestedCapabilityScope::Workspace,
            ScopeRequirement::NetworkDestinationRequired => {
                RequestedCapabilityScope::NetworkDestination
            }
            ScopeRequirement::ExternalResourceRequired => {
                RequestedCapabilityScope::ExternalResource
            }
        }
    }

    fn root_is_usable(
        decision: &crate::capability::authorization::CapabilityAuthorizationDecision,
    ) -> bool {
        decision.authorization_revision().is_some()
            && matches!(
                decision.outcome(),
                CapabilityAuthorizationDecisionKind::ScopeRequired
                    | CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired
                    | CapabilityAuthorizationDecisionKind::Eligible
            )
    }

    /// Freshly read every trusted registry root immediately before Host turn
    /// admission.  This is only an admission summary: it neither caches an
    /// authorization revision nor creates scope, confirmation, or grant
    /// authority for any individual tool.
    #[allow(dead_code)]
    fn preflight_capability_roots(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
    ) -> Result<(), String> {
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(|error| error.code.clone())?;
        preflight_capability_roots_in_scope(&authority_scope, registry, session)
    }

    fn preflight_capability_roots_in_scope(
        authority: &crate::storage::CapabilityAuthorizationScope<'_>,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
    ) -> Result<(), String> {
        let mut any_disabled = false;
        let mut any_missing = false;
        let mut any_unavailable = false;
        for descriptor in registry.entries() {
            let capability_id = descriptor.capability_id();
            match authority.find_capability_authorization(&session.life_id, capability_id) {
                Ok(None) => {
                    any_missing = true;
                    continue;
                }
                Err(error) => {
                    if matches!(
                        error.code,
                        CapabilityAuthorizationErrorCode::AuthorityRestartRequired
                    ) {
                        return Err(CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string());
                    }
                    any_unavailable = true;
                    continue;
                }
                Ok(Some(_)) => {}
            }
            match evaluate_capability_authorization_in_scope(
                authority,
                registry,
                &session.life_id,
                capability_id,
                requested_scope_for(descriptor.scope_requirement()),
            ) {
                Ok(decision) if root_is_usable(&decision) => return Ok(()),
                Ok(decision)
                    if decision.outcome() == CapabilityAuthorizationDecisionKind::RootDisabled =>
                {
                    any_disabled = true;
                }
                Ok(_) => any_unavailable = true,
                Err(error)
                    if matches!(
                        error.code,
                        CapabilityEvaluationErrorCode::AuthorityRestartRequired
                    ) =>
                {
                    return Err(CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string())
                }
                Err(_) => any_unavailable = true,
            }
        }
        if any_disabled {
            Err("CAPABILITY_ROOT_DISABLED".to_string())
        } else if any_missing {
            Err("CAPABILITY_AUTHORIZATION_REQUIRED".to_string())
        } else if any_unavailable {
            Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())
        } else {
            Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())
        }
    }

    fn active_workspace_read_turn_matches(
        authority: &HostTurnAuthority,
        host_turn_id: &str,
        binding: &protocol::WorkspaceReadBinding,
    ) -> bool {
        matches!(
            authority,
                HostTurnAuthority::Active(active)
                    if active.turn_id == host_turn_id
                        && active.binding.binding_hash == binding.provider_binding_hash
                        && active.h7_codex_turn_id.as_deref()
                            == Some(binding.codex_turn_id.as_str())
        )
    }

    #[allow(dead_code)]
    fn current_workspace_read_revision(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &protocol::WorkspaceReadBinding,
    ) -> Result<i64, String> {
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        current_workspace_read_revision_in_scope(&authority_scope, registry, session, binding)
    }

    fn current_workspace_read_revision_in_scope(
        authority: &crate::storage::CapabilityAuthorizationScope<'_>,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &protocol::WorkspaceReadBinding,
    ) -> Result<i64, String> {
        validate_workspace_read_binding(session, binding)?;
        let capability_id = CapabilityId::try_from(binding.capability_id.as_str())
            .map_err(|_| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())?;
        let descriptor = registry
            .descriptor(&capability_id)
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_REQUIRED".to_string())?;
        let decision = evaluate_capability_authorization_in_scope(
            authority,
            registry,
            &session.life_id,
            &capability_id,
            requested_scope_for(descriptor.scope_requirement()),
        )
        .map_err(|error| {
            if matches!(
                error.code,
                CapabilityEvaluationErrorCode::AuthorityRestartRequired
            ) {
                CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string()
            } else {
                "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string()
            }
        })?;
        if decision.outcome() == CapabilityAuthorizationDecisionKind::RootDisabled {
            return Err("CAPABILITY_ROOT_DISABLED".to_string());
        }
        if !root_is_usable(&decision) {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())
    }

    fn validate_workspace_read_binding(
        session: &HostSessionState,
        binding: &protocol::WorkspaceReadBinding,
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "WORKSPACE_READ_BINDING_MISMATCH".to_string())?;
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || binding.capability_id != PRODUCTION_WORKSPACE_READ_CAPABILITY_ID
            || binding.tool_name != PRODUCTION_WORKSPACE_READ_TOOL_NAME
            || binding.workspace_root_identity != session.workspace_identity
            || !matches!(binding.target_kind, protocol::WorkspaceReadTargetKind::File)
            || binding.max_bytes == 0
            || binding.max_bytes > protocol::MAX_WORKSPACE_READ_BYTES
            || binding.provider_binding_hash.len() != 64
            || !binding
                .provider_binding_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("WORKSPACE_READ_BINDING_MISMATCH".to_string());
        }
        Ok(())
    }

    fn active_workspace_replace_turn_matches(
        authority: &HostTurnAuthority,
        host_turn_id: &str,
        binding: &protocol::WorkspaceReplaceBinding,
    ) -> bool {
        matches!(
            authority,
            HostTurnAuthority::Active(active)
                if active.turn_id == host_turn_id
                    && active.binding.binding_hash == binding.provider_binding_hash
                    && active.h7_codex_turn_id.as_deref()
                        == Some(binding.codex_turn_id.as_str())
        )
    }

    fn validate_workspace_replace_binding(
        session: &HostSessionState,
        binding: &protocol::WorkspaceReplaceBinding,
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "WORKSPACE_REPLACE_BINDING_MISMATCH".to_string())?;
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || binding.capability_id != PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID
            || binding.tool_name != PRODUCTION_WORKSPACE_REPLACE_TOOL_NAME
            || binding.workspace_root_identity != session.workspace_identity
            || !matches!(
                binding.target_kind,
                protocol::WorkspaceReplaceTargetKind::File
            )
            || binding.replacement_bytes > protocol::MAX_WORKSPACE_READ_BYTES
            || binding.provider_binding_hash.len() != 64
            || !binding
                .provider_binding_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("WORKSPACE_REPLACE_BINDING_MISMATCH".to_string());
        }
        Ok(())
    }

    fn current_workspace_replace_revision(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &protocol::WorkspaceReplaceBinding,
    ) -> Result<i64, String> {
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        current_workspace_replace_revision_in_scope(&authority_scope, registry, session, binding)
    }

    fn current_workspace_replace_revision_in_scope(
        authority: &crate::storage::CapabilityAuthorizationScope<'_>,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &protocol::WorkspaceReplaceBinding,
    ) -> Result<i64, String> {
        validate_workspace_replace_binding(session, binding)?;
        let capability_id = CapabilityId::try_from(binding.capability_id.as_str())
            .map_err(|_| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())?;
        let descriptor = registry
            .descriptor(&capability_id)
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_REQUIRED".to_string())?;
        if descriptor.execution_profile() != Some(PRODUCTION_WORKSPACE_REPLACE_PROFILE_ID)
            || descriptor.tool_name() != Some(PRODUCTION_WORKSPACE_REPLACE_TOOL_NAME)
            || descriptor.is_read_only()
            || descriptor.approval_floor()
                != crate::capability::descriptor::ApprovalFloor::ExplicitPerAction
            || descriptor.scope_requirement() != ScopeRequirement::WorkspaceRequired
        {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        let decision = evaluate_capability_authorization_in_scope(
            authority,
            registry,
            &session.life_id,
            &capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|error| {
            if matches!(
                error.code,
                CapabilityEvaluationErrorCode::AuthorityRestartRequired
            ) {
                CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string()
            } else {
                "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string()
            }
        })?;
        if decision.outcome() == CapabilityAuthorizationDecisionKind::RootDisabled {
            return Err("CAPABILITY_ROOT_DISABLED".to_string());
        }
        if !root_is_usable(&decision) {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())
    }

    fn validate_recovery_binding(
        session: &HostSessionState,
        binding: &protocol::RecoveryBinding,
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "RECOVERY_BINDING_MISMATCH".to_string())?;
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || binding.capability_id != PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID
            || binding.workspace_root_identity != session.workspace_identity
        {
            return Err("RECOVERY_BINDING_MISMATCH".to_string());
        }
        Ok(())
    }

    fn recovery_action_matches(
        action: &HostRecoveryAction,
        binding: &protocol::RecoveryBinding,
    ) -> bool {
        let pending = &action.pending;
        action.recovery_action_id == binding.recovery_action_id
            && action.recovery_generation == binding.recovery_generation
            && action.transaction_id == binding.transaction_id
            && pending.life_id == binding.life_id
            && pending.task_id == binding.task_id
            && pending.capability_id == binding.capability_id
            && pending.workspace_root_identity == binding.workspace_root_identity
            && pending.relative_path == binding.relative_path
            && pending.target_identity == binding.target_identity
            && pending.journal_integrity_hash == binding.journal_integrity_hash
            && pending.current_sha256 == binding.current_sha256
            && pending.current_bytes == binding.current_bytes
            && pending.restore_sha256 == binding.restore_sha256
            && pending.restore_bytes == binding.restore_bytes
            && pending.original_replacement_sha256 == binding.original_replacement_sha256
    }

    fn current_recovery_revision_in_scope(
        authority_scope: &crate::storage::CapabilityAuthorizationScope<'_>,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &protocol::RecoveryBinding,
    ) -> Result<i64, String> {
        validate_recovery_binding(session, binding)?;
        let capability_id = CapabilityId::try_from(binding.capability_id.as_str())
            .map_err(|_| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())?;
        let descriptor = registry
            .descriptor(&capability_id)
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_REQUIRED".to_string())?;
        if descriptor.execution_profile() != Some(PRODUCTION_WORKSPACE_RECOVER_PROFILE_ID)
            || descriptor.tool_name().is_some()
            || descriptor.is_read_only()
            || descriptor.approval_floor()
                != crate::capability::descriptor::ApprovalFloor::ExplicitPerAction
            || descriptor.scope_requirement() != ScopeRequirement::WorkspaceRequired
        {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        let decision = evaluate_capability_authorization_in_scope(
            authority_scope,
            registry,
            &session.life_id,
            &capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|error| {
            if matches!(
                error.code,
                CapabilityEvaluationErrorCode::AuthorityRestartRequired
            ) {
                CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string()
            } else {
                "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string()
            }
        })?;
        if decision.outcome() == CapabilityAuthorizationDecisionKind::RootDisabled {
            return Err("CAPABILITY_ROOT_DISABLED".to_string());
        }
        if !root_is_usable(&decision) {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string())
    }

    /// Host-owned grant issue helper for the production workspace-read loop.  A
    /// confirmation ID can enter this function only through the Host-owned
    /// approved-action ledger.
    #[allow(dead_code)]
    fn issue_workspace_read_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReadIssueGrant,
    ) -> Result<WorkspaceReadGrant, String> {
        request
            .validate()
            .map_err(|_| "WORKSPACE_READ_ISSUE_INVALID".to_string())?;
        validate_workspace_read_binding(session, &request.binding)?;
        if request.session_id != session.session_id
            || request.binding.session_id != session.session_id
            || request.binding.life_id != session.life_id
            || request.binding.task_id != session.task_id
        {
            return Err("WORKSPACE_READ_BINDING_MISMATCH".to_string());
        }
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_read_turn_matches(&authority, &request.host_turn_id, &request.binding)
        {
            return Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string());
        }
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        require_current_session_life(storage, session)?;
        let current_revision = current_workspace_read_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        if current_revision != request.authorization_revision {
            return Err("CAPABILITY_AUTHORIZATION_REVISION_MISMATCH".to_string());
        }

        let approval_key = workspace_read_approval_key(&request.host_turn_id, &request.binding);
        let mut approvals = session
            .workspace_read_approvals
            .lock()
            .map_err(|_| "Vita workspace read approval state lock was poisoned".to_string())?;
        let approval = approvals
            .get(&approval_key)
            .cloned()
            .ok_or_else(|| "WORKSPACE_READ_CONFIRMATION_NOT_APPROVED".to_string())?;
        if approval.host_turn_id != request.host_turn_id
            || approval.binding != request.binding
            || approval.authorization_revision != request.authorization_revision
            || approval.expires_at_unix_ms <= unix_millis()
        {
            return Err("WORKSPACE_READ_CONFIRMATION_STALE".to_string());
        }

        let now = unix_millis();
        let expires_at_unix_ms = approval
            .expires_at_unix_ms
            .min(now.saturating_add(GRANT_LIFETIME_MS));
        if expires_at_unix_ms <= now {
            return Err("WORKSPACE_READ_GRANT_EXPIRED".to_string());
        }
        let grant = WorkspaceReadGrant {
            session_id: session.session_id.clone(),
            grant_id: secure_id("vita-read-grant")?,
            confirmation_id: approval.confirmation_id,
            binding: request.binding.clone(),
            authorization_revision: request.authorization_revision,
            issued_at_unix_ms: now,
            expires_at_unix_ms,
            single_use: true,
            used: false,
        };
        grant
            .validate()
            .map_err(|_| "WORKSPACE_READ_GRANT_INVALID".to_string())?;
        let mut grants = session
            .workspace_read_grants
            .lock()
            .map_err(|_| "Vita workspace read grant state lock was poisoned".to_string())?;
        reap_expired_workspace_read_grants(&mut grants);
        if grants.len() >= MAX_GRANTS {
            return Err("WORKSPACE_READ_GRANT_CAPACITY_EXHAUSTED".to_string());
        }
        approvals.remove(&approval_key);
        grants.insert(
            grant.grant_id.clone(),
            WorkspaceReadGrantState {
                host_turn_id: request.host_turn_id.clone(),
                grant: grant.clone(),
                phase: WorkspaceReadGrantPhase::Issued,
            },
        );
        Ok(grant)
    }

    /// The pre-read authorization commit is `Issued -> Revalidated`, and it
    /// uses the same Host-owned linearizer as D30 CAS updates and disclosure
    /// release.  Lock order is
    /// `turn_authority -> capability_authorization_gate
    /// -> workspace_read_grants -> StorageService state`; the linearizer is
    /// released as soon as the in-memory pre-read commit is complete, before
    /// any future filesystem I/O.
    #[allow(dead_code)]
    fn revalidate_workspace_read_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReadRevalidateGrant,
    ) -> Result<WorkspaceReadGrant, String> {
        request
            .validate()
            .map_err(|_| "WORKSPACE_READ_REVALIDATION_INVALID".to_string())?;
        validate_workspace_read_binding(session, &request.binding)?;
        if request.grant.used {
            return Err("WORKSPACE_READ_GRANT_ALREADY_REVALIDATED".to_string());
        }
        if request.session_id != session.session_id
            || request.grant.session_id != session.session_id
            || request.binding.session_id != session.session_id
        {
            return Err("WORKSPACE_READ_BINDING_MISMATCH".to_string());
        }
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_read_turn_matches(&authority, &request.host_turn_id, &request.binding)
        {
            return Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string());
        }
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        let mut grants = session
            .workspace_read_grants
            .lock()
            .map_err(|_| "Vita workspace read grant state lock was poisoned".to_string())?;
        let state = grants
            .get_mut(&request.grant.grant_id)
            .ok_or_else(|| "WORKSPACE_READ_GRANT_NOT_FOUND".to_string())?;
        if state.host_turn_id != request.host_turn_id
            || state.phase != WorkspaceReadGrantPhase::Issued
            || state.grant != request.grant
            || state.grant.binding != request.binding
            || state.grant.expires_at_unix_ms <= unix_millis()
            || !state.grant.single_use
        {
            return Err("WORKSPACE_READ_GRANT_REVALIDATION_DENIED".to_string());
        }
        require_current_session_life(storage, session)?;
        let current_revision = current_workspace_read_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        if state.grant.authorization_revision != current_revision {
            return Err("CAPABILITY_AUTHORIZATION_REVISION_MISMATCH".to_string());
        }
        state.grant.used = true;
        state.phase = WorkspaceReadGrantPhase::Revalidated;
        let revalidated = state.grant.clone();
        drop(grants);
        drop(authority_scope);
        drop(authority);
        Ok(revalidated)
    }

    /// Host release decision linearization point.  The caller may write the
    /// post-read IPC response only after this function commits `Revalidated →
    /// Released` under the turn authority and the shared capability
    /// authorization linearizer used by D30 revocation.
    #[allow(dead_code)]
    fn authorize_workspace_read_release(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReadReleaseCheck,
        confidential_bytes: &[u8],
    ) -> Result<(), String> {
        authorize_workspace_read_release_inner(
            storage,
            registry,
            session,
            request,
            Some(confidential_bytes),
        )
    }

    /// Production release path.  The Host receives only the bounded byte
    /// count and digest from Vita; the confidential bytes stay in the
    /// process-isolated sidecar and are never copied into Host memory.
    fn authorize_workspace_read_release_evidence(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReadReleaseCheck,
    ) -> Result<(), String> {
        authorize_workspace_read_release_inner(storage, registry, session, request, None)
    }

    fn authorize_workspace_read_release_inner(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReadReleaseCheck,
        confidential_bytes: Option<&[u8]>,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "WORKSPACE_READ_RELEASE_EVIDENCE_INVALID".to_string())?;
        validate_workspace_read_binding(session, &request.binding)?;
        if request.session_id != session.session_id
            || request.binding.session_id != session.session_id
            || request.binding.life_id != session.life_id
            || request.binding.task_id != session.task_id
        {
            return Err("WORKSPACE_READ_BINDING_MISMATCH".to_string());
        }
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_read_turn_matches(&authority, &request.host_turn_id, &request.binding)
        {
            return Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string());
        }
        // The turn authority is acquired first, then the shared Host-owned
        // capability linearizer, then the exact grant ledger, and only then
        // fresh D28 storage reads.  D30's enable/disable CAS takes the same
        // linearizer before its SQLite IMMEDIATE commit, so exactly one of
        // revoke or release linearizes first.  No IPC write happens while
        // either decision is pending.
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        let mut grants = session
            .workspace_read_grants
            .lock()
            .map_err(|_| "Vita workspace read grant state lock was poisoned".to_string())?;
        let state = grants
            .get_mut(&request.grant.grant_id)
            .ok_or_else(|| "WORKSPACE_READ_GRANT_NOT_FOUND".to_string())?;
        if state.host_turn_id != request.host_turn_id
            || state.phase != WorkspaceReadGrantPhase::Revalidated
            || state.grant != request.grant
            || state.grant.binding != request.binding
            || !state.grant.used
        {
            return Err("WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH".to_string());
        }
        require_current_session_life(storage, session)?;
        // D28 is read inside the release decision while the shared
        // linearizer is still held.  A revocation that commits first is
        // observed here and denies; a release that commits first is already
        // ordered before a later revocation.
        let current_revision = current_workspace_read_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        if current_revision != state.grant.authorization_revision {
            return Err("CAPABILITY_AUTHORIZATION_REVISION_MISMATCH".to_string());
        }
        if state.grant.expires_at_unix_ms <= unix_millis() {
            return Err("WORKSPACE_READ_GRANT_EXPIRED".to_string());
        }
        if request.bytes_read > request.binding.max_bytes {
            return Err("WORKSPACE_READ_CONTENT_EVIDENCE_MISMATCH".to_string());
        }
        if let Some(confidential_bytes) = confidential_bytes {
            if u64::try_from(confidential_bytes.len()).ok() != Some(request.bytes_read)
                || format!("{:x}", Sha256::digest(confidential_bytes)) != request.content_sha256
            {
                return Err("WORKSPACE_READ_CONTENT_EVIDENCE_MISMATCH".to_string());
            }
        }
        // This assignment is the authoritative disclosure decision.  The
        // later IPC write is transport only and cannot authorize a replay.
        state.phase = WorkspaceReadGrantPhase::Released;
        drop(grants);
        drop(authority_scope);
        drop(authority);
        Ok(())
    }

    fn capability_state(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        life_id: &str,
        descriptor: &crate::capability::descriptor::CapabilityDescriptor,
    ) -> VitaCapabilityState {
        let capability_id = descriptor.capability_id();
        let state = match storage.find_capability_authorization(life_id, capability_id) {
            Ok(None) => (VitaCapabilityReadiness::AuthorizationMissing, None),
            Err(error)
                if matches!(
                    error.code,
                    crate::capability::authorization::CapabilityAuthorizationErrorCode::AuthorityRestartRequired
                ) => (VitaCapabilityReadiness::LifeRestartRequired, None),
            Err(_) => (VitaCapabilityReadiness::AuthorizationUnavailable, None),
            Ok(Some(row)) => match evaluate_capability_authorization(
                storage,
                registry,
                life_id,
                capability_id,
                requested_scope_for(descriptor.scope_requirement()),
            ) {
                Ok(decision) if root_is_usable(&decision) => (
                    VitaCapabilityReadiness::RootEnabled,
                    decision.authorization_revision(),
                ),
                Ok(decision)
                    if decision.outcome() == CapabilityAuthorizationDecisionKind::RootDisabled =>
                {
                    (VitaCapabilityReadiness::RootDisabled, Some(row.revision))
                }
                Ok(_) => (VitaCapabilityReadiness::AuthorizationUnavailable, None),
                Err(error)
                    if matches!(
                        error.code,
                        CapabilityEvaluationErrorCode::AuthorityRestartRequired
                    ) => (VitaCapabilityReadiness::LifeRestartRequired, None),
                Err(_) => (VitaCapabilityReadiness::AuthorizationUnavailable, None),
            },
        };
        VitaCapabilityState {
            capability_id: capability_id.as_str().to_string(),
            readiness: state.0,
            revision: state.1,
        }
    }

    /// Project display-safe trusted registry state.  The current Life is read
    /// fresh for every status call, and a running session never borrows an
    /// authorization row of a different current Life.
    fn capability_readiness(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session_life_id: Option<&str>,
    ) -> (
        VitaCapabilityReadiness,
        Vec<VitaCapabilityState>,
        Option<String>,
    ) {
        if storage.ensure_capability_authority_current().is_err() {
            return (
                VitaCapabilityReadiness::LifeRestartRequired,
                Vec::new(),
                None,
            );
        }
        let current = match storage.get_current_life() {
            Ok(Some(life)) => life,
            Ok(None) | Err(_) => {
                return (
                    VitaCapabilityReadiness::AuthorizationUnavailable,
                    Vec::new(),
                    None,
                )
            }
        };
        let current_life_id = current.id.clone();
        let life_id = session_life_id.unwrap_or(current.id.as_str());
        if session_life_id.is_some_and(|session_life_id| session_life_id != current.id) {
            return (
                VitaCapabilityReadiness::LifeRestartRequired,
                Vec::new(),
                Some(current_life_id),
            );
        }
        let states = registry
            .entries()
            .map(|descriptor| capability_state(storage, registry, life_id, descriptor))
            .collect::<Vec<_>>();
        let aggregate = if states
            .iter()
            .any(|state| state.readiness == VitaCapabilityReadiness::LifeRestartRequired)
        {
            VitaCapabilityReadiness::LifeRestartRequired
        } else if states
            .iter()
            .any(|state| state.readiness == VitaCapabilityReadiness::RootEnabled)
        {
            VitaCapabilityReadiness::RootEnabled
        } else if states
            .iter()
            .any(|state| state.readiness == VitaCapabilityReadiness::RootDisabled)
        {
            VitaCapabilityReadiness::RootDisabled
        } else if states
            .iter()
            .any(|state| state.readiness == VitaCapabilityReadiness::AuthorizationMissing)
        {
            VitaCapabilityReadiness::AuthorizationMissing
        } else {
            VitaCapabilityReadiness::AuthorizationUnavailable
        };
        (aggregate, states, Some(current_life_id))
    }

    fn provider_readiness(
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
        running: bool,
        turn_active: bool,
        session_provider: Option<&protocol::ProviderConfiguration>,
    ) -> Result<VitaProviderReadiness, String> {
        let current_provider = active_chat_provider_configuration(storage, secrets)?;
        if sidecar_provider_requires_restart(running, session_provider, current_provider.as_ref()) {
            return Ok(VitaProviderReadiness::SidecarRestartRequired);
        }
        let Some(active) = storage
            .get_active_profile(ModelPurpose::Chat)
            .map_err(|error| error.message)?
        else {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        };
        let Some(profile) = storage
            .get_profile(&active.profile_id)
            .map_err(|error| error.message)?
        else {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        };
        if profile.purpose != ModelPurpose::Chat
            || profile.provider_kind != ModelProviderKind::OpenaiCompatible
        {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        }
        let identifier =
            SecretIdentifier::new(credential_purpose(ModelPurpose::Chat), profile.id.clone())
                .map_err(|_| "Vita Chat credential identifier was invalid".to_string())?;
        if !secrets
            .has_secret(&identifier)
            .map_err(|_| "Vita Chat credential availability could not be checked".to_string())?
        {
            return Ok(VitaProviderReadiness::CredentialMissing);
        }
        let url = reqwest::Url::parse(&profile.base_url)
            .map_err(|_| "Vita Chat provider URL was invalid".to_string())?;
        if url.scheme() != "https" {
            return Ok(VitaProviderReadiness::IneligibleUrl);
        }
        if !running {
            return Ok(VitaProviderReadiness::SidecarNotRunning);
        }
        if turn_active {
            return Ok(VitaProviderReadiness::TurnActive);
        }
        Ok(VitaProviderReadiness::Ready)
    }

    fn sidecar_provider_requires_restart(
        running: bool,
        session_provider: Option<&protocol::ProviderConfiguration>,
        current_provider: Option<&protocol::ProviderConfiguration>,
    ) -> bool {
        running && session_provider != current_provider
    }

    #[derive(Default)]
    pub(super) struct WindowsCoordinatorState {
        running: Option<RunningSidecar>,
        starting: bool,
        #[cfg(test)]
        test_session: Option<Arc<HostSessionState>>,
    }

    pub(super) use self::WindowsCoordinatorState as StateType;

    struct RunningSidecar {
        session: Arc<HostSessionState>,
        process: VitaSidecarProcess,
        reader: Option<JoinHandle<()>>,
    }

    impl RunningSidecar {
        fn stop(mut self) {
            let _ = self
                .session
                .send(&HostMessage::Shutdown(protocol::Shutdown {
                    request_id: next_id("host-shutdown"),
                    session_id: self.session.session_id.clone(),
                }));
            self.session.retire();
            self.session.close_writer();
            let _ = self.process.shutdown();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    struct HostSessionState {
        session_id: String,
        life_id: String,
        task_id: String,
        workspace_identity: String,
        cargo_profile: Option<HostCargoCheckProfileEvidence>,
        // The app-data authority is acquired once during sidecar startup and
        // retained for the complete session.  Production evidence and Cargo
        // binding checks must use this capability rather than reopening the
        // Initialize pathname.
        app_data_root_retained: Option<Arc<D32RetainedDirectory>>,
        provider: Option<protocol::ProviderConfiguration>,
        writer: Mutex<Option<BufWriter<File>>>,
        pending: Mutex<HashMap<String, PendingAction>>,
        workspace_read_pending: Mutex<HashMap<String, WorkspaceReadPendingAction>>,
        workspace_replace_pending: Mutex<HashMap<String, WorkspaceReplacePendingAction>>,
        approvals: Mutex<HashMap<String, ApprovedAction>>,
        grants: Mutex<HashMap<String, HostStoredGrant>>,
        workspace_read_approvals: Mutex<HashMap<String, WorkspaceReadApprovedAction>>,
        workspace_read_grants: Mutex<HashMap<String, WorkspaceReadGrantState>>,
        workspace_replace_approvals: Mutex<HashMap<String, WorkspaceReplaceApprovedAction>>,
        workspace_replace_grants: Mutex<HashMap<String, WorkspaceReplaceGrantState>>,
        recovery_pending: Mutex<HashMap<String, RecoveryPendingAction>>,
        recovery_scan_pending: Mutex<HashMap<String, protocol::RecoveryPending>>,
        recovery_actions: Mutex<HashMap<String, HostRecoveryAction>>,
        recovery_approvals: Mutex<HashMap<String, RecoveryApprovedAction>>,
        recovery_grants: Mutex<HashMap<String, RecoveryGrantState>>,
        replay: Mutex<RequestReplayWindow>,
        expiry: Arc<ExpiryOwner>,
        closed: AtomicBool,
        turn_authority: Mutex<HostTurnAuthority>,
        active_turn_id: Mutex<Option<String>>,
        turn_phase: Mutex<Option<protocol::TurnPhase>>,
        assistant_text: Mutex<Option<String>>,
        turn_error: Mutex<Option<String>>,
        recovery_result: Mutex<Option<protocol::RecoveryResult>>,
        #[cfg(feature = "d32-a-host-canary")]
        canary_control: Option<Arc<D32HostCanaryControl>>,
        #[cfg(test)]
        test_outbound: Mutex<Option<mpsc::Sender<HostMessage>>>,
    }

    #[derive(Clone)]
    struct PendingAction {
        pending_id: String,
        request_id: String,
        host_turn_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_summary: String,
        expires_at_unix_ms: u64,
        binding: ProcessBinding,
    }

    #[derive(Clone)]
    struct WorkspaceReadPendingAction {
        pending_id: String,
        request_id: String,
        host_turn_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_summary: String,
        expires_at_unix_ms: u64,
        binding: protocol::WorkspaceReadBinding,
    }

    #[derive(Clone)]
    struct WorkspaceReplacePendingAction {
        pending_id: String,
        request_id: String,
        host_turn_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_summary: String,
        expires_at_unix_ms: u64,
        binding: protocol::WorkspaceReplaceBinding,
    }

    #[derive(Clone)]
    struct RecoveryPendingAction {
        pending_id: String,
        request_id: String,
        recovery_action_id: String,
        recovery_generation: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_summary: String,
        expires_at_unix_ms: u64,
        binding: protocol::RecoveryBinding,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum HostRecoveryActionPhase {
        Requested,
        AwaitingAuthority,
        AwaitingConfirmation,
        GrantIssued,
        Revalidated,
    }

    /// Host-owned recovery action ledger.  This is deliberately separate from
    /// the model-turn authority so restart recovery never depends on a
    /// ProviderRequestIdentity or an active Codex turn.
    #[derive(Clone)]
    struct HostRecoveryAction {
        recovery_action_id: String,
        recovery_generation: String,
        transaction_id: String,
        pending: protocol::RecoveryPending,
        phase: HostRecoveryActionPhase,
    }

    struct ApprovedAction {
        host_turn_id: String,
        binding: ProcessBinding,
        authorization_revision: i64,
        confirmation_id: String,
        expires_at_unix_ms: u64,
    }

    /// Host-owned generation evidence.  The wire ProcessGrant intentionally
    /// remains unchanged; this wrapper prevents a later Host turn from
    /// replaying an unconsumed grant that was minted for an older turn.
    #[derive(Clone)]
    struct HostStoredGrant {
        host_turn_id: String,
        grant: ProcessGrant,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WorkspaceReadGrantPhase {
        Issued,
        Revalidated,
        Released,
    }

    /// Host-only confirmation evidence for the future workspace-read lane.
    /// The wire request never carries a confirmation ID; issue derives it
    /// only from this Host-owned state.
    #[derive(Clone)]
    struct WorkspaceReadApprovedAction {
        host_turn_id: String,
        binding: protocol::WorkspaceReadBinding,
        authorization_revision: i64,
        confirmation_id: String,
        expires_at_unix_ms: u64,
    }

    /// The read grant ledger is separate from the frozen H7 ProcessGrant
    /// ledger.  `phase` is authoritative Host state; the wire `used` bit is
    /// only the stage projection required by the protocol.
    #[derive(Clone)]
    struct WorkspaceReadGrantState {
        host_turn_id: String,
        grant: WorkspaceReadGrant,
        phase: WorkspaceReadGrantPhase,
    }

    #[derive(Clone)]
    struct WorkspaceReplaceApprovedAction {
        host_turn_id: String,
        binding: protocol::WorkspaceReplaceBinding,
        authorization_revision: i64,
        confirmation_id: String,
        expires_at_unix_ms: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WorkspaceReplaceGrantPhase {
        Issued,
        Revalidated,
    }

    #[derive(Clone)]
    struct WorkspaceReplaceGrantState {
        host_turn_id: String,
        grant: WorkspaceReplaceGrant,
        phase: WorkspaceReplaceGrantPhase,
    }

    #[derive(Clone)]
    struct RecoveryApprovedAction {
        recovery_action_id: String,
        recovery_generation: String,
        binding: protocol::RecoveryBinding,
        authorization_revision: i64,
        confirmation_id: String,
        expires_at_unix_ms: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryGrantPhase {
        Issued,
        Revalidated,
    }

    #[derive(Clone)]
    struct RecoveryGrantState {
        recovery_action_id: String,
        recovery_generation: String,
        grant: RecoveryGrant,
        phase: RecoveryGrantPhase,
    }

    enum PendingCancellation {
        Git(PendingAction),
        WorkspaceRead(WorkspaceReadPendingAction),
        WorkspaceReplace(WorkspaceReplacePendingAction),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExpiryTicket {
        session_id: String,
        pending_id: String,
        request_id: String,
        binding: Option<ProcessBinding>,
        workspace_binding: Option<protocol::WorkspaceReadBinding>,
        workspace_replace_binding: Option<protocol::WorkspaceReplaceBinding>,
        recovery_binding: Option<protocol::RecoveryBinding>,
        expires_at_unix_ms: u64,
    }

    impl ExpiryTicket {
        fn for_pending(session_id: &str, pending: &PendingAction) -> Self {
            Self {
                session_id: session_id.to_string(),
                pending_id: pending.pending_id.clone(),
                request_id: pending.request_id.clone(),
                binding: Some(pending.binding.clone()),
                workspace_binding: None,
                workspace_replace_binding: None,
                recovery_binding: None,
                expires_at_unix_ms: pending.expires_at_unix_ms,
            }
        }

        fn for_workspace_pending(session_id: &str, pending: &WorkspaceReadPendingAction) -> Self {
            Self {
                session_id: session_id.to_string(),
                pending_id: pending.pending_id.clone(),
                request_id: pending.request_id.clone(),
                binding: None,
                workspace_binding: Some(pending.binding.clone()),
                workspace_replace_binding: None,
                recovery_binding: None,
                expires_at_unix_ms: pending.expires_at_unix_ms,
            }
        }

        fn for_workspace_replace_pending(
            session_id: &str,
            pending: &WorkspaceReplacePendingAction,
        ) -> Self {
            Self {
                session_id: session_id.to_string(),
                pending_id: pending.pending_id.clone(),
                request_id: pending.request_id.clone(),
                binding: None,
                workspace_binding: None,
                workspace_replace_binding: Some(pending.binding.clone()),
                recovery_binding: None,
                expires_at_unix_ms: pending.expires_at_unix_ms,
            }
        }

        fn for_recovery_pending(session_id: &str, pending: &RecoveryPendingAction) -> Self {
            Self {
                session_id: session_id.to_string(),
                pending_id: pending.pending_id.clone(),
                request_id: pending.request_id.clone(),
                binding: None,
                workspace_binding: None,
                workspace_replace_binding: None,
                recovery_binding: Some(pending.binding.clone()),
                expires_at_unix_ms: pending.expires_at_unix_ms,
            }
        }
    }

    struct ExpiryState {
        ticket: Option<ExpiryTicket>,
        stopped: bool,
    }

    struct ExpiryOwner {
        control: Arc<(Mutex<ExpiryState>, Condvar)>,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl ExpiryOwner {
        fn new() -> Self {
            Self {
                control: Arc::new((
                    Mutex::new(ExpiryState {
                        ticket: None,
                        stopped: false,
                    }),
                    Condvar::new(),
                )),
                worker: Mutex::new(None),
            }
        }

        fn start(&self, session: Weak<HostSessionState>) -> Result<(), String> {
            let control = Arc::clone(&self.control);
            let worker = thread::Builder::new()
                .name("vita-sidecar-confirmation-expiry".to_string())
                .spawn(move || expiry_loop(control, session))
                .map_err(|_| "Vita confirmation expiry worker could not start".to_string())?;
            let mut slot = self
                .worker
                .lock()
                .map_err(|_| "Vita expiry worker lock was poisoned".to_string())?;
            if slot.is_some() {
                return Err("Vita confirmation expiry worker was already started".to_string());
            }
            *slot = Some(worker);
            Ok(())
        }

        fn schedule(&self, ticket: ExpiryTicket) {
            let (state, wake) = &*self.control;
            if let Ok(mut state) = state.lock() {
                if !state.stopped {
                    state.ticket = Some(ticket);
                    wake.notify_one();
                }
            }
        }

        fn clear(&self, ticket: &ExpiryTicket) {
            let (state, wake) = &*self.control;
            if let Ok(mut state) = state.lock() {
                if state.ticket.as_ref() == Some(ticket) {
                    state.ticket = None;
                    wake.notify_one();
                }
            }
        }

        fn stop(&self) {
            let worker = {
                let (state, wake) = &*self.control;
                if let Ok(mut state) = state.lock() {
                    state.stopped = true;
                    state.ticket = None;
                    wake.notify_all();
                }
                self.worker.lock().ok().and_then(|mut slot| slot.take())
            };
            if let Some(worker) = worker {
                let _ = worker.join();
            }
        }
    }

    impl Drop for ExpiryOwner {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[derive(Default)]
    struct RequestReplayWindow {
        order: VecDeque<String>,
        seen: HashSet<String>,
    }

    impl RequestReplayWindow {
        fn accept(&mut self, request_id: &str) -> bool {
            if self.seen.contains(request_id) {
                return false;
            }
            self.seen.insert(request_id.to_string());
            self.order.push_back(request_id.to_string());
            while self.order.len() > REQUEST_REPLAY_WINDOW {
                if let Some(retired) = self.order.pop_front() {
                    self.seen.remove(&retired);
                }
            }
            true
        }

        fn clear(&mut self) {
            self.order.clear();
            self.seen.clear();
        }

        #[cfg(test)]
        fn len(&self) -> usize {
            self.order.len()
        }
    }

    impl HostSessionState {
        #[cfg(feature = "d32-a-host-canary")]
        fn canary_control(&self) -> Option<Arc<D32HostCanaryControl>> {
            self.canary_control.clone()
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn canary_stage_result(
            &self,
            stage: D32HostCanaryStage,
            exact: bool,
            allowed: bool,
            sent: bool,
        ) {
            if !exact {
                return;
            }
            let Some(control) = self.canary_control.as_ref() else {
                return;
            };
            if !sent {
                control
                    .trace
                    .stage_failed(stage, D32StageFailureCode::OperationFailed);
            } else if allowed {
                control.trace.stage_passed(stage);
            } else {
                control.trace.stage_denied(stage);
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn canary_stage_failure(
            &self,
            stage: D32HostCanaryStage,
            exact: bool,
            code: D32StageFailureCode,
        ) {
            if exact {
                if let Some(control) = self.canary_control.as_ref() {
                    control.trace.stage_failed(stage, code);
                }
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn canary_bridge_result(&self, exact: bool, decision: D32BridgeDecision, sent: bool) {
            if !exact {
                return;
            }
            if let Some(control) = self.canary_control.as_ref() {
                if sent {
                    control.trace.bridge_replied(decision);
                } else {
                    control.trace.stage_failed(
                        D32HostCanaryStage::ConfirmationBridge,
                        D32StageFailureCode::OperationFailed,
                    );
                }
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn record_inbound(&self, message: &VitaMessage) {
            let Some(control) = self.canary_control.as_ref() else {
                return;
            };
            control.trace.update(|trace| match message {
                VitaMessage::AuthorityEvaluate(request) => {
                    trace.authority_evaluate += 1;
                    if request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
                        && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
                    {
                        trace
                            .stage_telemetry
                            .mark_started(D32HostCanaryStage::ScopeAuthority);
                    }
                }
                VitaMessage::ConfirmationRequired(request) => {
                    trace.confirmation_required += 1;
                    if request.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
                        && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
                    {
                        trace
                            .stage_telemetry
                            .mark_started(D32HostCanaryStage::ConfirmationBridge);
                        trace.stage_telemetry.bridge_sent();
                    }
                }
                VitaMessage::IssueGrant(request) => {
                    trace.issue_grant += 1;
                    if request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
                        && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
                    {
                        trace
                            .stage_telemetry
                            .mark_started(D32HostCanaryStage::Grant);
                    }
                }
                VitaMessage::RevalidateGrant(request) => {
                    trace.revalidate_grant += 1;
                    if request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
                        && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
                    {
                        trace
                            .stage_telemetry
                            .mark_started(D32HostCanaryStage::Revalidate);
                    }
                    if control.mode == D32HostCanaryMode::GrantReplay
                        && request.session_id == self.session_id
                        && request.grant.session_id == self.session_id
                    {
                        trace.replay_exact_request_count += 1;
                        trace.replay_exact_session_count += 1;
                    }
                }
                VitaMessage::TurnCompleted(_) => trace.turn_completed += 1,
                VitaMessage::TurnFailed(message) => {
                    trace.turn_failed += 1;
                    if let Some(diagnostic) = parse_d32_native_safe_diagnostic(&message.message) {
                        trace.native_diagnostic = Some(diagnostic);
                    }
                    if let Some(diagnostic) = parse_d32_vita_safe_stage_diagnostic(&message.message)
                    {
                        trace.stage_telemetry.mark_vita_failure(&diagnostic);
                    }
                }
                VitaMessage::ActionCancelled(_) => trace.action_cancelled += 1,
                _ => {}
            });
        }

        fn ensure_turn_idle(&self) -> Result<(), String> {
            let authority = self
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            if matches!(*authority, HostTurnAuthority::Idle) {
                Ok(())
            } else {
                Err("Vita turn is already active or cancelling".to_string())
            }
        }

        fn begin_turn(
            &self,
            turn_id: String,
            provider: protocol::ProviderConfiguration,
            binding: protocol::ProviderBinding,
        ) -> Result<(), String> {
            let mut authority = self
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            if self.closed.load(Ordering::Acquire) {
                return Err("Vita sidecar session was already retired".to_string());
            }
            if !matches!(*authority, HostTurnAuthority::Idle) {
                return Err("Vita turn is already active or cancelling".to_string());
            }
            if self
                .recovery_actions
                .lock()
                .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
                .len()
                != 0
            {
                return Err("Vita recovery action is active".to_string());
            }
            *authority = HostTurnAuthority::Active(HostTurnActive {
                turn_id: turn_id.clone(),
                provider,
                binding,
                h7_codex_turn_id: None,
            });
            drop(authority);
            // A new Host generation cannot inherit any disclosure evidence
            // (including a previously committed Released projection) from a
            // terminal generation.  The prior generation's release decision
            // remains observable until that generation is retired, then this
            // admission fence removes it before fresh tool traffic starts.
            if let Ok(mut approvals) = self.workspace_read_approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.workspace_read_grants.lock() {
                grants.clear();
            }
            if let Ok(mut approvals) = self.workspace_replace_approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.workspace_replace_grants.lock() {
                grants.clear();
            }
            if let Ok(mut pending) = self.workspace_replace_pending.lock() {
                pending.clear();
            }
            if let Ok(mut active) = self.active_turn_id.lock() {
                *active = Some(turn_id);
            }
            if let Ok(mut phase) = self.turn_phase.lock() {
                *phase = Some(protocol::TurnPhase::Starting);
            }
            Ok(())
        }

        /// Establishes the cancellation linearization point.  Once this
        /// returns `Some`, no credential request can pass the same authority
        /// mutex unless it already completed its decision and reply while the
        /// mutex was held.
        fn begin_cancellation(&self) -> Result<Option<String>, String> {
            let mut authority = self
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            let turn_id = match &*authority {
                HostTurnAuthority::Active(active) => {
                    let turn_id = active.turn_id.clone();
                    *authority = HostTurnAuthority::Cancelling(active.clone());
                    Some(turn_id)
                }
                HostTurnAuthority::Cancelling(active) => Some(active.turn_id.clone()),
                HostTurnAuthority::Idle | HostTurnAuthority::Terminal { .. } => None,
            };
            let retired_pending = turn_id
                .as_deref()
                .map(|turn_id| self.clear_turn_evidence_locked(turn_id))
                .unwrap_or_default();
            drop(authority);
            self.cancel_pending_replies(retired_pending);
            if turn_id.is_some() {
                if let Ok(mut phase) = self.turn_phase.lock() {
                    *phase = Some(protocol::TurnPhase::Cancelling);
                }
            }
            Ok(turn_id)
        }

        #[cfg(test)]
        fn authority_snapshot(&self) -> Option<HostTurnAuthority> {
            self.turn_authority.lock().ok().map(|state| state.clone())
        }

        #[cfg(test)]
        fn active_authority_matches(
            &self,
            turn_id: &str,
            binding: &protocol::ProviderBinding,
        ) -> bool {
            self.turn_authority.lock().ok().is_some_and(|state| {
                matches!(
                    &*state,
                    HostTurnAuthority::Active(active)
                        if active.turn_id == turn_id && active.binding == *binding
                )
            })
        }

        fn terminalize_turn(&self, turn_id: &str, phase: protocol::TurnPhase) -> bool {
            let Ok(mut authority) = self.turn_authority.lock() else {
                return false;
            };
            let accepted = match &*authority {
                HostTurnAuthority::Active(active) | HostTurnAuthority::Cancelling(active)
                    if active.turn_id == turn_id =>
                {
                    true
                }
                _ => false,
            };
            if !accepted {
                return false;
            }
            *authority = HostTurnAuthority::Terminal {
                turn_id: turn_id.to_string(),
                phase,
            };
            let retired_pending = self.clear_turn_evidence_locked(turn_id);
            // Terminal is a generation fence.  New turns are admitted only
            // after this exact acknowledgement has been observed, and late
            // frames cannot match the new generation once it starts.
            if let Ok(mut active) = self.active_turn_id.lock() {
                active.take();
            }
            if let Ok(mut current_phase) = self.turn_phase.lock() {
                *current_phase = Some(phase);
            }
            *authority = HostTurnAuthority::Idle;
            drop(authority);
            self.cancel_pending_replies(retired_pending);
            true
        }

        fn accept_turn_state(&self, turn_id: &str, phase: protocol::TurnPhase) -> bool {
            let Ok(mut authority) = self.turn_authority.lock() else {
                return false;
            };
            let accepted = match &*authority {
                HostTurnAuthority::Active(active) if active.turn_id == turn_id => {
                    if matches!(
                        phase,
                        protocol::TurnPhase::Completed
                            | protocol::TurnPhase::Failed
                            | protocol::TurnPhase::Cancelled
                            | protocol::TurnPhase::TimedOut
                    ) {
                        *authority = HostTurnAuthority::Terminal {
                            turn_id: turn_id.to_string(),
                            phase,
                        };
                        true
                    } else {
                        true
                    }
                }
                // Once Host cancellation wins, only an exact terminal
                // cancellation acknowledgement can close the generation.
                HostTurnAuthority::Cancelling(active)
                    if active.turn_id == turn_id
                        && matches!(
                            phase,
                            protocol::TurnPhase::Cancelled | protocol::TurnPhase::TimedOut
                        ) =>
                {
                    *authority = HostTurnAuthority::Terminal {
                        turn_id: turn_id.to_string(),
                        phase,
                    };
                    true
                }
                _ => false,
            };
            if !accepted {
                return false;
            }
            let terminal = matches!(
                phase,
                protocol::TurnPhase::Completed
                    | protocol::TurnPhase::Failed
                    | protocol::TurnPhase::Cancelled
                    | protocol::TurnPhase::TimedOut
            );
            let retired_pending = if terminal {
                self.clear_turn_evidence_locked(turn_id)
            } else {
                Vec::new()
            };
            if terminal {
                if let HostTurnAuthority::Terminal { .. } = &*authority {
                    // The terminal state is projected through `turn_phase`
                    // below; the authority lock remains held until all
                    // generation evidence has been retired.
                    *authority = HostTurnAuthority::Idle;
                }
            }
            drop(authority);
            if matches!(
                phase,
                protocol::TurnPhase::Completed
                    | protocol::TurnPhase::Failed
                    | protocol::TurnPhase::Cancelled
                    | protocol::TurnPhase::TimedOut
            ) {
                if let Ok(mut active) = self.active_turn_id.lock() {
                    active.take();
                }
            } else if let Ok(mut active) = self.active_turn_id.lock() {
                *active = Some(turn_id.to_string());
            }
            if let Ok(mut current_phase) = self.turn_phase.lock() {
                *current_phase = Some(phase);
            }
            self.cancel_pending_replies(retired_pending);
            true
        }

        fn force_terminal_cancelled(&self) {
            if let Ok(mut authority) = self.turn_authority.lock() {
                let turn_id = match &*authority {
                    HostTurnAuthority::Active(active) | HostTurnAuthority::Cancelling(active) => {
                        Some(active.turn_id.clone())
                    }
                    HostTurnAuthority::Terminal { turn_id, .. } => Some(turn_id.clone()),
                    HostTurnAuthority::Idle => None,
                };
                if let Some(turn_id) = turn_id {
                    *authority = HostTurnAuthority::Terminal {
                        turn_id,
                        phase: protocol::TurnPhase::Cancelled,
                    };
                }
            }
            if let Ok(mut active) = self.active_turn_id.lock() {
                active.take();
            }
            if let Ok(mut phase) = self.turn_phase.lock() {
                *phase = Some(protocol::TurnPhase::Cancelled);
            }
        }

        fn send(&self, message: &HostMessage) -> Result<(), String> {
            #[cfg(feature = "d32-a-host-canary")]
            if let Some(control) = self.canary_control.as_ref() {
                if let HostMessage::GrantRevalidated(reply) = message {
                    if control.capture_replay_response(reply)? {
                        control.trace.update(|trace| {
                            if !reply.allowed {
                                trace.replay_second_denied += 1;
                            }
                        });
                        return Ok(());
                    }
                    control.trace.update(|trace| {
                        trace.replay_wire_responses += 1;
                        if reply.allowed {
                            trace.grant_revalidated_allowed += 1;
                            trace.binding_fields_validated = true;
                        } else {
                            trace.grant_revalidated_denied += 1;
                            trace.grant_denial_code = reply.error_code.clone();
                        }
                    });
                }
            }
            #[cfg(test)]
            if let Ok(hook) = self.test_outbound.lock() {
                if let Some(sender) = hook.as_ref() {
                    return sender
                        .send(message.clone())
                        .map_err(|_| "Vita test outbound channel was closed".to_string());
                }
            }
            let mut guard = self
                .writer
                .lock()
                .map_err(|_| "Vita Host writer lock was poisoned".to_string())?;
            let writer = guard
                .as_mut()
                .ok_or_else(|| "Vita Host sidecar writer is closed".to_string())?;
            if matches!(message, HostMessage::SensitiveCredentialReply(_)) {
                protocol::write_sensitive_frame(writer, message).map_err(|error| error.to_string())
            } else {
                protocol::write_frame(writer, message).map_err(|error| error.to_string())
            }
        }

        fn close_writer(&self) {
            if let Ok(mut writer) = self.writer.lock() {
                writer.take();
            }
        }

        /// Retire all authority evidence belonging to one Host turn while the
        /// caller still owns `turn_authority`.  Keeping this under the same
        /// mutex as Active -> Cancelling/terminal admission means a fresh turn
        /// cannot observe the old ledger half-cleared.
        fn clear_turn_evidence_locked(&self, turn_id: &str) -> Vec<PendingCancellation> {
            let pending = if let Ok(mut pending) = self.pending.lock() {
                let keys = pending
                    .iter()
                    .filter(|(_, value)| value.host_turn_id == turn_id)
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                keys.into_iter()
                    .filter_map(|key| pending.remove(&key))
                    .into_iter()
                    .map(PendingCancellation::Git)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let workspace_pending = if let Ok(mut pending) = self.workspace_read_pending.lock() {
                let keys = pending
                    .iter()
                    .filter(|(_, value)| value.host_turn_id == turn_id)
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                keys.into_iter()
                    .filter_map(|key| pending.remove(&key))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let workspace_replace_pending =
                if let Ok(mut pending) = self.workspace_replace_pending.lock() {
                    let keys = pending
                        .iter()
                        .filter(|(_, value)| value.host_turn_id == turn_id)
                        .map(|(key, _)| key.clone())
                        .collect::<Vec<_>>();
                    keys.into_iter()
                        .filter_map(|key| pending.remove(&key))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
            for value in &pending {
                if let PendingCancellation::Git(value) = value {
                    self.expiry
                        .clear(&ExpiryTicket::for_pending(&self.session_id, value));
                }
            }
            for value in &workspace_pending {
                self.expiry.clear(&ExpiryTicket::for_workspace_pending(
                    &self.session_id,
                    value,
                ));
            }
            for value in &workspace_replace_pending {
                self.expiry
                    .clear(&ExpiryTicket::for_workspace_replace_pending(
                        &self.session_id,
                        value,
                    ));
            }
            if let Ok(mut approvals) = self.approvals.lock() {
                approvals.retain(|_, approval| approval.host_turn_id != turn_id);
            }
            if let Ok(mut grants) = self.grants.lock() {
                grants.retain(|_, grant| grant.host_turn_id != turn_id);
            }
            if let Ok(mut approvals) = self.workspace_read_approvals.lock() {
                approvals.retain(|_, approval| approval.host_turn_id != turn_id);
            }
            if let Ok(mut grants) = self.workspace_read_grants.lock() {
                // A release decision is already authoritative.  Cancellation
                // after that point cannot retroactively erase the committed
                // disclosure state; pre-release evidence is retired here.
                grants.retain(|_, grant| {
                    grant.host_turn_id != turn_id
                        || grant.phase == WorkspaceReadGrantPhase::Released
                });
            }
            if let Ok(mut approvals) = self.workspace_replace_approvals.lock() {
                approvals.retain(|_, approval| approval.host_turn_id != turn_id);
            }
            if let Ok(mut grants) = self.workspace_replace_grants.lock() {
                grants.retain(|_, grant| grant.host_turn_id != turn_id);
            }
            pending
                .into_iter()
                .chain(
                    workspace_pending
                        .into_iter()
                        .map(PendingCancellation::WorkspaceRead),
                )
                .chain(
                    workspace_replace_pending
                        .into_iter()
                        .map(PendingCancellation::WorkspaceReplace),
                )
                .collect()
        }

        fn cancel_pending_replies(&self, pending: Vec<PendingCancellation>) {
            for pending in pending {
                match pending {
                    PendingCancellation::Git(pending) => {
                        let _ = send_confirmation_decision(
                            self,
                            &pending,
                            ConfirmationDecision::Cancel,
                            None,
                        );
                    }
                    PendingCancellation::WorkspaceRead(pending) => {
                        let _ = send_workspace_read_confirmation_decision(
                            self,
                            &pending,
                            ConfirmationDecision::Cancel,
                            None,
                        );
                    }
                    PendingCancellation::WorkspaceReplace(pending) => {
                        let _ = send_workspace_replace_confirmation_decision(
                            self,
                            &pending,
                            ConfirmationDecision::Cancel,
                            None,
                        );
                    }
                }
            }
        }

        fn pending_summary(&self) -> Option<VitaSidecarPendingSummary> {
            if let Some(pending) = self.pending.lock().ok()?.values().next().cloned() {
                return Some(VitaSidecarPendingSummary {
                    pending_id: pending_key(&pending),
                    life_id: pending.life_id,
                    task_id: pending.task_id,
                    capability_id: pending.capability_id,
                    workspace_summary: pending.workspace_summary,
                    expires_at_unix_ms: pending.expires_at_unix_ms,
                });
            }
            if let Some(pending) = self
                .workspace_read_pending
                .lock()
                .ok()?
                .values()
                .next()
                .cloned()
            {
                return Some(VitaSidecarPendingSummary {
                    pending_id: pending.pending_id,
                    life_id: pending.life_id,
                    task_id: pending.task_id,
                    capability_id: pending.capability_id,
                    workspace_summary: pending.workspace_summary,
                    expires_at_unix_ms: pending.expires_at_unix_ms,
                });
            }
            if let Some(pending) = self
                .workspace_replace_pending
                .lock()
                .ok()?
                .values()
                .next()
                .cloned()
            {
                return Some(VitaSidecarPendingSummary {
                    pending_id: pending.pending_id,
                    life_id: pending.life_id,
                    task_id: pending.task_id,
                    capability_id: pending.capability_id,
                    workspace_summary: pending.workspace_summary,
                    expires_at_unix_ms: pending.expires_at_unix_ms,
                });
            }
            let pending = self.recovery_pending.lock().ok()?.values().next()?.clone();
            Some(VitaSidecarPendingSummary {
                pending_id: pending.pending_id,
                life_id: pending.life_id,
                task_id: pending.task_id,
                capability_id: pending.capability_id,
                workspace_summary: pending.workspace_summary,
                expires_at_unix_ms: pending.expires_at_unix_ms,
            })
        }

        fn recovery_scan_summary(&self) -> Vec<VitaSidecarRecoveryPendingSummary> {
            let mut values = self
                .recovery_scan_pending
                .lock()
                .map(|pending| {
                    pending
                        .values()
                        .map(|item| VitaSidecarRecoveryPendingSummary {
                            transaction_id: item.transaction_id.clone(),
                            life_id: item.life_id.clone(),
                            task_id: item.task_id.clone(),
                            capability_id: item.capability_id.clone(),
                            relative_path: item.relative_path.clone(),
                            current_sha256: item.current_sha256.clone(),
                            restore_sha256: item.restore_sha256.clone(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            values.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
            values
        }

        fn recovery_result(&self) -> Option<protocol::RecoveryResult> {
            self.recovery_result
                .lock()
                .ok()
                .and_then(|result| result.clone())
        }

        fn accept_request_id(&self, request_id: &str) -> bool {
            self.replay
                .lock()
                .map(|mut replay| replay.accept(request_id))
                .unwrap_or(false)
        }

        #[cfg(test)]
        fn install_workspace_read_approval(
            &self,
            host_turn_id: &str,
            binding: protocol::WorkspaceReadBinding,
            authorization_revision: i64,
            confirmation_id: &str,
            expires_at_unix_ms: u64,
        ) {
            self.workspace_read_approvals
                .lock()
                .expect("workspace read approval lock")
                .insert(
                    workspace_read_approval_key(host_turn_id, &binding),
                    WorkspaceReadApprovedAction {
                        host_turn_id: host_turn_id.to_string(),
                        binding,
                        authorization_revision,
                        confirmation_id: confirmation_id.to_string(),
                        expires_at_unix_ms,
                    },
                );
        }

        fn retire(&self) {
            self.closed.store(true, Ordering::Release);
            let pending = if let Ok(mut pending) = self.pending.lock() {
                pending.drain().map(|(_, value)| value).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            for pending in pending {
                let _ = self.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id: pending.request_id,
                    session_id: self.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                }));
            }
            let workspace_pending = if let Ok(mut pending) = self.workspace_read_pending.lock() {
                pending.drain().map(|(_, value)| value).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            for pending in workspace_pending {
                let _ = self.send(&HostMessage::WorkspaceReadConfirmationReply(
                    WorkspaceReadConfirmationReply {
                        request_id: pending.request_id,
                        session_id: self.session_id.clone(),
                        decision: ConfirmationDecision::Deny,
                        authorization_revision: None,
                    },
                ));
            }
            let workspace_replace_pending =
                if let Ok(mut pending) = self.workspace_replace_pending.lock() {
                    pending.drain().map(|(_, value)| value).collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
            for pending in workspace_replace_pending {
                let _ = self.send(&HostMessage::WorkspaceReplaceConfirmationReply(
                    WorkspaceReplaceConfirmationReply {
                        request_id: pending.request_id,
                        session_id: self.session_id.clone(),
                        decision: ConfirmationDecision::Deny,
                        authorization_revision: None,
                    },
                ));
            }
            let recovery_pending = if let Ok(mut pending) = self.recovery_pending.lock() {
                pending.drain().map(|(_, value)| value).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            for pending in recovery_pending {
                let _ = self.send(&HostMessage::RecoveryConfirmationReply(
                    RecoveryConfirmationReply {
                        request_id: pending.request_id,
                        session_id: self.session_id.clone(),
                        decision: ConfirmationDecision::Deny,
                        authorization_revision: None,
                    },
                ));
            }
            if let Ok(mut approvals) = self.approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.grants.lock() {
                grants.clear();
            }
            if let Ok(mut approvals) = self.workspace_read_approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.workspace_read_grants.lock() {
                grants.clear();
            }
            if let Ok(mut approvals) = self.workspace_replace_approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.workspace_replace_grants.lock() {
                grants.clear();
            }
            if let Ok(mut approvals) = self.recovery_approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.recovery_grants.lock() {
                grants.clear();
            }
            if let Ok(mut actions) = self.recovery_actions.lock() {
                actions.clear();
            }
            if let Ok(mut replay) = self.replay.lock() {
                replay.clear();
            }
            self.expiry.stop();
            self.force_terminal_cancelled();
        }
    }

    fn pending_key(pending: &PendingAction) -> String {
        pending.pending_id.clone()
    }

    fn expiry_loop(control: Arc<(Mutex<ExpiryState>, Condvar)>, session: Weak<HostSessionState>) {
        loop {
            let ticket = {
                let (state_lock, wake) = &*control;
                let mut state = match state_lock.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                loop {
                    if state.stopped {
                        return;
                    }
                    let Some(ticket) = state.ticket.clone() else {
                        state = match wake.wait(state) {
                            Ok(state) => state,
                            Err(_) => return,
                        };
                        continue;
                    };
                    let now = unix_millis();
                    if ticket.expires_at_unix_ms > now {
                        let wait_for =
                            Duration::from_millis(ticket.expires_at_unix_ms.saturating_sub(now));
                        state = match wake.wait_timeout(state, wait_for) {
                            Ok((state, _)) => state,
                            Err(_) => return,
                        };
                        continue;
                    }
                    // Retire this ticket before dropping the control lock.  A
                    // newer pending action can install a new ticket while the
                    // exact old ticket is being retired.
                    state.ticket = None;
                    break ticket;
                }
            };
            let Some(session) = session.upgrade() else {
                return;
            };
            session.expire_pending_ticket(&ticket);
        }
    }

    impl HostSessionState {
        fn expire_pending_ticket(&self, ticket: &ExpiryTicket) {
            if self.closed.load(Ordering::Acquire) || ticket.session_id != self.session_id {
                return;
            }
            if let Some(expected_binding) = ticket.binding.as_ref() {
                let expired = if let Ok(mut pending) = self.pending.lock() {
                    let key = pending.iter().find_map(|(key, value)| {
                        (value.pending_id == ticket.pending_id
                            && value.request_id == ticket.request_id
                            && value.binding == *expected_binding
                            && value.expires_at_unix_ms == ticket.expires_at_unix_ms
                            && value.expires_at_unix_ms <= unix_millis())
                        .then_some(key.clone())
                    });
                    key.and_then(|key| pending.remove(&key))
                } else {
                    None
                };
                if let Some(pending) = expired {
                    let _ = self.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                        request_id: pending.request_id,
                        session_id: self.session_id.clone(),
                        decision: ConfirmationDecision::Deny,
                        authorization_revision: None,
                    }));
                }
                return;
            }
            if let Some(expected_binding) = ticket.workspace_binding.as_ref() {
                let expired = if let Ok(mut pending) = self.workspace_read_pending.lock() {
                    let key = pending.iter().find_map(|(key, value)| {
                        (value.pending_id == ticket.pending_id
                            && value.request_id == ticket.request_id
                            && value.binding == *expected_binding
                            && value.expires_at_unix_ms == ticket.expires_at_unix_ms
                            && value.expires_at_unix_ms <= unix_millis())
                        .then_some(key.clone())
                    });
                    key.and_then(|key| pending.remove(&key))
                } else {
                    None
                };
                if let Some(pending) = expired {
                    let _ = send_workspace_read_confirmation_decision(
                        self,
                        &pending,
                        ConfirmationDecision::Deny,
                        None,
                    );
                }
                return;
            }
            if let Some(expected_binding) = ticket.workspace_replace_binding.as_ref() {
                let expired = if let Ok(mut pending) = self.workspace_replace_pending.lock() {
                    let key = pending.iter().find_map(|(key, value)| {
                        (value.pending_id == ticket.pending_id
                            && value.request_id == ticket.request_id
                            && value.binding == *expected_binding
                            && value.expires_at_unix_ms == ticket.expires_at_unix_ms
                            && value.expires_at_unix_ms <= unix_millis())
                        .then_some(key.clone())
                    });
                    key.and_then(|key| pending.remove(&key))
                } else {
                    None
                };
                if let Some(pending) = expired {
                    let _ = send_workspace_replace_confirmation_decision(
                        self,
                        &pending,
                        ConfirmationDecision::Deny,
                        None,
                    );
                }
                return;
            }
            let Some(expected_binding) = ticket.recovery_binding.as_ref() else {
                return;
            };
            let expired = if let Ok(mut pending) = self.recovery_pending.lock() {
                let key = pending.iter().find_map(|(key, value)| {
                    (value.pending_id == ticket.pending_id
                        && value.request_id == ticket.request_id
                        && value.binding == *expected_binding
                        && value.expires_at_unix_ms == ticket.expires_at_unix_ms
                        && value.expires_at_unix_ms <= unix_millis())
                    .then_some(key.clone())
                });
                key.and_then(|key| pending.remove(&key))
            } else {
                None
            };
            if let Some(pending) = expired {
                let _ = send_recovery_confirmation_decision(
                    self,
                    &pending,
                    ConfirmationDecision::Deny,
                    None,
                );
            }
        }
    }

    impl VitaSidecarCoordinator {
        #[cfg(feature = "d32-a-host-canary")]
        fn d32_app_data_root_retained(&self) -> Result<Arc<D32RetainedDirectory>, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "D32 Host coordinator lock was poisoned".to_string())?;
            guard
                .running
                .as_ref()
                .and_then(|running| running.session.app_data_root_retained.clone())
                .ok_or_else(|| "D32 Host app-data authority was not retained".to_string())
        }

        #[cfg(test)]
        fn install_test_session(&self, session: Arc<HostSessionState>) {
            if let Ok(mut guard) = self.inner.lock() {
                guard.test_session = Some(session);
            }
        }

        fn start<R: Runtime>(
            &self,
            app: &AppHandle<R>,
            request: VitaSidecarStartRequest,
        ) -> Result<VitaSidecarStartResponse, String> {
            validate_id(&request.life_id)?;
            validate_id(&request.task_id)?;
            // `request.life_id` is only the caller's observed-current-Life
            // fence.  The Host reads the current Life once and carries this
            // immutable record through image preparation and initialization;
            // the caller never selects the runtime authorization target.
            let life = observed_current_life(&self.authority_storage, &request.life_id)?;

            {
                let mut guard = self
                    .inner
                    .lock()
                    .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
                if guard.starting {
                    return Err("Vita sidecar already has an active session".to_string());
                }
                if guard
                    .running
                    .as_ref()
                    .is_some_and(|running| running.session.closed.load(Ordering::Acquire))
                {
                    let retired = guard.running.take();
                    drop(guard);
                    if let Some(retired) = retired {
                        retired.stop();
                    }
                    guard = self
                        .inner
                        .lock()
                        .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
                }
                if guard.running.is_some() {
                    return Err("Vita sidecar already has an active session".to_string());
                }
                guard.starting = true;
            }

            let result = self.start_inner(app, request, life);
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            guard.starting = false;
            if let Ok((running, response)) = result {
                guard.running = Some(running);
                Ok(response)
            } else {
                result.map(|(_, response)| response)
            }
        }

        fn start_inner<R: Runtime>(
            &self,
            app: &AppHandle<R>,
            request: VitaSidecarStartRequest,
            life: crate::storage::LifeIdentityRecord,
        ) -> Result<(RunningSidecar, VitaSidecarStartResponse), String> {
            let secrets = app.state::<WindowsCredentialSecretStore>().inner().clone();
            let provider = active_chat_provider_configuration(&self.authority_storage, &secrets)?;
            let workspace = fs::canonicalize(&request.workspace_path)
                .map_err(|_| "Vita workspace path could not be canonicalized".to_string())?;
            if !workspace.is_dir() {
                return Err("Vita workspace path is not a directory".to_string());
            }
            let sidecar_workspace = normalize_sidecar_local_path(&workspace)?;
            let app_data_root = sidecar_app_data_root(app)?;
            fs::create_dir_all(&app_data_root)
                .map_err(|_| "Vita app data root could not be created".to_string())?;
            let app_data_root = fs::canonicalize(&app_data_root)
                .map_err(|_| "Vita app data root could not be canonicalized".to_string())?;
            validate_private_app_data_root(&app_data_root)?;
            // Acquire the app-data capability once for this startup.  All
            // subsequent marker/profile/evidence operations use this retained
            // handle; the canonical path below is only a process/display
            // projection.
            let app_data_root_retained = D32RetainedDirectory::open(&app_data_root)
                .map_err(|error| format!("Vita app-data authority unavailable: {error}"))?;
            app_data_root_retained
                .revalidate("D32 Host app-data root before Cargo publication")
                .map_err(|error| format!("Vita app-data authority changed: {error}"))?;
            // Cargo image authority is published by the Host into its own
            // private app-data namespace before Vita is started.  The
            // mandatory D32 canary is fail-closed: missing or changed cargo,
            // rustc, rustdoc, mirror, or profile evidence is a structured
            // NOT_EXECUTABLE result rather than an optional/soft-disabled
            // lane.  The ordinary production sidecar retains its historical
            // optional readiness behavior.
            #[cfg(feature = "d32-a-host-canary")]
            let published_cargo_profile = Some(
                host_publish_cargo_selection(&app_data_root_retained)
                    .map_err(d32_not_executable)?,
            );
            #[cfg(not(feature = "d32-a-host-canary"))]
            let published_cargo_profile =
                host_publish_cargo_selection(&app_data_root_retained).ok();
            app_data_root_retained
                .revalidate("D32 Host app-data root after Cargo publication")
                .map_err(|error| format!("Vita app-data authority changed: {error}"))?;
            let sidecar_app_data_root = normalize_sidecar_local_path(&app_data_root)?;

            let sidecar_binding = app_owned_sidecar_path(app)?;
            let sidecar = sidecar_binding.path.clone();
            // The image authority retains the resource directory and image
            // handles through the final pre-CreateProcessW fence.  The path
            // below is only the app-owned resource lookup, not the authority.
            let image = VitaSidecarProcess::prepare_image(&sidecar, &sidecar_binding.resource_dir)
                .map_err(map_process_error)?;
            #[cfg(feature = "d32-a-host-canary")]
            app_data_root_retained
                .revalidate("D32 Host app-data root before sidecar process root create")
                .map_err(d32_not_executable)?;
            #[cfg(feature = "d32-a-host-canary")]
            let process_root_retained = app_data_root_retained
                .open_or_create_child(OsStr::new("vita-sidecar-process"))
                .map_err(d32_not_executable)?;
            #[cfg(feature = "d32-a-host-canary")]
            let process_root = process_root_retained.path().to_path_buf();
            #[cfg(not(feature = "d32-a-host-canary"))]
            let process_root = {
                let process_root = app_data_root.join("vita-sidecar-process");
                fs::create_dir_all(&process_root)
                    .map_err(|_| "Vita sidecar process root could not be created".to_string())?;
                fs::canonicalize(&process_root).map_err(|_| {
                    "Vita sidecar process root could not be canonicalized".to_string()
                })?
            };
            #[cfg(feature = "d32-a-host-canary")]
            app_data_root_retained
                .revalidate("D32 Host app-data root after sidecar process root create")
                .map_err(d32_not_executable)?;
            let git_path = resolve_git_path()?;
            let sidecar_git_path = normalize_sidecar_local_path(&git_path)?;

            #[cfg(feature = "d32-a-host-canary")]
            let sidecar_args = [OsString::from("--serve-ipc-d32-canary")];
            #[cfg(not(feature = "d32-a-host-canary"))]
            let sidecar_args = [OsString::from("--serve-ipc")];
            #[cfg(feature = "d32-a-host-canary")]
            app_data_root_retained
                .revalidate("D32 Host app-data root before sidecar launch")
                .map_err(d32_not_executable)?;
            #[cfg(feature = "d32-a-host-canary")]
            process_root_retained
                .revalidate("D32 Host sidecar process root before sidecar launch")
                .map_err(d32_not_executable)?;
            let mut process =
                VitaSidecarProcess::spawn_prepared(image, &sidecar_args, &process_root)
                    .map_err(map_process_error)?;
            #[cfg(feature = "d32-a-host-canary")]
            app_data_root_retained
                .revalidate("D32 Host app-data root after sidecar launch")
                .map_err(d32_not_executable)?;
            let stdout = process
                .take_stdout()
                .ok_or_else(|| "Vita sidecar stdout pipe was unavailable".to_string())?;
            let stdin = process
                .take_stdin()
                .ok_or_else(|| "Vita sidecar stdin pipe was unavailable".to_string())?;
            let _stderr = process
                .take_stderr()
                .ok_or_else(|| "Vita sidecar stderr pipe was unavailable".to_string())?;
            // Drain stderr in a bounded, detached reader so a diagnostic burst
            // can never block the sidecar's stdout protocol channel.
            spawn_stderr_drain(_stderr);

            let (message, reader) = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "Vita sidecar handshake",
            )?;
            let handshake = match message {
                VitaMessage::Handshake(handshake) => handshake,
                _ => return Err("Vita sidecar first frame was not Handshake".to_string()),
            };
            validate_handshake(&handshake)?;
            let current_binding = app_owned_sidecar_path(app)?;
            if current_binding.path != sidecar
                || current_binding.resource_dir != sidecar_binding.resource_dir
            {
                return Err("Vita sidecar resource namespace changed during launch".to_string());
            }

            let session_id = secure_id("vita-session")?;
            let mut writer = BufWriter::new(stdin);
            let init = HostMessage::Initialize(InitializeSession {
                request_id: next_id("host-initialize"),
                protocol_version: PROTOCOL_VERSION.to_string(),
                session_id: session_id.clone(),
                life_id: life.id.clone(),
                task_id: request.task_id.clone(),
                app_data_root: sidecar_app_data_root.to_string_lossy().into_owned(),
                workspace_path: sidecar_workspace.to_string_lossy().into_owned(),
                git_path: sidecar_git_path.to_string_lossy().into_owned(),
                provider: provider.clone(),
            });
            protocol::write_frame(&mut writer, &init).map_err(|error| error.to_string())?;

            let (message, reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "Vita sidecar ready")?;
            let ready = match message {
                VitaMessage::Ready(ready) => ready,
                _ => return Err("Vita sidecar post-initialize frame was not Ready".to_string()),
            };
            validate_ready(&ready, &session_id, &request, &life.id)?;
            // D32 Cargo is an optional fixed profile alongside the generic
            // H7/H9 sidecar.  A normal sidecar session must remain usable when
            // the app-owned Cargo projection is unavailable; the Cargo lane
            // then stays fail-closed because validate_binding() requires this
            // Host-owned evidence before it can issue or revalidate a grant.
            #[cfg(feature = "d32-a-host-canary")]
            let cargo_profile = published_cargo_profile
                .as_ref()
                .map(|published| {
                    host_finalize_published_cargo_profile_retained(
                        &app_data_root_retained,
                        published,
                    )
                })
                .transpose()
                .map_err(d32_not_executable)?;
            #[cfg(not(feature = "d32-a-host-canary"))]
            let cargo_profile = published_cargo_profile.as_ref().and_then(|published| {
                host_finalize_published_cargo_profile_retained(&app_data_root_retained, published)
                    .ok()
            });
            let app_data_root_retained_session = Arc::new(app_data_root_retained.clone());
            #[cfg(feature = "d32-a-host-canary")]
            let canary_control = self.d32_host_canary_control()?;
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: life.id.clone(),
                task_id: request.task_id.clone(),
                workspace_identity: ready.workspace_identity,
                cargo_profile,
                app_data_root_retained: Some(Arc::clone(&app_data_root_retained_session)),
                provider,
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                workspace_read_pending: Mutex::new(HashMap::new()),
                workspace_replace_pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                workspace_read_approvals: Mutex::new(HashMap::new()),
                workspace_read_grants: Mutex::new(HashMap::new()),
                workspace_replace_approvals: Mutex::new(HashMap::new()),
                workspace_replace_grants: Mutex::new(HashMap::new()),
                recovery_pending: Mutex::new(HashMap::new()),
                recovery_scan_pending: Mutex::new(HashMap::new()),
                recovery_actions: Mutex::new(HashMap::new()),
                recovery_approvals: Mutex::new(HashMap::new()),
                recovery_grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                turn_authority: Mutex::new(HostTurnAuthority::Idle),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                recovery_result: Mutex::new(None),
                #[cfg(feature = "d32-a-host-canary")]
                canary_control,
                #[cfg(test)]
                test_outbound: Mutex::new(None),
            });
            let reader_session = Arc::clone(&session);
            let storage = Arc::clone(&self.authority_storage);
            let registry = self.registry.clone();
            session.expiry.start(Arc::downgrade(&session))?;
            let reader_handle = thread::Builder::new()
                .name("vita-sidecar-host-reader".to_string())
                .spawn(move || reader_loop(reader, reader_session, storage, registry, secrets))
                .map_err(|_| "Vita sidecar Host reader could not start".to_string())?;
            Ok((
                RunningSidecar {
                    session,
                    process,
                    reader: Some(reader_handle),
                },
                VitaSidecarStartResponse {
                    session_id,
                    ready: true,
                },
            ))
        }

        fn status(&self) -> Result<VitaSidecarStatusResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let Some(running) = guard.running.as_ref() else {
                let (capability_readiness, capability_states, current_life_id) =
                    capability_readiness(&self.authority_storage, &self.registry, None);
                return Ok(VitaSidecarStatusResponse {
                    running: false,
                    provider_readiness: provider_readiness(
                        &self.authority_storage,
                        &self.credential_store,
                        false,
                        false,
                        None,
                    )?,
                    capability_readiness,
                    capability_states,
                    session_life_id: None,
                    current_life_id,
                    session_id: None,
                    pending: None,
                    recovery_pending: Vec::new(),
                    recovery_result: None,
                    active_turn_id: None,
                    turn_phase: None,
                    assistant_text: None,
                    turn_error: None,
                });
            };
            let active_turn = running
                .session
                .active_turn_id
                .lock()
                .ok()
                .is_some_and(|turn| turn.is_some());
            let (capability_readiness, capability_states, current_life_id) = capability_readiness(
                &self.authority_storage,
                &self.registry,
                Some(&running.session.life_id),
            );
            let running_now = !running.session.closed.load(Ordering::Acquire);
            Ok(VitaSidecarStatusResponse {
                running: running_now,
                provider_readiness: provider_readiness(
                    &self.authority_storage,
                    &self.credential_store,
                    running_now,
                    active_turn,
                    running.session.provider.as_ref(),
                )?,
                capability_readiness,
                capability_states,
                session_life_id: Some(running.session.life_id.clone()),
                current_life_id,
                session_id: Some(running.session.session_id.clone()),
                pending: running.session.pending_summary(),
                recovery_pending: running.session.recovery_scan_summary(),
                recovery_result: running.session.recovery_result(),
                active_turn_id: running
                    .session
                    .active_turn_id
                    .lock()
                    .ok()
                    .and_then(|turn| turn.clone()),
                turn_phase: running
                    .session
                    .turn_phase
                    .lock()
                    .ok()
                    .and_then(|phase| *phase),
                assistant_text: running
                    .session
                    .assistant_text
                    .lock()
                    .ok()
                    .and_then(|text| text.clone()),
                turn_error: running
                    .session
                    .turn_error
                    .lock()
                    .ok()
                    .and_then(|error| error.clone()),
            })
        }

        fn confirm(&self, pending_id: String) -> Result<VitaSidecarActionResponse, String> {
            self.decide_pending(pending_id, ConfirmationDecision::Confirm)
        }

        fn deny(&self, pending_id: String) -> Result<VitaSidecarActionResponse, String> {
            self.decide_pending(pending_id, ConfirmationDecision::Deny)
        }

        fn recover(&self, transaction_id: String) -> Result<VitaSidecarActionResponse, String> {
            if transaction_id.is_empty()
                || transaction_id.len() > protocol::MAX_ID_BYTES
                || transaction_id
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err("Vita recovery transaction identity was malformed".to_string());
            }
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            #[cfg(test)]
            if let Some(session) = guard.test_session.as_ref() {
                return self.execute_recovery_for_session(session, &transaction_id);
            }
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            self.execute_recovery_for_session(&running.session, &transaction_id)
        }

        fn execute_recovery_for_session(
            &self,
            session: &Arc<HostSessionState>,
            transaction_id: &str,
        ) -> Result<VitaSidecarActionResponse, String> {
            if session.closed.load(Ordering::Acquire) {
                return Err("Vita sidecar is not running".to_string());
            }
            let authority = session
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            if !matches!(*authority, HostTurnAuthority::Idle) {
                return Err("Vita recovery requires an idle Host turn".to_string());
            }
            if session
                .recovery_actions
                .lock()
                .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
                .len()
                != 0
            {
                return Err("Vita recovery action is already active".to_string());
            }
            let pending = session
                .recovery_scan_pending
                .lock()
                .map_err(|_| "Vita recovery scan state lock was poisoned".to_string())?
                .remove(transaction_id)
                .ok_or_else(|| "Vita recovery transaction was not pending".to_string())?;
            let recovery_action_id = secure_id("vita-recovery-action")?;
            let recovery_generation = secure_id("vita-recovery-generation")?;
            let action = HostRecoveryAction {
                recovery_action_id: recovery_action_id.clone(),
                recovery_generation: recovery_generation.clone(),
                transaction_id: transaction_id.to_string(),
                pending,
                phase: HostRecoveryActionPhase::Requested,
            };
            session
                .recovery_actions
                .lock()
                .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
                .insert(recovery_action_id.clone(), action);
            if let Ok(mut actions) = session.recovery_actions.lock() {
                if let Some(action) = actions.get_mut(&recovery_action_id) {
                    action.phase = HostRecoveryActionPhase::AwaitingAuthority;
                }
            }
            let command = HostMessage::ExecuteRecovery(ExecuteRecovery {
                request_id: next_id("host-recovery-execute"),
                session_id: session.session_id.clone(),
                transaction_id: transaction_id.to_string(),
                recovery_action_id: recovery_action_id.clone(),
                recovery_generation,
            });
            if let Err(error) = session.send(&command) {
                if let Ok(mut actions) = session.recovery_actions.lock() {
                    if let Some(action) = actions.remove(&recovery_action_id) {
                        if let Ok(mut pending) = session.recovery_scan_pending.lock() {
                            pending.insert(action.transaction_id, action.pending);
                        }
                    }
                }
                return Err(error);
            }
            drop(authority);
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn decide_pending(
            &self,
            pending_id: String,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            #[cfg(test)]
            if let Some(session) = guard.test_session.as_ref() {
                return self.decide_pending_for_session(session, pending_id, decision);
            }
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            self.decide_pending_for_session(&running.session, pending_id, decision)
        }

        /// The production decision path is kept separate from the outer
        /// RunningSidecar lock so tests can inject only an already-constructed
        /// Host session.  No confirmation logic is duplicated or bypassed.
        fn decide_pending_for_session(
            &self,
            session: &Arc<HostSessionState>,
            pending_id: String,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            expire_pending(session);
            if let Some(pending) = take_workspace_read_pending(session, &pending_id) {
                return self.decide_workspace_read_pending_for_session(session, pending, decision);
            }
            if let Some(pending) = take_workspace_replace_pending(session, &pending_id) {
                return self
                    .decide_workspace_replace_pending_for_session(session, pending, decision);
            }
            if let Some(pending) = take_recovery_pending(session, &pending_id) {
                return self.decide_recovery_pending_for_session(session, pending, decision);
            }
            let pending = take_pending(session, &pending_id)
                .ok_or_else(|| "Vita pending confirmation was not found".to_string())?;
            let authority = session
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            let active = matches!(
                &*authority,
                HostTurnAuthority::Active(active)
                    if active.turn_id == pending.host_turn_id
            );
            if !active {
                let _ = send_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Cancel,
                    None,
                );
                return Err("Vita pending confirmation belongs to a retired turn".to_string());
            }
            if pending.expires_at_unix_ms <= unix_millis() {
                let _ =
                    send_confirmation_decision(session, &pending, ConfirmationDecision::Deny, None);
                return Err("Vita pending confirmation expired".to_string());
            }

            let mut revision = None;
            if decision == ConfirmationDecision::Confirm {
                revision = match current_workspace_revision(
                    &self.authority_storage,
                    &self.registry,
                    session,
                    &pending.binding,
                ) {
                    Ok(revision) => Some(revision),
                    Err(error) => {
                        let _ = session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                            request_id: pending.request_id.clone(),
                            session_id: session.session_id.clone(),
                            decision: ConfirmationDecision::Deny,
                            authorization_revision: None,
                        }));
                        return Err(error);
                    }
                };
                let confirmation_id = secure_id("vita-confirmation")?;
                session
                    .approvals
                    .lock()
                    .map_err(|_| "Vita approval state lock was poisoned".to_string())?
                    .insert(
                        approval_key(&pending.host_turn_id, &pending.binding),
                        ApprovedAction {
                            host_turn_id: pending.host_turn_id.clone(),
                            binding: pending.binding.clone(),
                            authorization_revision: revision.unwrap_or_default(),
                            confirmation_id,
                            expires_at_unix_ms: pending.expires_at_unix_ms,
                        },
                    );
            }
            if let Err(error) = send_confirmation_decision(session, &pending, decision, revision) {
                if decision == ConfirmationDecision::Confirm {
                    if let Ok(mut approvals) = session.approvals.lock() {
                        approvals.remove(&approval_key(&pending.host_turn_id, &pending.binding));
                    }
                }
                return Err(error);
            }
            drop(authority);
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn decide_workspace_read_pending_for_session(
            &self,
            session: &Arc<HostSessionState>,
            pending: WorkspaceReadPendingAction,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            let authority = session
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            let active = matches!(
                &*authority,
                HostTurnAuthority::Active(active)
                    if active_workspace_read_turn_matches(
                        &HostTurnAuthority::Active(active.clone()),
                        &pending.host_turn_id,
                        &pending.binding,
                    )
            );
            if !active {
                let _ = send_workspace_read_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Cancel,
                    None,
                );
                return Err("Vita pending workspace read belongs to a retired turn".to_string());
            }
            if pending.expires_at_unix_ms <= unix_millis() {
                let _ = send_workspace_read_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Deny,
                    None,
                );
                return Err("Vita pending workspace read confirmation expired".to_string());
            }

            let mut revision = None;
            if decision == ConfirmationDecision::Confirm {
                if let Err(error) = require_current_session_life(&self.authority_storage, session) {
                    let _ = send_workspace_read_confirmation_decision(
                        session,
                        &pending,
                        ConfirmationDecision::Deny,
                        None,
                    );
                    return Err(error);
                }
                revision = match current_workspace_read_revision(
                    &self.authority_storage,
                    &self.registry,
                    session,
                    &pending.binding,
                ) {
                    Ok(revision) => Some(revision),
                    Err(error) => {
                        let _ = send_workspace_read_confirmation_decision(
                            session,
                            &pending,
                            ConfirmationDecision::Deny,
                            None,
                        );
                        return Err(error);
                    }
                };
                let confirmation_id = match secure_id("vita-read-confirmation") {
                    Ok(confirmation_id) => confirmation_id,
                    Err(error) => {
                        let _ = send_workspace_read_confirmation_decision(
                            session,
                            &pending,
                            ConfirmationDecision::Deny,
                            None,
                        );
                        return Err(error);
                    }
                };
                session
                    .workspace_read_approvals
                    .lock()
                    .map_err(|_| {
                        "Vita workspace read approval state lock was poisoned".to_string()
                    })?
                    .insert(
                        workspace_read_approval_key(&pending.host_turn_id, &pending.binding),
                        WorkspaceReadApprovedAction {
                            host_turn_id: pending.host_turn_id.clone(),
                            binding: pending.binding.clone(),
                            authorization_revision: revision.unwrap_or_default(),
                            confirmation_id,
                            expires_at_unix_ms: pending.expires_at_unix_ms,
                        },
                    );
            }
            if let Err(error) =
                send_workspace_read_confirmation_decision(session, &pending, decision, revision)
            {
                if decision == ConfirmationDecision::Confirm {
                    if let Ok(mut approvals) = session.workspace_read_approvals.lock() {
                        approvals.remove(&workspace_read_approval_key(
                            &pending.host_turn_id,
                            &pending.binding,
                        ));
                    }
                }
                return Err(error);
            }
            drop(authority);
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn decide_workspace_replace_pending_for_session(
            &self,
            session: &Arc<HostSessionState>,
            pending: WorkspaceReplacePendingAction,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            let authority = session
                .turn_authority
                .lock()
                .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
            let active = matches!(
                &*authority,
                HostTurnAuthority::Active(active)
                    if active.turn_id == pending.host_turn_id
                        && active.binding.binding_hash == pending.binding.provider_binding_hash
                        && active.h7_codex_turn_id.as_deref()
                            == Some(pending.binding.codex_turn_id.as_str())
            );
            if !active {
                let _ = send_workspace_replace_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Cancel,
                    None,
                );
                return Err("Vita pending workspace replace belongs to a retired turn".to_string());
            }
            if pending.expires_at_unix_ms <= unix_millis() {
                let _ = send_workspace_replace_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Deny,
                    None,
                );
                return Err("Vita pending workspace replace confirmation expired".to_string());
            }
            let mut revision = None;
            if decision == ConfirmationDecision::Confirm {
                require_current_session_life(&self.authority_storage, session)?;
                revision = Some(current_workspace_replace_revision(
                    &self.authority_storage,
                    &self.registry,
                    session,
                    &pending.binding,
                )?);
                let confirmation_id = secure_id("vita-replace-confirmation")?;
                session
                    .workspace_replace_approvals
                    .lock()
                    .map_err(|_| {
                        "Vita workspace replace approval state lock was poisoned".to_string()
                    })?
                    .insert(
                        workspace_replace_approval_key(&pending.host_turn_id, &pending.binding),
                        WorkspaceReplaceApprovedAction {
                            host_turn_id: pending.host_turn_id.clone(),
                            binding: pending.binding.clone(),
                            authorization_revision: revision.unwrap_or_default(),
                            confirmation_id,
                            expires_at_unix_ms: pending.expires_at_unix_ms,
                        },
                    );
            }
            if let Err(error) =
                send_workspace_replace_confirmation_decision(session, &pending, decision, revision)
            {
                if decision == ConfirmationDecision::Confirm {
                    if let Ok(mut approvals) = session.workspace_replace_approvals.lock() {
                        approvals.remove(&workspace_replace_approval_key(
                            &pending.host_turn_id,
                            &pending.binding,
                        ));
                    }
                }
                return Err(error);
            }
            drop(authority);
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn decide_recovery_pending_for_session(
            &self,
            session: &Arc<HostSessionState>,
            pending: RecoveryPendingAction,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            let action_phase = session
                .recovery_actions
                .lock()
                .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
                .get(&pending.recovery_action_id)
                .filter(|action| recovery_action_matches(action, &pending.binding))
                .map(|action| action.phase);
            if !matches!(
                action_phase,
                Some(
                    HostRecoveryActionPhase::Requested
                        | HostRecoveryActionPhase::AwaitingAuthority
                        | HostRecoveryActionPhase::AwaitingConfirmation
                )
            ) {
                let _ = send_recovery_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Cancel,
                    None,
                );
                return Err("Vita pending recovery action was retired".to_string());
            }
            if pending.expires_at_unix_ms <= unix_millis() {
                let _ = send_recovery_confirmation_decision(
                    session,
                    &pending,
                    ConfirmationDecision::Deny,
                    None,
                );
                return Err("Vita pending recovery confirmation expired".to_string());
            }
            let mut revision = None;
            if decision == ConfirmationDecision::Confirm {
                let authority_scope = self
                    .authority_storage
                    .capability_authorization_scope()
                    .map_err(capability_authorization_gate_error)?;
                require_current_session_life(authority_scope.storage(), session)?;
                revision = Some(current_recovery_revision_in_scope(
                    &authority_scope,
                    &self.registry,
                    session,
                    &pending.binding,
                )?);
                let confirmation_id = secure_id("vita-recovery-confirmation")?;
                session
                    .recovery_approvals
                    .lock()
                    .map_err(|_| "Vita recovery approval state lock was poisoned".to_string())?
                    .insert(
                        recovery_approval_key(&pending.recovery_action_id, &pending.binding),
                        RecoveryApprovedAction {
                            recovery_action_id: pending.recovery_action_id.clone(),
                            recovery_generation: pending.recovery_generation.clone(),
                            binding: pending.binding.clone(),
                            authorization_revision: revision.unwrap_or_default(),
                            confirmation_id,
                            expires_at_unix_ms: pending.expires_at_unix_ms,
                        },
                    );
            }
            if let Err(error) =
                send_recovery_confirmation_decision(session, &pending, decision, revision)
            {
                if decision == ConfirmationDecision::Confirm {
                    if let Ok(mut approvals) = session.recovery_approvals.lock() {
                        approvals.remove(&recovery_approval_key(
                            &pending.recovery_action_id,
                            &pending.binding,
                        ));
                    }
                }
                return Err(error);
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn cancel(&self) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            let turn_id = running.session.begin_cancellation()?;
            expire_pending(&running.session);
            if let Some(pending) = take_any_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_confirmation_decision(&running.session, &pending, decision, None);
            } else if let Some(pending) = take_any_workspace_read_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_workspace_read_confirmation_decision(
                    &running.session,
                    &pending,
                    decision,
                    None,
                );
            } else if let Some(pending) = take_any_workspace_replace_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_workspace_replace_confirmation_decision(
                    &running.session,
                    &pending,
                    decision,
                    None,
                );
            } else if let Some(pending) = take_any_recovery_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ =
                    send_recovery_confirmation_decision(&running.session, &pending, decision, None);
            }
            running
                .session
                .send(&HostMessage::CancelAction(protocol::CancelAction {
                    request_id: next_id("host-cancel"),
                    session_id: running.session.session_id.clone(),
                }))?;
            if let Some(turn_id) = turn_id {
                let _ = running
                    .session
                    .send(&HostMessage::CancelTurn(protocol::CancelTurn {
                        request_id: next_id("host-cancel-turn"),
                        session_id: running.session.session_id.clone(),
                        turn_id,
                    }));
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn start_turn(
            &self,
            request: VitaTurnStartRequest,
        ) -> Result<VitaTurnStartResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            #[cfg(test)]
            if let Some(session) = guard.test_session.as_ref() {
                return self.start_turn_for_session(session, request);
            }
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            self.start_turn_for_session(&running.session, request)
        }

        /// Runs the same production admission sequence against one Host
        /// session.  The outer command keeps the coordinator lock; tests use
        /// this narrow seam only to inject provider/session plumbing without
        /// constructing another process graph.
        fn start_turn_for_session(
            &self,
            session: &Arc<HostSessionState>,
            request: VitaTurnStartRequest,
        ) -> Result<VitaTurnStartResponse, String> {
            if request.prompt.is_empty()
                || request.prompt.len() > protocol::MAX_PROMPT_BYTES
                || request.prompt.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
            {
                return Err("Vita turn prompt was empty, oversized, or malformed".to_string());
            }
            if session.closed.load(Ordering::Acquire) {
                return Err("Vita sidecar is not running".to_string());
            }
            // StartTurn admission is one authority transaction: the shared
            // capability gate is acquired before the fresh current-Life read,
            // remains held through the D30 preflight and Host turn-authority
            // begin point, and is released before provider inspection or any
            // sidecar/network IPC.
            let authority_scope = self
                .authority_storage
                .capability_authorization_scope()
                .map_err(|error| error.code.clone())?;
            require_current_session_life(authority_scope.storage(), session)?;
            session.ensure_turn_idle()?;
            // Root admission deliberately precedes provider/credential
            // inspection.  A disabled D30 root must not release credentials,
            // contact a provider, create a turn generation, or emit a
            // HostMessage::StartTurn frame.
            preflight_capability_roots_in_scope(&authority_scope, &self.registry, session)?;
            let provider = session
                .provider
                .clone()
                .ok_or_else(|| "Vita Chat provider is not configured".to_string())?;
            // The preflight above is advisory only.  The D29 AuthorityEvaluate,
            // confirmation, grant, and final revalidation paths below still
            // perform their own fresh D28 reads; do not carry this decision or
            // its revision into executable authority.
            let turn_id = secure_id("vita-turn")?;
            let binding =
                protocol::ProviderBinding::derive(&session.session_id, &turn_id, &provider)
                    .map_err(|_| "Vita provider binding could not be derived".to_string())?;
            session.begin_turn(turn_id.clone(), provider.clone(), binding.clone())?;
            drop(authority_scope);
            // Provider/credential inspection is intentionally outside the
            // authority gate.  A provider change after the Host generation is
            // admitted retires that generation before any IPC is emitted.
            let current_provider = match current_chat_provider_configuration(self)? {
                Some(provider) => provider,
                None => {
                    let _ = session.terminalize_turn(&turn_id, protocol::TurnPhase::Failed);
                    return Err("Vita Chat provider is not ready".to_string());
                }
            };
            if current_provider != provider {
                let _ = session.terminalize_turn(&turn_id, protocol::TurnPhase::Failed);
                return Err("Vita active Chat provider changed; restart the sidecar".to_string());
            }
            if let Ok(mut output) = session.assistant_text.lock() {
                output.take();
            }
            if let Ok(mut error) = session.turn_error.lock() {
                error.take();
            }
            let message = HostMessage::StartTurn(protocol::StartTurn {
                request_id: next_id("host-start-turn"),
                session_id: session.session_id.clone(),
                turn_id: turn_id.clone(),
                prompt: request.prompt,
                binding,
            });
            if let Err(error) = session.send(&message) {
                let _ = session.terminalize_turn(&turn_id, protocol::TurnPhase::Failed);
                return Err(error);
            }
            Ok(VitaTurnStartResponse {
                turn_id,
                accepted: true,
            })
        }

        fn cancel_turn(&self) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            let Some(turn_id) = running.session.begin_cancellation()? else {
                return Ok(VitaSidecarActionResponse { accepted: false });
            };
            expire_pending(&running.session);
            if let Some(pending) = take_any_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_confirmation_decision(&running.session, &pending, decision, None);
            } else if let Some(pending) = take_any_workspace_read_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_workspace_read_confirmation_decision(
                    &running.session,
                    &pending,
                    decision,
                    None,
                );
            } else if let Some(pending) = take_any_workspace_replace_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_workspace_replace_confirmation_decision(
                    &running.session,
                    &pending,
                    decision,
                    None,
                );
            } else if let Some(pending) = take_any_recovery_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ =
                    send_recovery_confirmation_decision(&running.session, &pending, decision, None);
            }
            // Cancel the governed H7 action and any pending H8 confirmation
            // before interrupting the Codex turn.  A turn-only interrupt is
            // not sufficient to retire a tool broker that is waiting on the
            // Host confirmation bridge.
            let _ = running
                .session
                .send(&HostMessage::CancelAction(protocol::CancelAction {
                    request_id: next_id("host-cancel-action"),
                    session_id: running.session.session_id.clone(),
                }));
            running
                .session
                .send(&HostMessage::CancelTurn(protocol::CancelTurn {
                    request_id: next_id("host-cancel-turn"),
                    session_id: running.session.session_id.clone(),
                    turn_id,
                }))?;
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn stop(&self) -> Result<VitaSidecarActionResponse, String> {
            let running = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned")?
                .running
                .take();
            if let Some(running) = running {
                running.stop();
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }
    }

    impl Drop for VitaSidecarCoordinator {
        fn drop(&mut self) {
            if let Ok(mut guard) = self.inner.lock() {
                if let Some(running) = guard.running.take() {
                    running.stop();
                }
            }
        }
    }

    fn dispatch_inbound_message(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        secrets: &WindowsCredentialSecretStore,
        message: VitaMessage,
    ) -> Result<(), String> {
        match message {
            VitaMessage::AuthorityEvaluate(request) => {
                handle_authority_evaluate(session, storage, registry, request)
            }
            VitaMessage::ConfirmationRequired(request) => {
                handle_confirmation_required(session, request)
            }
            VitaMessage::IssueGrant(request) => {
                handle_issue_grant(session, storage, registry, request)
            }
            VitaMessage::RevalidateGrant(request) => {
                handle_revalidate_grant_with_secrets(session, storage, registry, secrets, request)
            }
            VitaMessage::WorkspaceReadAuthorityEvaluate(request) => {
                handle_workspace_read_authority_evaluate(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReadConfirmationRequired(request) => {
                handle_workspace_read_confirmation_required(session, request)
            }
            VitaMessage::WorkspaceReadIssueGrant(request) => {
                handle_workspace_read_issue_grant(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReadRevalidateGrant(request) => {
                handle_workspace_read_revalidate_grant(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReadReleaseCheck(request) => {
                handle_workspace_read_release_check(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReplaceAuthorityEvaluate(request) => {
                handle_workspace_replace_authority_evaluate(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReplaceConfirmationRequired(request) => {
                handle_workspace_replace_confirmation_required(session, request)
            }
            VitaMessage::WorkspaceReplaceIssueGrant(request) => {
                handle_workspace_replace_issue_grant(session, storage, registry, request)
            }
            VitaMessage::WorkspaceReplaceRevalidateGrant(request) => {
                handle_workspace_replace_revalidate_grant(session, storage, registry, request)
            }
            VitaMessage::RecoveryAuthorityEvaluate(request) => {
                handle_recovery_authority_evaluate(session, storage, registry, request)
            }
            VitaMessage::RecoveryConfirmationRequired(request) => {
                handle_recovery_confirmation_required(session, request)
            }
            VitaMessage::RecoveryIssueGrant(request) => {
                handle_recovery_issue_grant(session, storage, registry, request)
            }
            VitaMessage::RecoveryRevalidateGrant(request) => {
                handle_recovery_revalidate_grant(session, storage, registry, request)
            }
            VitaMessage::RecoveryPending(request) => handle_recovery_pending(session, request),
            VitaMessage::RecoveryResult(result) => handle_recovery_result(session, result),
            VitaMessage::CredentialRequired(request) => {
                handle_credential_required(session, storage, secrets, request)
            }
            VitaMessage::TurnState(message) => handle_turn_state(session, message),
            VitaMessage::TurnCompleted(message) => handle_turn_completed(session, message),
            VitaMessage::TurnFailed(message) => handle_turn_failed(session, message),
            VitaMessage::ActionCancelled(message) if message.session_id == session.session_id => {
                Ok(())
            }
            VitaMessage::ShutdownAck(message) if message.session_id == session.session_id => Ok(()),
            VitaMessage::Fatal(_) | VitaMessage::Handshake(_) | VitaMessage::Ready(_) => {
                Err("Vita sidecar emitted an invalid Host-phase message".to_string())
            }
            VitaMessage::ActionCancelled(_) | VitaMessage::ShutdownAck(_) => {
                Err("Vita sidecar lifecycle response session was not exact".to_string())
            }
        }
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_dispatch_replay_inbound(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        secrets: &WindowsCredentialSecretStore,
        message: VitaMessage,
    ) -> Result<(), String> {
        let request_id = vita_request_id(&message);
        let VitaMessage::RevalidateGrant(request) = &message else {
            return Err("D32 replay message was not RevalidateGrant".to_string());
        };
        if request_id.is_empty()
            || request_id.len() > protocol::MAX_ID_BYTES
            || request.session_id != session.session_id
            || request.grant.session_id != session.session_id
        {
            return Err("D32 replay request/session identity was not exact".to_string());
        }
        // Deliberately bypass only the outer request-id replay window: this
        // feature-only seam proves that an exact duplicate still reaches the
        // canonical inbound dispatch and is denied by the consumed grant
        // ledger.  Production reader_loop retains the normal fail-closed
        // duplicate-frame fence.
        session.record_inbound(&message);
        dispatch_inbound_message(session, storage, registry, secrets, message)
    }

    fn reader_loop(
        mut reader: BufReader<File>,
        session: Arc<HostSessionState>,
        storage: Arc<StorageService>,
        registry: CapabilityRegistry,
        secrets: WindowsCredentialSecretStore,
    ) {
        loop {
            let body = match protocol::read_sensitive_frame(&mut reader) {
                Ok(Some(body)) => body,
                Ok(None) | Err(_) => break,
            };
            let message = match protocol::decode_frame::<VitaMessage>(&body) {
                Ok(message) => message,
                Err(_) => break,
            };
            let request_id = vita_request_id(&message);
            if request_id.is_empty()
                || request_id.len() > protocol::MAX_ID_BYTES
                || !session.accept_request_id(request_id)
            {
                break;
            }
            #[cfg(feature = "d32-a-host-canary")]
            session.record_inbound(&message);
            let result = dispatch_inbound_message(&session, &storage, &registry, &secrets, message);
            if result.is_err() {
                break;
            }
        }
        session.retire();
        session.close_writer();
    }

    fn handle_recovery_pending(
        session: &Arc<HostSessionState>,
        request: protocol::RecoveryPending,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita recovery pending evidence was malformed".to_string())?;
        if request.session_id != session.session_id
            || request.life_id != session.life_id
            || request.task_id != session.task_id
        {
            return Err("RECOVERY_PENDING_BINDING_MISMATCH".to_string());
        }
        session
            .recovery_scan_pending
            .lock()
            .map_err(|_| "Vita recovery scan state lock was poisoned".to_string())?
            .insert(request.transaction_id.clone(), request);
        Ok(())
    }

    fn handle_recovery_result(
        session: &Arc<HostSessionState>,
        result: protocol::RecoveryResult,
    ) -> Result<(), String> {
        result
            .validate()
            .map_err(|_| "Vita recovery result was malformed".to_string())?;
        if result.session_id != session.session_id {
            return Err("RECOVERY_RESULT_BINDING_MISMATCH".to_string());
        }
        let action = session
            .recovery_actions
            .lock()
            .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
            .remove(&result.recovery_action_id)
            .ok_or_else(|| "RECOVERY_ACTION_NOT_FOUND".to_string())?;
        if action.transaction_id != result.transaction_id
            || action.recovery_generation != result.recovery_generation
        {
            return Err("RECOVERY_RESULT_BINDING_MISMATCH".to_string());
        }
        let terminal = result.marker_persisted
            && matches!(
                result.outcome,
                protocol::RecoveryOutcome::Recovered | protocol::RecoveryOutcome::RecoveredNoOp
            );
        if !terminal {
            session
                .recovery_scan_pending
                .lock()
                .map_err(|_| "Vita recovery scan state lock was poisoned".to_string())?
                .insert(action.transaction_id.clone(), action.pending);
        }
        *session
            .recovery_result
            .lock()
            .map_err(|_| "Vita recovery result state lock was poisoned".to_string())? =
            Some(result);
        Ok(())
    }

    fn handle_turn_state(
        session: &Arc<HostSessionState>,
        message: protocol::TurnState,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn state was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn state session was not exact".to_string());
        }
        let _ = session.accept_turn_state(&message.turn_id, message.phase);
        Ok(())
    }

    fn handle_turn_completed(
        session: &Arc<HostSessionState>,
        message: protocol::TurnCompleted,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn result was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn result session was not exact".to_string());
        }
        let accepted = session.accept_turn_state(&message.turn_id, protocol::TurnPhase::Completed);
        if !accepted {
            return Ok(());
        }
        if let Ok(mut output) = session.assistant_text.lock() {
            *output = Some(message.assistant_text);
        }
        if let Ok(mut error) = session.turn_error.lock() {
            error.take();
        }
        Ok(())
    }

    fn handle_turn_failed(
        session: &Arc<HostSessionState>,
        message: protocol::TurnFailed,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn failure was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn failure session was not exact".to_string());
        }
        let accepted = session.accept_turn_state(&message.turn_id, message.phase);
        if !accepted {
            return Ok(());
        }
        if let Ok(mut error) = session.turn_error.lock() {
            *error = Some(message.error_code);
        }
        Ok(())
    }

    fn handle_credential_required(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
        request: protocol::CredentialRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita credential request was malformed".to_string())?;
        let deny = |code: &str| {
            session.send(&HostMessage::SensitiveCredentialReply(
                protocol::SensitiveCredentialReply {
                    request_id: request.request_id.clone(),
                    session_id: session.session_id.clone(),
                    turn_id: request.turn_id.clone(),
                    binding_hash: request.binding.binding_hash.clone(),
                    credential_ref: request.binding.credential_ref.clone(),
                    credential: None,
                    error_code: Some(code.to_string()),
                },
            ))
        };
        if session.closed.load(Ordering::Acquire) || request.session_id != session.session_id {
            return deny("TURN_NOT_ACTIVE");
        }

        // This guard is the Host credential authority fence.  Keep it held
        // through profile/secret resolution and the sensitive reply write so
        // `cancel_vita_turn` cannot linearize between the final check and
        // credential release.
        let authority = match session.turn_authority.lock() {
            Ok(authority) => authority,
            Err(_) => return deny("TURN_AUTHORITY_UNAVAILABLE"),
        };
        let HostTurnAuthority::Active(active) = &*authority else {
            return deny("TURN_NOT_ACTIVE");
        };
        if active.turn_id != request.turn_id || active.binding != request.binding {
            return deny("TURN_NOT_ACTIVE");
        }
        let Some(configuration) = active_chat_provider_configuration(storage, secrets)? else {
            return deny("CREDENTIAL_MISSING");
        };
        if configuration != active.provider {
            return deny("PROVIDER_PROFILE_CHANGED");
        }
        let expected = protocol::ProviderBinding::derive(
            &session.session_id,
            &request.turn_id,
            &configuration,
        )
        .map_err(|_| "provider binding could not be derived".to_string())?;
        if expected != request.binding {
            return deny("PROVIDER_BINDING_MISMATCH");
        }
        if request.binding.credential_ref != configuration.credential_ref
            || request.binding.purpose != "chat"
            || request.binding.provider_kind != "openai_compatible"
            || request.binding.base_url != configuration.base_url
            || request.binding.model != configuration.model
        {
            return deny("PROVIDER_BINDING_MISMATCH");
        }
        let identifier = SecretIdentifier::new(
            credential_purpose(ModelPurpose::Chat),
            configuration.credential_ref.clone(),
        )
        .map_err(|_| "credential identifier was invalid".to_string())?;
        let secret = match secrets.get_secret(&identifier) {
            Ok(secret) => secret,
            Err(_) => return deny("CREDENTIAL_MISSING"),
        };
        let credential = protocol::SensitiveCredential::new(secret.expose_secret().to_owned())
            .map_err(|_| "credential value was invalid".to_string())?;
        let result = session.send(&HostMessage::SensitiveCredentialReply(
            protocol::SensitiveCredentialReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                turn_id: request.turn_id,
                binding_hash: request.binding.binding_hash,
                credential_ref: request.binding.credential_ref,
                credential: Some(credential),
                error_code: None,
            },
        ));
        drop(authority);
        result
    }

    fn handle_authority_evaluate(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: AuthorityEvaluate,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita authority request was malformed".to_string())?;
        if request.session_id != session.session_id {
            return Err("Vita authority request session was not exact".to_string());
        }
        #[cfg(feature = "d32-a-host-canary")]
        let exact_d32 = request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID;
        let mut authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        let active = match &mut *authority {
            HostTurnAuthority::Active(active) if active.turn_id == request.host_turn_id => active,
            _ => {
                let result = session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("TURN_NOT_ACTIVE".to_string()),
                }));
                #[cfg(feature = "d32-a-host-canary")]
                session.canary_stage_result(
                    D32HostCanaryStage::ScopeAuthority,
                    exact_d32,
                    false,
                    result.is_ok(),
                );
                drop(authority);
                return result;
            }
        };
        if active
            .h7_codex_turn_id
            .as_deref()
            .is_some_and(|codex_turn_id| codex_turn_id != request.binding.turn_id)
        {
            let result = session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                authorization_revision: None,
                error_code: Some("CODEX_TURN_MISMATCH".to_string()),
            }));
            #[cfg(feature = "d32-a-host-canary")]
            session.canary_stage_result(
                D32HostCanaryStage::ScopeAuthority,
                exact_d32,
                false,
                result.is_ok(),
            );
            drop(authority);
            return result;
        }
        let (allowed, revision, reply_error_code) = match storage.capability_authorization_scope() {
            Ok(authority_scope) => match current_workspace_revision_in_scope(
                &authority_scope,
                registry,
                session,
                &request.binding,
            ) {
                Ok(revision) => {
                    active.h7_codex_turn_id = Some(request.binding.turn_id.clone());
                    (true, Some(revision), None)
                }
                Err(error) => (false, None, Some(error_code(&error))),
            },
            Err(error) => (false, None, Some(error.code)),
        };
        let result = session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
            request_id: request.request_id,
            session_id: session.session_id.clone(),
            allowed,
            authorization_revision: revision,
            error_code: reply_error_code,
        }));
        #[cfg(feature = "d32-a-host-canary")]
        session.canary_stage_result(
            D32HostCanaryStage::ScopeAuthority,
            exact_d32,
            allowed,
            result.is_ok(),
        );
        drop(authority);
        result
    }

    fn handle_workspace_read_authority_evaluate(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReadAuthorityEvaluate,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace read authority request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) {
            return Err("Vita sidecar session was already retired".to_string());
        }
        if request.session_id != session.session_id {
            return Err("Vita workspace read authority session was not exact".to_string());
        }
        validate_workspace_read_binding(session, &request.binding)?;
        let mut authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        let active = match &mut *authority {
            HostTurnAuthority::Active(active) if active.turn_id == request.host_turn_id => active,
            _ => {
                let result = session.send(&HostMessage::WorkspaceReadAuthorityReply(
                    WorkspaceReadAuthorityReply {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        authorization_revision: None,
                        error_code: Some("TURN_NOT_ACTIVE".to_string()),
                    },
                ));
                drop(authority);
                result?;
                return Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string());
            }
        };
        if active.binding.binding_hash != request.binding.provider_binding_hash {
            let result = session.send(&HostMessage::WorkspaceReadAuthorityReply(
                WorkspaceReadAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("PROVIDER_BINDING_MISMATCH".to_string()),
                },
            ));
            drop(authority);
            result?;
            return Err("WORKSPACE_READ_BINDING_MISMATCH".to_string());
        }
        if active
            .h7_codex_turn_id
            .as_deref()
            .is_some_and(|codex_turn_id| codex_turn_id != request.binding.codex_turn_id)
        {
            let result = session.send(&HostMessage::WorkspaceReadAuthorityReply(
                WorkspaceReadAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("CODEX_TURN_MISMATCH".to_string()),
                },
            ));
            drop(authority);
            result?;
            return Err("CODEX_TURN_MISMATCH".to_string());
        }
        let (allowed, revision, reply_error_code) = match storage.capability_authorization_scope() {
            Ok(authority_scope) => {
                match require_current_session_life(storage, session).and_then(|_| {
                    current_workspace_read_revision_in_scope(
                        &authority_scope,
                        registry,
                        session,
                        &request.binding,
                    )
                }) {
                    Ok(revision) => {
                        // This is the first Codex-side read message for the Host
                        // generation.  Retain it as part of the same generation
                        // fence used by H7 so a later independent Codex turn can
                        // never reuse this Host authority.
                        active.h7_codex_turn_id = Some(request.binding.codex_turn_id.clone());
                        (true, Some(revision), None)
                    }
                    Err(error) => (false, None, Some(error_code(&error))),
                }
            }
            Err(error) => (
                false,
                None,
                Some(error_code(&capability_authorization_gate_error(error))),
            ),
        };
        let result = session.send(&HostMessage::WorkspaceReadAuthorityReply(
            WorkspaceReadAuthorityReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed,
                authorization_revision: revision,
                error_code: reply_error_code,
            },
        ));
        drop(authority);
        result
    }

    fn handle_workspace_read_confirmation_required(
        session: &Arc<HostSessionState>,
        request: WorkspaceReadConfirmationRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace read confirmation request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) {
            return Err("Vita sidecar session was already retired".to_string());
        }
        if request.session_id != session.session_id {
            return Err("Vita workspace read confirmation session was not exact".to_string());
        }
        validate_workspace_read_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            session.send(&HostMessage::WorkspaceReadConfirmationReply(
                WorkspaceReadConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                },
            ))?;
            return Ok(());
        };
        expire_pending(session);
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        let active = matches!(
            &*authority,
            HostTurnAuthority::Active(active)
                if active.turn_id == request.host_turn_id
                    && active.binding.binding_hash == request.binding.provider_binding_hash
                    && active.h7_codex_turn_id.as_deref()
                        == Some(request.binding.codex_turn_id.as_str())
        );
        if !active {
            session.send(&HostMessage::WorkspaceReadConfirmationReply(
                WorkspaceReadConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Cancel,
                    authorization_revision: None,
                },
            ))?;
            drop(authority);
            return Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string());
        }
        let pending_id = format!("read-pending:{}", secure_id("vita")?);
        let pending_action = WorkspaceReadPendingAction {
            pending_id: pending_id.clone(),
            request_id: request.request_id,
            host_turn_id: request.host_turn_id,
            life_id: request.binding.life_id.clone(),
            task_id: request.binding.task_id.clone(),
            capability_id: request.binding.capability_id.clone(),
            workspace_summary: request.workspace_summary,
            expires_at_unix_ms,
            binding: request.binding,
        };
        let h7_pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        let mut pending = session
            .workspace_read_pending
            .lock()
            .map_err(|_| "Vita workspace read pending state lock was poisoned".to_string())?;
        if h7_pending.len() + pending.len() >= MAX_PENDING {
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket = ExpiryTicket::for_workspace_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(pending);
        drop(h7_pending);
        drop(authority);
        session.expiry.schedule(ticket);
        Ok(())
    }

    fn handle_workspace_read_issue_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReadIssueGrant,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace read grant request was malformed".to_string())?;
        if request.session_id != session.session_id {
            return Err("Vita workspace read grant session was not exact".to_string());
        }
        let result = issue_workspace_read_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::WorkspaceReadGrantIssued(
                WorkspaceReadGrantIssued {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                },
            )),
            Err(error) => {
                let terminal = workspace_read_protocol_error_is_terminal(&error);
                let result = session.send(&HostMessage::WorkspaceReadGrantIssued(
                    WorkspaceReadGrantIssued {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        grant: None,
                        error_code: Some(error_code(&error)),
                    },
                ));
                if terminal {
                    result?;
                    Err(error)
                } else {
                    result
                }
            }
        }
    }

    fn handle_workspace_read_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReadRevalidateGrant,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace read revalidation request was malformed".to_string())?;
        if request.session_id != session.session_id {
            return Err("Vita workspace read revalidation session was not exact".to_string());
        }
        let result = revalidate_workspace_read_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::WorkspaceReadGrantRevalidated(
                WorkspaceReadGrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                },
            )),
            Err(error) => {
                let terminal = workspace_read_protocol_error_is_terminal(&error);
                let result = session.send(&HostMessage::WorkspaceReadGrantRevalidated(
                    WorkspaceReadGrantRevalidated {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        grant: None,
                        error_code: Some(error_code(&error)),
                    },
                ));
                if terminal {
                    result?;
                    Err(error)
                } else {
                    result
                }
            }
        }
    }

    fn handle_workspace_read_release_check(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReadReleaseCheck,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace read release evidence was malformed".to_string())?;
        if request.session_id != session.session_id {
            return Err("Vita workspace read release session was not exact".to_string());
        }
        let result =
            authorize_workspace_read_release_evidence(storage, registry, session, &request);
        match result {
            Ok(()) => session.send(&HostMessage::WorkspaceReadReleaseChecked(
                WorkspaceReadReleaseChecked {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    error_code: None,
                },
            )),
            Err(error) => {
                let terminal = workspace_read_protocol_error_is_terminal(&error);
                let result = session.send(&HostMessage::WorkspaceReadReleaseChecked(
                    WorkspaceReadReleaseChecked {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        error_code: Some(error_code(&error)),
                    },
                ));
                if terminal {
                    result?;
                    Err(error)
                } else {
                    result
                }
            }
        }
    }

    fn handle_confirmation_required(
        session: &Arc<HostSessionState>,
        request: ConfirmationRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita confirmation request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) {
            return Err("Vita sidecar session was already retired".to_string());
        }
        if request.session_id != session.session_id
            || request.life_id != session.life_id
            || request.task_id != session.task_id
            || (request.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
                && request.capability_id != PRODUCTION_CARGO_CHECK_CAPABILITY_ID)
            || request.binding.validate().is_err()
        {
            return Err("Vita confirmation binding was not exact".to_string());
        }
        #[cfg(feature = "d32-a-host-canary")]
        let exact_d32_confirmation = request.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID;
        validate_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            let result = session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                decision: ConfirmationDecision::Deny,
                authorization_revision: None,
            }));
            #[cfg(feature = "d32-a-host-canary")]
            session.canary_bridge_result(
                exact_d32_confirmation,
                D32BridgeDecision::Deny,
                result.is_ok(),
            );
            result?;
            return Ok(());
        };
        // The active timer is authoritative; this opportunistic pass only
        // closes a just-expired slot before applying MAX_PENDING.
        expire_pending(session);
        // Serialize H8 admission with Host cancellation.  A confirmation
        // request that arrives after Active -> Cancelling is denied without
        // entering the pending ledger, so a stale H7 action cannot be
        // resurrected by a new UI decision.
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !matches!(
            &*authority,
            HostTurnAuthority::Active(active)
                if active_h7_binding_matches(active, &request.host_turn_id, &request.binding)
        ) {
            let result = session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                decision: ConfirmationDecision::Cancel,
                authorization_revision: None,
            }));
            #[cfg(feature = "d32-a-host-canary")]
            session.canary_bridge_result(
                exact_d32_confirmation,
                D32BridgeDecision::Cancel,
                result.is_ok(),
            );
            result?;
            return Ok(());
        }
        let pending_id = format!("pending:{}", secure_id("vita")?);
        let pending_action = PendingAction {
            pending_id: pending_id.clone(),
            request_id: request.request_id,
            host_turn_id: request.host_turn_id,
            life_id: request.life_id,
            task_id: request.task_id,
            capability_id: request.capability_id,
            workspace_summary: request.workspace_summary,
            expires_at_unix_ms,
            binding: request.binding,
        };
        let mut pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        if pending.len() >= MAX_PENDING {
            #[cfg(feature = "d32-a-host-canary")]
            if exact_d32_confirmation {
                if let Some(control) = session.canary_control.as_ref() {
                    control.trace.stage_failed(
                        D32HostCanaryStage::ConfirmationBridge,
                        D32StageFailureCode::LedgerCapacity,
                    );
                }
            }
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket = ExpiryTicket::for_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(pending);
        drop(authority);
        session.expiry.schedule(ticket);
        #[cfg(feature = "d32-a-host-canary")]
        if exact_d32_confirmation {
            if let Some(control) = session.canary_control.as_ref() {
                control.trace.bridge_pending();
            }
        }
        Ok(())
    }

    fn handle_issue_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: IssueGrant,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita grant request was malformed".to_string())?;
        if request.session_id != session.session_id {
            return Err("Vita grant request session was not exact".to_string());
        }
        #[cfg(feature = "d32-a-host-canary")]
        let exact_d32 = request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID;
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !matches!(
            &*authority,
            HostTurnAuthority::Active(active)
                if active_h7_binding_matches(active, &request.host_turn_id, &request.binding)
        ) {
            let result = session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some("TURN_NOT_ACTIVE".to_string()),
            }));
            #[cfg(feature = "d32-a-host-canary")]
            session.canary_stage_result(
                D32HostCanaryStage::Grant,
                exact_d32,
                false,
                result.is_ok(),
            );
            drop(authority);
            return result;
        }
        expire_pending(session);
        let authority_scope = match storage.capability_authorization_scope() {
            Ok(scope) => scope,
            Err(error) => {
                let result = session.send(&HostMessage::GrantIssued(GrantIssued {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error.code),
                }));
                #[cfg(feature = "d32-a-host-canary")]
                session.canary_stage_result(
                    D32HostCanaryStage::Grant,
                    exact_d32,
                    false,
                    result.is_ok(),
                );
                drop(authority);
                return result;
            }
        };
        let allowed = validate_binding(session, &request.binding).and_then(|_| {
            let revision = current_workspace_revision_in_scope(
                &authority_scope,
                registry,
                session,
                &request.binding,
            )?;
            if revision != request.authorization_revision {
                return Err("stale authorization revision".to_string());
            }
            {
                let mut grants = session
                    .grants
                    .lock()
                    .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
                reap_expired_grants(&mut grants);
                if grants.len() >= MAX_GRANTS {
                    return Err("Vita grant capacity was exhausted".to_string());
                }
            }
            let mut approvals = session
                .approvals
                .lock()
                .map_err(|_| "Vita approval state lock was poisoned".to_string())?;
            let key = approval_key(&request.host_turn_id, &request.binding);
            let approval = approvals
                .remove(&key)
                .ok_or_else(|| "Vita confirmation was not approved".to_string())?;
            if approval.host_turn_id != request.host_turn_id
                || approval.binding != request.binding
                || approval.authorization_revision != request.authorization_revision
                || approval.expires_at_unix_ms <= unix_millis()
            {
                return Err("Vita confirmation binding or revision was stale".to_string());
            }
            let grant = ProcessGrant {
                session_id: session.session_id.clone(),
                grant_id: secure_id("vita-grant")?,
                confirmation_id: approval.confirmation_id,
                binding: request.binding.clone(),
                authorization_revision: request.authorization_revision,
                issued_at_unix_ms: unix_millis(),
                expires_at_unix_ms: unix_millis().saturating_add(GRANT_LIFETIME_MS),
                single_use: true,
                used: false,
            };
            let mut grants = session
                .grants
                .lock()
                .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
            if grants.len() >= MAX_GRANTS {
                return Err("Vita grant capacity was exhausted".to_string());
            }
            grants.insert(
                grant.grant_id.clone(),
                HostStoredGrant {
                    host_turn_id: request.host_turn_id.clone(),
                    grant: grant.clone(),
                },
            );
            Ok(grant)
        });
        #[cfg(feature = "d32-a-host-canary")]
        let grant_allowed = allowed.is_ok();
        let result = match allowed {
            Ok(grant) => session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            })),
            Err(error) => session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            })),
        };
        #[cfg(feature = "d32-a-host-canary")]
        session.canary_stage_result(
            D32HostCanaryStage::Grant,
            exact_d32,
            grant_allowed,
            result.is_ok(),
        );
        drop(authority);
        result
    }

    fn revalidate_grant_decision(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RevalidateGrant,
    ) -> Result<GrantRevalidated, String> {
        request
            .validate()
            .map_err(|_| "Vita revalidation request was malformed".to_string())?;
        if request.session_id != session.session_id
            || request.grant.session_id != session.session_id
        {
            return Err("Vita revalidation request session was not exact".to_string());
        }
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !matches!(
            &*authority,
            HostTurnAuthority::Active(active)
                if active_h7_binding_matches(active, &request.host_turn_id, &request.binding)
        ) {
            return Ok(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some("TURN_NOT_ACTIVE".to_string()),
            });
        }
        let authority_scope = match storage.capability_authorization_scope() {
            Ok(scope) => scope,
            Err(error) => {
                return Ok(GrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error.code),
                });
            }
        };
        let result = require_current_session_life_in_scope(&authority_scope, session)
            .and_then(|_| validate_binding(session, &request.binding))
            .and_then(|_| {
                let revision = current_workspace_revision_in_scope(
                    &authority_scope,
                    registry,
                    session,
                    &request.binding,
                )?;
                let mut grants = session
                    .grants
                    .lock()
                    .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
                consume_active_grant(
                    &mut grants,
                    &request.host_turn_id,
                    &request.grant,
                    &request.binding,
                    revision,
                )
            });
        let result = match result {
            Ok(grant) => GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            },
            Err(error) => GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            },
        };
        drop(authority);
        Ok(result)
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn canary_exact_cargo_request(session: &HostSessionState, request: &RevalidateGrant) -> bool {
        request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            && request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
            && request.binding.task_id == session.task_id
            && request.binding.life_id == session.life_id
            && request.binding.session_id == session.session_id
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn canary_prepare_revalidation(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: &mut RevalidateGrant,
    ) -> Result<Option<D32HostCanaryMode>, String> {
        let Some(control) = session.canary_control() else {
            return Ok(None);
        };
        if !canary_exact_cargo_request(session, request) {
            return Ok(None);
        }
        let exact_capability =
            request.binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID;
        let exact_tool = request.binding.program_id == CARGO_PROGRAM_ID;
        let exact_profile = request.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID;
        let exact_cargo_check = request.binding.argv_count == 2
            && request.binding.argv_hash == CARGO_ARGV_HASH
            && request.binding.stdout_bound == 65_536
            && request.binding.stderr_bound == 65_536
            && request.binding.timeout_ms == 120_000
            && request.binding.environment_policy_hash == CARGO_ENVIRONMENT_POLICY_HASH
            && request.binding.git_metadata_fence_hash == CARGO_NO_GIT_METADATA_FENCE;
        control.trace.update(|trace| {
            trace.exact_capability = exact_capability;
            trace.exact_tool = exact_tool;
            trace.exact_profile = exact_profile;
            trace.exact_cargo_check = exact_cargo_check;
        });
        let first_fence = control.trace.snapshot().pre_native_fence_seen;
        if first_fence {
            return Ok(None);
        }
        let run_id = d32_run_id(
            &request.binding.session_id,
            &request.binding.turn_id,
            &request.binding.tool_call_id,
        );
        control.trace.update(|trace| {
            trace.native_evidence_run_id = Some(run_id);
            trace.native_evidence_session_id = Some(request.binding.session_id.clone());
            trace.native_evidence_life_id = Some(request.binding.life_id.clone());
            trace.native_evidence_task_id = Some(request.binding.task_id.clone());
            trace.native_evidence_turn_id = Some(request.binding.turn_id.clone());
            trace.native_evidence_tool_call_id = Some(request.binding.tool_call_id.clone());
        });
        control
            .trace
            .update(|trace| trace.pre_native_fence_seen = true);
        match control.mode {
            D32HostCanaryMode::Positive | D32HostCanaryMode::GrantReplay => Ok(Some(control.mode)),
            D32HostCanaryMode::RevokeBeforeRevalidation => {
                let capability_id = CapabilityId::try_from(PRODUCTION_CARGO_CHECK_CAPABILITY_ID)
                    .map_err(|_| d32_not_executable("Cargo capability id invalid"))?;
                let authority = storage
                    .capability_authorization_scope()
                    .map_err(|error| d32_not_executable(error.code))?;
                let row = authority
                    .find_capability_authorization(&session.life_id, &capability_id)
                    .map_err(|_| d32_not_executable("Cargo capability authorization unavailable"))?
                    .ok_or_else(|| d32_not_executable("Cargo capability authorization missing"))?;
                if !row.enabled {
                    return Err(d32_not_executable(
                        "Cargo capability root was already disabled before revoke mode",
                    ));
                }
                drop(authority);
                let transition = apply_transition_for_host_canary(
                    storage,
                    registry,
                    PRODUCTION_CARGO_CHECK_CAPABILITY_ID,
                    false,
                    row.revision,
                    &session.life_id,
                )
                .map_err(|error| {
                    d32_not_executable(format!("revoke transition failed: {error:?}"))
                })?;
                control.set_revoke_restore_revision(transition.revision);
                control.trace.update(|trace| trace.revoke_applied = true);
                Ok(Some(control.mode))
            }
            D32HostCanaryMode::CancelBeforeRevalidation => {
                control.signal_cancel_worker();
                control.cancel_barrier().wait();
                Ok(Some(control.mode))
            }
            D32HostCanaryMode::ExecutableIdentityTamper => {
                request.binding.executable_identity =
                    format!("d32-a-tampered-{}", request.binding.executable_identity);
                Ok(Some(control.mode))
            }
            D32HostCanaryMode::EnvironmentProfileTamper => {
                request.binding.environment_policy_hash =
                    format!("d32-a-tampered-{}", request.binding.environment_policy_hash);
                Ok(Some(control.mode))
            }
            D32HostCanaryMode::LifeBeforeRevalidation => {
                d32_life_switch_snapshot(storage)?;
                control
                    .trace
                    .update(|trace| trace.life_switch_applied = true);
                Ok(Some(control.mode))
            }
            D32HostCanaryMode::MigrationBeforeRevalidation => {
                d32_migration_snapshot(storage)?;
                control
                    .trace
                    .update(|trace| trace.isolated_migration_applied = true);
                Ok(Some(control.mode))
            }
        }
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_life_switch_snapshot(storage: &StorageService) -> Result<(), String> {
        let before = storage
            .get_current_life()
            .map_err(|error| d32_not_executable(format!("canary Life read failed: {error:?}")))?
            .ok_or_else(|| d32_not_executable("canary current Life was not published"))?;
        let persona_id = format!("d32-a-persona-{}", std::process::id());
        let life_id = format!("d32-a-life-switch-{}", std::process::id());
        storage
            .save_persona(crate::storage::PersonaTemplateRecord {
                id: persona_id.clone(),
                name: "D32-A canary Life-switch persona".to_string(),
                version: 1,
                persona_json: "{}".to_string(),
            })
            .map_err(|error| {
                d32_not_executable(format!("canary persona write failed: {error:?}"))
            })?;
        storage
            .save_life(crate::storage::LifeIdentityRecord {
                id: life_id.clone(),
                name: "D32-A canary Life-switch life".to_string(),
                created_at: "2026-09-19T00:00:00.000Z".to_string(),
                version: 1,
                body_id: format!("d32-a-body-{}", std::process::id()),
                persona_id,
                persona_version: 1,
            })
            .map_err(|error| d32_not_executable(format!("canary Life write failed: {error:?}")))?;
        let current = storage
            .get_current_life()
            .map_err(|error| {
                d32_not_executable(format!("canary Life switch read failed: {error:?}"))
            })?
            .ok_or_else(|| d32_not_executable("canary switched Life was not published"))?;
        if current.id == before.id || current.id != life_id {
            return Err(d32_not_executable("canary Life switch was not exact"));
        }
        Ok(())
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_migration_snapshot(storage: &StorageService) -> Result<(), String> {
        let source = storage.active_data_root().map_err(|error| {
            d32_not_executable(format!("canary active root unavailable: {error:?}"))
        })?;
        let parent = source
            .parent()
            .ok_or_else(|| d32_not_executable("canary migration parent unavailable"))?;
        let target = parent.join(format!("d32-a-migration-target-{}", std::process::id()));
        if target.exists() {
            return Err(d32_not_executable("canary migration target already exists"));
        }
        let migration = storage.migrate_location(
            target
                .to_str()
                .ok_or_else(|| d32_not_executable("canary migration target path invalid"))?,
        );
        if !migration.success || !migration.restart_required {
            return Err(d32_not_executable(format!(
                "canary migration did not return restart-required success: {:?}",
                migration.failed_stage
            )));
        }
        let current = storage
            .get_current_life()
            .map_err(|error| {
                d32_not_executable(format!("canary migrated Life read failed: {error:?}"))
            })?
            .ok_or_else(|| d32_not_executable("canary migrated Life was absent"))?;
        if current.id.is_empty() {
            return Err(d32_not_executable(
                "canary migrated Life identity was empty",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn handle_revalidate_grant_canary(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        secrets: &WindowsCredentialSecretStore,
        request: RevalidateGrant,
    ) -> Result<(), String> {
        let exact_d32 = canary_exact_cargo_request(session, &request);
        let mut effective_request = request.clone();
        let mode =
            match canary_prepare_revalidation(session, storage, registry, &mut effective_request) {
                Ok(mode) => mode,
                Err(error) => {
                    session.canary_stage_failure(
                        D32HostCanaryStage::Revalidate,
                        exact_d32,
                        D32StageFailureCode::OperationFailed,
                    );
                    return Err(error);
                }
            };
        let Some(control) = session.canary_control() else {
            let response =
                revalidate_grant_decision(session, storage, registry, effective_request)?;
            return session.send(&HostMessage::GrantRevalidated(response));
        };
        let response =
            match revalidate_grant_decision(session, storage, registry, effective_request) {
                Ok(response) => response,
                Err(error) => {
                    session.canary_stage_failure(
                        D32HostCanaryStage::Revalidate,
                        exact_d32,
                        D32StageFailureCode::OperationFailed,
                    );
                    return Err(error);
                }
            };
        let expected_restart_code = match mode {
            Some(D32HostCanaryMode::LifeBeforeRevalidation) => Some(LIFE_RESTART_REQUIRED),
            Some(D32HostCanaryMode::MigrationBeforeRevalidation) => {
                Some(CAPABILITY_AUTHORITY_RESTART_REQUIRED)
            }
            _ => None,
        };
        if let Some(expected_code) = expected_restart_code {
            if response.allowed || response.error_code.as_deref() != Some(expected_code) {
                return Err(d32_not_executable(format!(
                    "canonical restart denial was not exact: expected {expected_code}, got {:?}",
                    response.error_code
                )));
            }
        }
        if mode == Some(D32HostCanaryMode::GrantReplay) && response.allowed {
            // Hold the first canonical response.  The exact same parsed
            // inbound request is then sent through the canonical dispatch
            // boundary a second time; the consumed Host ledger must deny it.
            // Only that safe denial is released on the wire.
            control
                .trace
                .update(|trace| trace.replay_first_allowed += 1);
            control.begin_replay_capture()?;
            let replay_result = d32_dispatch_replay_inbound(
                session,
                storage,
                registry,
                secrets,
                VitaMessage::RevalidateGrant(request.clone()),
            );
            if let Err(error) = replay_result {
                let _ = control.finish_replay_capture();
                return Err(error);
            }
            let replay_response = control.finish_replay_capture()?;
            let replay_denied = !replay_response.allowed;
            control.trace.update(|trace| {
                trace.replay_checked = true;
                trace.replay_denied = replay_denied;
            });
            if !replay_denied {
                return Err(
                    "D32_A_HOST_FAILURE: GrantReplay canonical duplicate was allowed".to_string(),
                );
            }
            let result = session.send(&HostMessage::GrantRevalidated(replay_response));
            session.canary_stage_result(
                D32HostCanaryStage::Revalidate,
                exact_d32,
                replay_denied,
                result.is_ok(),
            );
            return result;
        }
        if matches!(
            mode,
            Some(
                D32HostCanaryMode::ExecutableIdentityTamper
                    | D32HostCanaryMode::EnvironmentProfileTamper
            )
        ) {
            control
                .trace
                .update(|trace| trace.tamper_denied = !response.allowed);
        }
        let response_allowed = response.allowed;
        let result = session.send(&HostMessage::GrantRevalidated(response));
        session.canary_stage_result(
            D32HostCanaryStage::Revalidate,
            exact_d32,
            response_allowed,
            result.is_ok(),
        );
        result
    }

    fn handle_revalidate_grant_with_secrets(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        _secrets: &WindowsCredentialSecretStore,
        request: RevalidateGrant,
    ) -> Result<(), String> {
        #[cfg(feature = "d32-a-host-canary")]
        if session.canary_control().is_some() {
            return handle_revalidate_grant_canary(session, storage, registry, _secrets, request);
        }
        let response = revalidate_grant_decision(session, storage, registry, request)?;
        session.send(&HostMessage::GrantRevalidated(response))
    }

    fn handle_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RevalidateGrant,
    ) -> Result<(), String> {
        let secrets = WindowsCredentialSecretStore::new();
        handle_revalidate_grant_with_secrets(session, storage, registry, &secrets, request)
    }

    fn current_workspace_revision(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &ProcessBinding,
    ) -> Result<i64, String> {
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        current_workspace_revision_in_scope(&authority_scope, registry, session, binding)
    }

    fn current_workspace_revision_in_scope(
        authority: &crate::storage::CapabilityAuthorizationScope<'_>,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &ProcessBinding,
    ) -> Result<i64, String> {
        validate_binding(session, binding)?;
        let capability_id = CapabilityId::try_from(binding.capability_id.as_str())
            .map_err(|_| "invalid capability identity".to_string())?;
        let descriptor = registry
            .descriptor(&capability_id)
            .ok_or_else(|| "CAPABILITY_AUTHORIZATION_REQUIRED".to_string())?;
        let expected_profile = if binding.capability_id == PRODUCTION_GIT_STATUS_CAPABILITY_ID {
            PRODUCTION_GIT_STATUS_PROFILE_ID
        } else {
            PRODUCTION_CARGO_CHECK_PROFILE_ID
        };
        let expected_tool = if binding.capability_id == PRODUCTION_GIT_STATUS_CAPABILITY_ID {
            PRODUCTION_GIT_STATUS_TOOL_NAME
        } else {
            PRODUCTION_CARGO_CHECK_TOOL_NAME
        };
        if descriptor.execution_profile() != Some(expected_profile)
            || descriptor.tool_name() != Some(expected_tool)
            || descriptor.scope_requirement() != ScopeRequirement::WorkspaceRequired
        {
            return Err("CAPABILITY_AUTHORIZATION_UNAVAILABLE".to_string());
        }
        let decision = evaluate_capability_authorization_in_scope(
            authority,
            registry,
            &session.life_id,
            &capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|error| {
            if matches!(
                error.code,
                CapabilityEvaluationErrorCode::AuthorityRestartRequired
            ) {
                CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string()
            } else {
                error.message
            }
        })?;
        if decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired {
            return Err(decision.decision_code().as_str().to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "authorization revision was absent".to_string())
    }

    fn validate_binding(
        session: &HostSessionState,
        binding: &ProcessBinding,
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "Vita process binding was malformed".to_string())?;
        let cargo_profile_exact = if binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID {
            let Some(expected) = session.cargo_profile.as_ref() else {
                return Err("D32 Host Cargo profile evidence was absent".to_string());
            };
            let current = {
                match session.app_data_root_retained.as_ref() {
                    Some(root) => {
                        let selection = host_read_cargo_selection_marker_retained(root)?;
                        host_cargo_profile_evidence_for_selection(root, &selection).map_err(
                            |_| {
                                "D32 Host Cargo profile evidence changed or became unavailable"
                                    .to_string()
                            },
                        )?
                    }
                    None => expected.clone(),
                }
            };
            let fresh_source_exact = {
                match session.app_data_root_retained.as_ref() {
                    Some(root) => match host_cargo_run_source_identity_retained(root, binding) {
                        Ok(identity) => identity == binding.working_directory_identity,
                        Err(_) => false,
                    },
                    None => {
                        binding.working_directory_identity
                            == expected.staged_working_directory_identity
                    }
                }
            };
            current == *expected
                && !expected.toolchain_manifest_hash.is_empty()
                && binding.executable_identity == expected.executable_identity
                && binding.executable_sha256 == expected.executable_sha256
                && fresh_source_exact
                && binding.environment_policy_hash == expected.environment_policy_hash
                && binding.profile_id == expected.profile_id
        } else {
            false
        };
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || !((binding.capability_id == PRODUCTION_GIT_STATUS_CAPABILITY_ID
                && binding.program_id == PROGRAM_ID
                && binding.profile_id == PRODUCTION_GIT_STATUS_PROFILE_ID
                && binding.git_metadata_fence_hash.len() == 64
                && binding
                    .git_metadata_fence_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
                || (binding.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
                    && binding.program_id == CARGO_PROGRAM_ID
                    && binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
                    && binding.argv_count == 2
                    && binding.argv_hash == CARGO_ARGV_HASH
                    && binding.stdout_bound == 65_536
                    && binding.stderr_bound == 65_536
                    && binding.timeout_ms == 120_000
                    && cargo_profile_exact
                    && binding.git_metadata_fence_hash == CARGO_NO_GIT_METADATA_FENCE))
            || binding.workspace_root_identity != session.workspace_identity
        {
            return Err("Vita process binding was not exact".to_string());
        }
        Ok(())
    }

    fn active_h7_binding_matches(
        active: &HostTurnActive,
        host_turn_id: &str,
        binding: &ProcessBinding,
    ) -> bool {
        active.turn_id == host_turn_id
            && active
                .h7_codex_turn_id
                .as_deref()
                .is_some_and(|codex_turn_id| codex_turn_id == binding.turn_id)
    }

    fn take_pending(session: &HostSessionState, pending_id: &str) -> Option<PendingAction> {
        let removed = session.pending.lock().ok().and_then(|mut pending| {
            pending
                .iter()
                .find_map(|(key, value)| (pending_key(value) == pending_id).then_some(key.clone()))
                .and_then(|key| pending.remove(&key))
        });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, pending));
        }
        removed
    }

    fn take_workspace_read_pending(
        session: &HostSessionState,
        pending_id: &str,
    ) -> Option<WorkspaceReadPendingAction> {
        let removed = session
            .workspace_read_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                pending
                    .iter()
                    .find_map(|(key, value)| {
                        (value.pending_id == pending_id).then_some(key.clone())
                    })
                    .and_then(|key| pending.remove(&key))
            });
        if let Some(ref pending) = removed {
            session.expiry.clear(&ExpiryTicket::for_workspace_pending(
                &session.session_id,
                pending,
            ));
        }
        removed
    }

    fn take_workspace_replace_pending(
        session: &HostSessionState,
        pending_id: &str,
    ) -> Option<WorkspaceReplacePendingAction> {
        let removed = session
            .workspace_replace_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                let key = pending.iter().find_map(|(key, value)| {
                    (value.pending_id == pending_id).then_some(key.clone())
                });
                key.and_then(|key| pending.remove(&key))
            });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_workspace_replace_pending(
                    &session.session_id,
                    pending,
                ));
        }
        removed
    }

    fn take_recovery_pending(
        session: &HostSessionState,
        pending_id: &str,
    ) -> Option<RecoveryPendingAction> {
        let removed = session
            .recovery_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                let key = pending.iter().find_map(|(key, value)| {
                    (value.pending_id == pending_id).then_some(key.clone())
                });
                key.and_then(|key| pending.remove(&key))
            });
        if let Some(ref pending) = removed {
            session.expiry.clear(&ExpiryTicket::for_recovery_pending(
                &session.session_id,
                pending,
            ));
        }
        removed
    }

    fn take_any_pending(session: &HostSessionState) -> Option<PendingAction> {
        let removed = session.pending.lock().ok().and_then(|mut pending| {
            let key = pending.keys().next().cloned()?;
            pending.remove(&key)
        });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, pending));
        }
        removed
    }

    fn take_any_workspace_read_pending(
        session: &HostSessionState,
    ) -> Option<WorkspaceReadPendingAction> {
        let removed = session
            .workspace_read_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                let key = pending.keys().next().cloned()?;
                pending.remove(&key)
            });
        if let Some(ref pending) = removed {
            session.expiry.clear(&ExpiryTicket::for_workspace_pending(
                &session.session_id,
                pending,
            ));
        }
        removed
    }

    fn take_any_workspace_replace_pending(
        session: &HostSessionState,
    ) -> Option<WorkspaceReplacePendingAction> {
        let removed = session
            .workspace_replace_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                let key = pending.keys().next().cloned()?;
                pending.remove(&key)
            });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_workspace_replace_pending(
                    &session.session_id,
                    pending,
                ));
        }
        removed
    }

    fn take_any_recovery_pending(session: &HostSessionState) -> Option<RecoveryPendingAction> {
        let removed = session
            .recovery_pending
            .lock()
            .ok()
            .and_then(|mut pending| {
                let key = pending.keys().next().cloned()?;
                pending.remove(&key)
            });
        if let Some(ref pending) = removed {
            session.expiry.clear(&ExpiryTicket::for_recovery_pending(
                &session.session_id,
                pending,
            ));
        }
        removed
    }

    fn send_confirmation_decision(
        session: &HostSessionState,
        pending: &PendingAction,
        decision: ConfirmationDecision,
        authorization_revision: Option<i64>,
    ) -> Result<(), String> {
        let result = session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
            request_id: pending.request_id.clone(),
            session_id: session.session_id.clone(),
            decision,
            authorization_revision,
        }));
        #[cfg(feature = "d32-a-host-canary")]
        if pending.capability_id == PRODUCTION_CARGO_CHECK_CAPABILITY_ID
            && pending.binding.profile_id == PRODUCTION_CARGO_CHECK_PROFILE_ID
        {
            if let Some(control) = session.canary_control.as_ref() {
                if result.is_ok() {
                    let bridge_decision = match decision {
                        ConfirmationDecision::Confirm => D32BridgeDecision::Confirm,
                        ConfirmationDecision::Deny => D32BridgeDecision::Deny,
                        ConfirmationDecision::Cancel => D32BridgeDecision::Cancel,
                    };
                    control.trace.bridge_replied(bridge_decision);
                    control
                        .trace
                        .stage_passed(D32HostCanaryStage::ConfirmationBridge);
                } else {
                    control.trace.stage_failed(
                        D32HostCanaryStage::ConfirmationBridge,
                        D32StageFailureCode::OperationFailed,
                    );
                }
            }
        }
        result
    }

    fn send_workspace_read_confirmation_decision(
        session: &HostSessionState,
        pending: &WorkspaceReadPendingAction,
        decision: ConfirmationDecision,
        authorization_revision: Option<i64>,
    ) -> Result<(), String> {
        session.send(&HostMessage::WorkspaceReadConfirmationReply(
            WorkspaceReadConfirmationReply {
                request_id: pending.request_id.clone(),
                session_id: session.session_id.clone(),
                decision,
                authorization_revision,
            },
        ))
    }

    fn send_workspace_replace_confirmation_decision(
        session: &HostSessionState,
        pending: &WorkspaceReplacePendingAction,
        decision: ConfirmationDecision,
        authorization_revision: Option<i64>,
    ) -> Result<(), String> {
        session.send(&HostMessage::WorkspaceReplaceConfirmationReply(
            WorkspaceReplaceConfirmationReply {
                request_id: pending.request_id.clone(),
                session_id: session.session_id.clone(),
                decision,
                authorization_revision,
            },
        ))
    }

    fn send_recovery_confirmation_decision(
        session: &HostSessionState,
        pending: &RecoveryPendingAction,
        decision: ConfirmationDecision,
        authorization_revision: Option<i64>,
    ) -> Result<(), String> {
        session.send(&HostMessage::RecoveryConfirmationReply(
            RecoveryConfirmationReply {
                request_id: pending.request_id.clone(),
                session_id: session.session_id.clone(),
                decision,
                authorization_revision,
            },
        ))
    }

    fn workspace_read_protocol_error_is_terminal(error: &str) -> bool {
        matches!(
            error,
            "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
                | "WORKSPACE_READ_BINDING_MISMATCH"
                | "WORKSPACE_READ_GRANT_NOT_FOUND"
                | "WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH"
                | "WORKSPACE_READ_GRANT_REVALIDATION_DENIED"
                | "WORKSPACE_READ_CONFIRMATION_NOT_APPROVED"
                | "WORKSPACE_READ_CONFIRMATION_STALE"
                | "WORKSPACE_READ_GRANT_ALREADY_REVALIDATED"
        )
    }

    fn expire_pending(session: &HostSessionState) {
        let now = unix_millis();
        let expired = if let Ok(mut pending) = session.pending.lock() {
            let mut expired = Vec::new();
            pending.retain(|_, value| {
                if value.expires_at_unix_ms <= now {
                    expired.push(value.clone());
                    false
                } else {
                    true
                }
            });
            expired
        } else {
            Vec::new()
        };
        for pending in expired {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, &pending));
            let _ = send_confirmation_decision(session, &pending, ConfirmationDecision::Deny, None);
        }
        let expired = if let Ok(mut pending) = session.workspace_read_pending.lock() {
            let mut expired = Vec::new();
            pending.retain(|_, value| {
                if value.expires_at_unix_ms <= now {
                    expired.push(value.clone());
                    false
                } else {
                    true
                }
            });
            expired
        } else {
            Vec::new()
        };
        for pending in expired {
            session.expiry.clear(&ExpiryTicket::for_workspace_pending(
                &session.session_id,
                &pending,
            ));
            let _ = send_workspace_read_confirmation_decision(
                session,
                &pending,
                ConfirmationDecision::Deny,
                None,
            );
        }
        let expired = if let Ok(mut pending) = session.workspace_replace_pending.lock() {
            let mut expired = Vec::new();
            pending.retain(|_, value| {
                if value.expires_at_unix_ms <= now {
                    expired.push(value.clone());
                    false
                } else {
                    true
                }
            });
            expired
        } else {
            Vec::new()
        };
        for pending in expired {
            session
                .expiry
                .clear(&ExpiryTicket::for_workspace_replace_pending(
                    &session.session_id,
                    &pending,
                ));
            let _ = send_workspace_replace_confirmation_decision(
                session,
                &pending,
                ConfirmationDecision::Deny,
                None,
            );
        }
        let expired = if let Ok(mut pending) = session.recovery_pending.lock() {
            let mut expired = Vec::new();
            pending.retain(|_, value| {
                if value.expires_at_unix_ms <= now {
                    expired.push(value.clone());
                    false
                } else {
                    true
                }
            });
            expired
        } else {
            Vec::new()
        };
        for pending in expired {
            session.expiry.clear(&ExpiryTicket::for_recovery_pending(
                &session.session_id,
                &pending,
            ));
            let _ = send_recovery_confirmation_decision(
                session,
                &pending,
                ConfirmationDecision::Deny,
                None,
            );
        }
    }

    fn handle_workspace_replace_authority_evaluate(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReplaceAuthorityEvaluate,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace replace authority request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) || request.session_id != session.session_id {
            return Err("WORKSPACE_REPLACE_BINDING_MISMATCH".to_string());
        }
        validate_workspace_replace_binding(session, &request.binding)?;
        let mut authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        let active = match &mut *authority {
            HostTurnAuthority::Active(active) if active.turn_id == request.host_turn_id => active,
            _ => {
                return session.send(&HostMessage::WorkspaceReplaceAuthorityReply(
                    WorkspaceReplaceAuthorityReply {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        authorization_revision: None,
                        error_code: Some("TURN_NOT_ACTIVE".to_string()),
                    },
                ));
            }
        };
        if active.binding.binding_hash != request.binding.provider_binding_hash
            || active
                .h7_codex_turn_id
                .as_deref()
                .is_some_and(|turn| turn != request.binding.codex_turn_id)
        {
            let result = session.send(&HostMessage::WorkspaceReplaceAuthorityReply(
                WorkspaceReplaceAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("PROVIDER_BINDING_MISMATCH".to_string()),
                },
            ));
            drop(authority);
            result?;
            return Err("WORKSPACE_REPLACE_BINDING_MISMATCH".to_string());
        }
        let result = match storage.capability_authorization_scope() {
            Ok(scope) => require_current_session_life(storage, session).and_then(|_| {
                current_workspace_replace_revision_in_scope(
                    &scope,
                    registry,
                    session,
                    &request.binding,
                )
            }),
            Err(error) => Err(capability_authorization_gate_error(error)),
        };
        let response = match result {
            Ok(revision) => {
                active.h7_codex_turn_id = Some(request.binding.codex_turn_id.clone());
                WorkspaceReplaceAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                }
            }
            Err(error) => WorkspaceReplaceAuthorityReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                authorization_revision: None,
                error_code: Some(error_code(&error)),
            },
        };
        let send_result = session.send(&HostMessage::WorkspaceReplaceAuthorityReply(response));
        drop(authority);
        send_result
    }

    fn handle_workspace_replace_confirmation_required(
        session: &Arc<HostSessionState>,
        request: WorkspaceReplaceConfirmationRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita workspace replace confirmation request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) || request.session_id != session.session_id {
            return Err("WORKSPACE_REPLACE_BINDING_MISMATCH".to_string());
        }
        validate_workspace_replace_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            session.send(&HostMessage::WorkspaceReplaceConfirmationReply(
                WorkspaceReplaceConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                },
            ))?;
            return Ok(());
        };
        expire_pending(session);
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_replace_turn_matches(
            &authority,
            &request.host_turn_id,
            &request.binding,
        ) {
            let result = session.send(&HostMessage::WorkspaceReplaceConfirmationReply(
                WorkspaceReplaceConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Cancel,
                    authorization_revision: None,
                },
            ));
            drop(authority);
            result?;
            return Err("WORKSPACE_REPLACE_TURN_NOT_ACTIVE".to_string());
        }
        let pending_id = format!("replace-pending:{}", secure_id("vita")?);
        let pending_action = WorkspaceReplacePendingAction {
            pending_id: pending_id.clone(),
            request_id: request.request_id,
            host_turn_id: request.host_turn_id,
            life_id: request.binding.life_id.clone(),
            task_id: request.binding.task_id.clone(),
            capability_id: request.binding.capability_id.clone(),
            workspace_summary: request.workspace_summary,
            expires_at_unix_ms,
            binding: request.binding,
        };
        let h7_pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        let read_pending = session
            .workspace_read_pending
            .lock()
            .map_err(|_| "Vita workspace read pending state lock was poisoned".to_string())?;
        let mut pending = session
            .workspace_replace_pending
            .lock()
            .map_err(|_| "Vita workspace replace pending state lock was poisoned".to_string())?;
        let recovery_pending = session
            .recovery_pending
            .lock()
            .map_err(|_| "Vita recovery pending state lock was poisoned".to_string())?;
        if h7_pending.len() + read_pending.len() + pending.len() + recovery_pending.len()
            >= MAX_PENDING
        {
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket =
            ExpiryTicket::for_workspace_replace_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(recovery_pending);
        drop(pending);
        drop(read_pending);
        drop(h7_pending);
        drop(authority);
        session.expiry.schedule(ticket);
        Ok(())
    }

    fn issue_workspace_replace_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReplaceIssueGrant,
    ) -> Result<WorkspaceReplaceGrant, String> {
        request
            .validate()
            .map_err(|_| "WORKSPACE_REPLACE_ISSUE_INVALID".to_string())?;
        validate_workspace_replace_binding(session, &request.binding)?;
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_replace_turn_matches(
            &authority,
            &request.host_turn_id,
            &request.binding,
        ) {
            return Err("WORKSPACE_REPLACE_TURN_NOT_ACTIVE".to_string());
        }
        // Keep the shared D30 authority scope held through the authoritative
        // Issued -> Revalidated ledger transition.  Releasing it after the
        // revision read would let a concurrent revoke (or generation
        // retirement) commit before this grant transition and still allow the
        // final mutation fence to pass.
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        require_current_session_life(authority_scope.storage(), session)?;
        let current_revision = current_workspace_replace_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        if current_revision != request.authorization_revision {
            return Err("CAPABILITY_AUTHORIZATION_REVISION_MISMATCH".to_string());
        }
        let key = workspace_replace_approval_key(&request.host_turn_id, &request.binding);
        let mut approvals = session
            .workspace_replace_approvals
            .lock()
            .map_err(|_| "Vita workspace replace approval state lock was poisoned".to_string())?;
        let approval = approvals
            .remove(&key)
            .ok_or_else(|| "WORKSPACE_REPLACE_CONFIRMATION_NOT_APPROVED".to_string())?;
        if approval.host_turn_id != request.host_turn_id
            || approval.binding != request.binding
            || approval.authorization_revision != request.authorization_revision
            || approval.expires_at_unix_ms <= unix_millis()
        {
            return Err("WORKSPACE_REPLACE_CONFIRMATION_STALE".to_string());
        }
        let now = unix_millis();
        let expires_at_unix_ms = approval
            .expires_at_unix_ms
            .min(now.saturating_add(GRANT_LIFETIME_MS));
        if expires_at_unix_ms <= now {
            return Err("WORKSPACE_REPLACE_GRANT_EXPIRED".to_string());
        }
        let grant = WorkspaceReplaceGrant {
            session_id: session.session_id.clone(),
            grant_id: secure_id("vita-replace-grant")?,
            confirmation_id: approval.confirmation_id,
            binding: request.binding.clone(),
            authorization_revision: request.authorization_revision,
            issued_at_unix_ms: now,
            expires_at_unix_ms,
            single_use: true,
            used: false,
        };
        grant
            .validate()
            .map_err(|_| "WORKSPACE_REPLACE_GRANT_INVALID".to_string())?;
        let mut grants = session
            .workspace_replace_grants
            .lock()
            .map_err(|_| "Vita workspace replace grant state lock was poisoned".to_string())?;
        reap_expired_workspace_replace_grants(&mut grants);
        if grants.len() >= MAX_GRANTS {
            return Err("WORKSPACE_REPLACE_GRANT_CAPACITY_EXHAUSTED".to_string());
        }
        grants.insert(
            grant.grant_id.clone(),
            WorkspaceReplaceGrantState {
                host_turn_id: request.host_turn_id.clone(),
                grant: grant.clone(),
                phase: WorkspaceReplaceGrantPhase::Issued,
            },
        );
        drop(authority);
        Ok(grant)
    }

    fn revalidate_workspace_replace_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &WorkspaceReplaceRevalidateGrant,
    ) -> Result<WorkspaceReplaceGrant, String> {
        request
            .validate()
            .map_err(|_| "WORKSPACE_REPLACE_REVALIDATION_INVALID".to_string())?;
        validate_workspace_replace_binding(session, &request.binding)?;
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !active_workspace_replace_turn_matches(
            &authority,
            &request.host_turn_id,
            &request.binding,
        ) {
            return Err("WORKSPACE_REPLACE_TURN_NOT_ACTIVE".to_string());
        }
        // Keep the D30 authority scope held until the single-use grant ledger
        // commits Issued -> Revalidated.  This is the final mutation fence:
        // revoke, Life switch, and storage-generation retirement cannot commit
        // between the revision read and this state transition.
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        require_current_session_life(authority_scope.storage(), session)?;
        let current_revision = current_workspace_replace_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        let mut grants = session
            .workspace_replace_grants
            .lock()
            .map_err(|_| "Vita workspace replace grant state lock was poisoned".to_string())?;
        let state = grants
            .get_mut(&request.grant.grant_id)
            .ok_or_else(|| "WORKSPACE_REPLACE_GRANT_NOT_FOUND".to_string())?;
        if state.host_turn_id != request.host_turn_id
            || state.phase != WorkspaceReplaceGrantPhase::Issued
            || state.grant != request.grant
            || state.grant.binding != request.binding
            || state.grant.authorization_revision != current_revision
            || state.grant.expires_at_unix_ms <= unix_millis()
        {
            return Err("WORKSPACE_REPLACE_GRANT_REVALIDATION_DENIED".to_string());
        }
        state.grant.used = true;
        state.phase = WorkspaceReplaceGrantPhase::Revalidated;
        let result = state.grant.clone();
        drop(grants);
        drop(authority_scope);
        drop(authority);
        Ok(result)
    }

    fn handle_workspace_replace_issue_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReplaceIssueGrant,
    ) -> Result<(), String> {
        let result = issue_workspace_replace_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::WorkspaceReplaceGrantIssued(
                WorkspaceReplaceGrantIssued {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                },
            )),
            Err(error) => session.send(&HostMessage::WorkspaceReplaceGrantIssued(
                WorkspaceReplaceGrantIssued {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error_code(&error)),
                },
            )),
        }
    }

    fn handle_workspace_replace_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: WorkspaceReplaceRevalidateGrant,
    ) -> Result<(), String> {
        let result = revalidate_workspace_replace_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::WorkspaceReplaceGrantRevalidated(
                WorkspaceReplaceGrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                },
            )),
            Err(error) => session.send(&HostMessage::WorkspaceReplaceGrantRevalidated(
                WorkspaceReplaceGrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error_code(&error)),
                },
            )),
        }
    }

    fn handle_recovery_authority_evaluate(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RecoveryAuthorityEvaluate,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita recovery authority request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) || request.session_id != session.session_id {
            return Err("RECOVERY_BINDING_MISMATCH".to_string());
        }
        validate_recovery_binding(session, &request.binding)?;
        let mut actions = session
            .recovery_actions
            .lock()
            .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?;
        let Some(action) = actions.get_mut(&request.recovery_action_id) else {
            return session.send(&HostMessage::RecoveryAuthorityReply(
                RecoveryAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("RECOVERY_ACTION_NOT_FOUND".to_string()),
                },
            ));
        };
        if !recovery_action_matches(action, &request.binding)
            || !matches!(
                action.phase,
                HostRecoveryActionPhase::Requested | HostRecoveryActionPhase::AwaitingAuthority
            )
        {
            return session.send(&HostMessage::RecoveryAuthorityReply(
                RecoveryAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("RECOVERY_BINDING_MISMATCH".to_string()),
                },
            ));
        }
        let authority_scope = match storage.capability_authorization_scope() {
            Ok(scope) => scope,
            Err(error) => {
                return session.send(&HostMessage::RecoveryAuthorityReply(
                    RecoveryAuthorityReply {
                        request_id: request.request_id,
                        session_id: session.session_id.clone(),
                        allowed: false,
                        authorization_revision: None,
                        error_code: Some(error_code(&capability_authorization_gate_error(error))),
                    },
                ));
            }
        };
        let result =
            require_current_session_life(authority_scope.storage(), session).and_then(|_| {
                current_recovery_revision_in_scope(
                    &authority_scope,
                    registry,
                    session,
                    &request.binding,
                )
            });
        let response = match result {
            Ok(revision) => {
                action.phase = HostRecoveryActionPhase::AwaitingConfirmation;
                RecoveryAuthorityReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                }
            }
            Err(error) => RecoveryAuthorityReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                authorization_revision: None,
                error_code: Some(error_code(&error)),
            },
        };
        let send_result = session.send(&HostMessage::RecoveryAuthorityReply(response));
        drop(authority_scope);
        drop(actions);
        send_result
    }

    fn handle_recovery_confirmation_required(
        session: &Arc<HostSessionState>,
        request: RecoveryConfirmationRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita recovery confirmation request was malformed".to_string())?;
        if session.closed.load(Ordering::Acquire) || request.session_id != session.session_id {
            return Err("RECOVERY_BINDING_MISMATCH".to_string());
        }
        validate_recovery_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            session.send(&HostMessage::RecoveryConfirmationReply(
                RecoveryConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                },
            ))?;
            return Ok(());
        };
        expire_pending(session);
        let action_matches = session
            .recovery_actions
            .lock()
            .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?
            .get(&request.recovery_action_id)
            .is_some_and(|action| {
                recovery_action_matches(action, &request.binding)
                    && action.phase == HostRecoveryActionPhase::AwaitingConfirmation
            });
        if !action_matches {
            let result = session.send(&HostMessage::RecoveryConfirmationReply(
                RecoveryConfirmationReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    decision: ConfirmationDecision::Cancel,
                    authorization_revision: None,
                },
            ));
            result?;
            return Err("RECOVERY_ACTION_NOT_ACTIVE".to_string());
        }
        let pending_id = format!("recovery-pending:{}", secure_id("vita")?);
        let pending_action = RecoveryPendingAction {
            pending_id: pending_id.clone(),
            request_id: request.request_id,
            recovery_action_id: request.recovery_action_id,
            recovery_generation: request.binding.recovery_generation.clone(),
            life_id: request.binding.life_id.clone(),
            task_id: request.binding.task_id.clone(),
            capability_id: request.binding.capability_id.clone(),
            workspace_summary: request.workspace_summary,
            expires_at_unix_ms,
            binding: request.binding,
        };
        let h7_pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        let read_pending = session
            .workspace_read_pending
            .lock()
            .map_err(|_| "Vita workspace read pending state lock was poisoned".to_string())?;
        let replace_pending = session
            .workspace_replace_pending
            .lock()
            .map_err(|_| "Vita workspace replace pending state lock was poisoned".to_string())?;
        let mut pending = session
            .recovery_pending
            .lock()
            .map_err(|_| "Vita recovery pending state lock was poisoned".to_string())?;
        if h7_pending.len() + read_pending.len() + replace_pending.len() + pending.len()
            >= MAX_PENDING
        {
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket = ExpiryTicket::for_recovery_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(pending);
        drop(replace_pending);
        drop(read_pending);
        drop(h7_pending);
        session.expiry.schedule(ticket);
        Ok(())
    }

    fn issue_recovery_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &RecoveryIssueGrant,
    ) -> Result<RecoveryGrant, String> {
        request
            .validate()
            .map_err(|_| "RECOVERY_ISSUE_INVALID".to_string())?;
        validate_recovery_binding(session, &request.binding)?;
        // Recovery uses the same D30 linearization fence as replacement.  The
        // Host action ledger, current Life, D28 revision, approval consume,
        // and grant insertion remain serialized as one authority decision.
        let mut actions = session
            .recovery_actions
            .lock()
            .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?;
        let action = actions
            .get_mut(&request.recovery_action_id)
            .filter(|action| {
                recovery_action_matches(action, &request.binding)
                    && action.phase == HostRecoveryActionPhase::AwaitingConfirmation
            })
            .ok_or_else(|| "RECOVERY_ACTION_NOT_ACTIVE".to_string())?;
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        require_current_session_life(authority_scope.storage(), session)?;
        let current_revision = current_recovery_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        if current_revision != request.authorization_revision {
            return Err("CAPABILITY_AUTHORIZATION_REVISION_MISMATCH".to_string());
        }
        let key = recovery_approval_key(&request.recovery_action_id, &request.binding);
        let mut approvals = session
            .recovery_approvals
            .lock()
            .map_err(|_| "Vita recovery approval state lock was poisoned".to_string())?;
        let approval = approvals
            .remove(&key)
            .ok_or_else(|| "RECOVERY_CONFIRMATION_NOT_APPROVED".to_string())?;
        if approval.recovery_action_id != request.recovery_action_id
            || approval.recovery_generation != request.binding.recovery_generation
            || approval.binding != request.binding
            || approval.authorization_revision != request.authorization_revision
            || approval.expires_at_unix_ms <= unix_millis()
        {
            return Err("RECOVERY_CONFIRMATION_STALE".to_string());
        }
        let now = unix_millis();
        let expires_at_unix_ms = approval
            .expires_at_unix_ms
            .min(now.saturating_add(GRANT_LIFETIME_MS));
        if expires_at_unix_ms <= now {
            return Err("RECOVERY_GRANT_EXPIRED".to_string());
        }
        let grant = RecoveryGrant {
            session_id: session.session_id.clone(),
            grant_id: secure_id("vita-recovery-grant")?,
            confirmation_id: approval.confirmation_id,
            binding: request.binding.clone(),
            authorization_revision: request.authorization_revision,
            issued_at_unix_ms: now,
            expires_at_unix_ms,
            single_use: true,
            used: false,
        };
        grant
            .validate()
            .map_err(|_| "RECOVERY_GRANT_INVALID".to_string())?;
        let mut grants = session
            .recovery_grants
            .lock()
            .map_err(|_| "Vita recovery grant state lock was poisoned".to_string())?;
        reap_expired_recovery_grants(&mut grants);
        if grants.len() >= MAX_GRANTS {
            return Err("RECOVERY_GRANT_CAPACITY_EXHAUSTED".to_string());
        }
        grants.insert(
            grant.grant_id.clone(),
            RecoveryGrantState {
                recovery_action_id: request.recovery_action_id.clone(),
                recovery_generation: request.binding.recovery_generation.clone(),
                grant: grant.clone(),
                phase: RecoveryGrantPhase::Issued,
            },
        );
        action.phase = HostRecoveryActionPhase::GrantIssued;
        drop(grants);
        drop(approvals);
        drop(authority_scope);
        drop(actions);
        Ok(grant)
    }

    fn revalidate_recovery_grant(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        request: &RecoveryRevalidateGrant,
    ) -> Result<RecoveryGrant, String> {
        request
            .validate()
            .map_err(|_| "RECOVERY_REVALIDATION_INVALID".to_string())?;
        validate_recovery_binding(session, &request.binding)?;
        // Hold the D30 capability scope through the exact grant ledger commit.
        // A revoke, Life switch, or storage-generation retirement that wins
        // first therefore makes this fence fail before any mutation can run.
        let mut actions = session
            .recovery_actions
            .lock()
            .map_err(|_| "Vita recovery action state lock was poisoned".to_string())?;
        let action = actions
            .get_mut(&request.recovery_action_id)
            .filter(|action| {
                recovery_action_matches(action, &request.binding)
                    && action.phase == HostRecoveryActionPhase::GrantIssued
            })
            .ok_or_else(|| "RECOVERY_ACTION_NOT_ACTIVE".to_string())?;
        let authority_scope = storage
            .capability_authorization_scope()
            .map_err(capability_authorization_gate_error)?;
        require_current_session_life(authority_scope.storage(), session)?;
        let current_revision = current_recovery_revision_in_scope(
            &authority_scope,
            registry,
            session,
            &request.binding,
        )?;
        let mut grants = session
            .recovery_grants
            .lock()
            .map_err(|_| "Vita recovery grant state lock was poisoned".to_string())?;
        let state = grants
            .get_mut(&request.grant.grant_id)
            .ok_or_else(|| "RECOVERY_GRANT_NOT_FOUND".to_string())?;
        if state.recovery_action_id != request.recovery_action_id
            || state.recovery_generation != request.binding.recovery_generation
            || state.phase != RecoveryGrantPhase::Issued
            || state.grant != request.grant
            || state.grant.binding != request.binding
            || state.grant.authorization_revision != current_revision
            || state.grant.used
            || !state.grant.single_use
            || state.grant.expires_at_unix_ms <= unix_millis()
        {
            return Err("RECOVERY_GRANT_REVALIDATION_DENIED".to_string());
        }
        state.grant.used = true;
        state.phase = RecoveryGrantPhase::Revalidated;
        action.phase = HostRecoveryActionPhase::Revalidated;
        let result = state.grant.clone();
        drop(grants);
        drop(authority_scope);
        drop(actions);
        Ok(result)
    }

    fn handle_recovery_issue_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RecoveryIssueGrant,
    ) -> Result<(), String> {
        let result = issue_recovery_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::RecoveryGrantIssued(RecoveryGrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            })),
            Err(error) => session.send(&HostMessage::RecoveryGrantIssued(RecoveryGrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            })),
        }
    }

    fn handle_recovery_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RecoveryRevalidateGrant,
    ) -> Result<(), String> {
        let result = revalidate_recovery_grant(storage, registry, session, &request);
        match result {
            Ok(grant) => session.send(&HostMessage::RecoveryGrantRevalidated(
                RecoveryGrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                },
            )),
            Err(error) => session.send(&HostMessage::RecoveryGrantRevalidated(
                RecoveryGrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error_code(&error)),
                },
            )),
        }
    }

    fn reap_expired_grants(grants: &mut HashMap<String, HostStoredGrant>) {
        let now = unix_millis();
        grants.retain(|_, grant| !grant.grant.used && grant.grant.expires_at_unix_ms > now);
    }

    fn reap_expired_workspace_read_grants(grants: &mut HashMap<String, WorkspaceReadGrantState>) {
        let now = unix_millis();
        grants.retain(|_, state| {
            state.phase == WorkspaceReadGrantPhase::Released || state.grant.expires_at_unix_ms > now
        });
    }

    fn reap_expired_workspace_replace_grants(
        grants: &mut HashMap<String, WorkspaceReplaceGrantState>,
    ) {
        let now = unix_millis();
        grants.retain(|_, state| state.grant.expires_at_unix_ms > now);
    }

    fn reap_expired_recovery_grants(grants: &mut HashMap<String, RecoveryGrantState>) {
        let now = unix_millis();
        grants.retain(|_, state| state.grant.expires_at_unix_ms > now);
    }

    fn consume_active_grant(
        grants: &mut HashMap<String, HostStoredGrant>,
        host_turn_id: &str,
        requested: &ProcessGrant,
        binding: &ProcessBinding,
        authorization_revision: i64,
    ) -> Result<ProcessGrant, String> {
        let stored = grants
            .get(&requested.grant_id)
            .cloned()
            .ok_or_else(|| "Vita grant was not found".to_string())?;
        if stored.host_turn_id != host_turn_id
            || stored.grant != *requested
            || stored.grant.used
            || !stored.grant.single_use
            || stored.grant.binding != *binding
            || stored.grant.authorization_revision != authorization_revision
            || stored.grant.expires_at_unix_ms <= unix_millis()
        {
            return Err("Vita grant revalidation was denied".to_string());
        }
        let mut consumed = grants
            .remove(&requested.grant_id)
            .ok_or_else(|| "Vita grant was not found".to_string())?;
        consumed.grant.used = true;
        Ok(consumed.grant)
    }

    fn effective_confirmation_expiry(now: u64, vita_expiry: u64) -> Option<u64> {
        let host_deadline = now.saturating_add(HOST_CONFIRMATION_TTL_MS);
        let effective = vita_expiry.min(host_deadline);
        (effective > now).then_some(effective)
    }

    fn binding_key(binding: &ProcessBinding) -> String {
        format!("{}:{}", binding.tool_call_id, binding.turn_id)
    }

    fn approval_key(host_turn_id: &str, binding: &ProcessBinding) -> String {
        format!("{host_turn_id}:{}", binding_key(binding))
    }

    fn workspace_read_approval_key(
        host_turn_id: &str,
        binding: &protocol::WorkspaceReadBinding,
    ) -> String {
        format!(
            "{host_turn_id}:{}:{}",
            binding.tool_call_id, binding.codex_turn_id
        )
    }

    fn workspace_replace_approval_key(
        host_turn_id: &str,
        binding: &protocol::WorkspaceReplaceBinding,
    ) -> String {
        format!(
            "{host_turn_id}:{}:{}",
            binding.tool_call_id, binding.codex_turn_id
        )
    }

    fn recovery_approval_key(
        recovery_action_id: &str,
        binding: &protocol::RecoveryBinding,
    ) -> String {
        format!(
            "{recovery_action_id}:{}:{}",
            binding.recovery_generation, binding.transaction_id
        )
    }

    fn vita_request_id(message: &VitaMessage) -> &str {
        match message {
            VitaMessage::Handshake(message) => &message.request_id,
            VitaMessage::Ready(message) => &message.request_id,
            VitaMessage::AuthorityEvaluate(message) => &message.request_id,
            VitaMessage::ConfirmationRequired(message) => &message.request_id,
            VitaMessage::IssueGrant(message) => &message.request_id,
            VitaMessage::RevalidateGrant(message) => &message.request_id,
            VitaMessage::WorkspaceReadAuthorityEvaluate(message) => &message.request_id,
            VitaMessage::WorkspaceReadConfirmationRequired(message) => &message.request_id,
            VitaMessage::WorkspaceReadIssueGrant(message) => &message.request_id,
            VitaMessage::WorkspaceReadRevalidateGrant(message) => &message.request_id,
            VitaMessage::WorkspaceReadReleaseCheck(message) => &message.request_id,
            VitaMessage::WorkspaceReplaceAuthorityEvaluate(message) => &message.request_id,
            VitaMessage::WorkspaceReplaceConfirmationRequired(message) => &message.request_id,
            VitaMessage::WorkspaceReplaceIssueGrant(message) => &message.request_id,
            VitaMessage::WorkspaceReplaceRevalidateGrant(message) => &message.request_id,
            VitaMessage::RecoveryAuthorityEvaluate(message) => &message.request_id,
            VitaMessage::RecoveryConfirmationRequired(message) => &message.request_id,
            VitaMessage::RecoveryIssueGrant(message) => &message.request_id,
            VitaMessage::RecoveryRevalidateGrant(message) => &message.request_id,
            VitaMessage::RecoveryPending(message) => &message.request_id,
            VitaMessage::RecoveryResult(message) => &message.request_id,
            VitaMessage::ActionCancelled(message) => &message.request_id,
            VitaMessage::CredentialRequired(message) => &message.request_id,
            VitaMessage::TurnState(message) => &message.request_id,
            VitaMessage::TurnCompleted(message) => &message.request_id,
            VitaMessage::TurnFailed(message) => &message.request_id,
            VitaMessage::ShutdownAck(message) => &message.request_id,
            VitaMessage::Fatal(message) => &message.request_id,
        }
    }

    fn validate_handshake(handshake: &protocol::Handshake) -> Result<(), String> {
        if handshake.protocol_version != PROTOCOL_VERSION
            || handshake.runtime != RUNTIME_ID
            || handshake.codex_commit != CODEX_UPSTREAM_COMMIT
            || handshake.codex_schema_hash != CODEX_PROTOCOL_SCHEMA_HASH
        {
            return Err("Vita sidecar handshake identity was not pinned".to_string());
        }
        Ok(())
    }

    fn validate_ready(
        ready: &protocol::Ready,
        session_id: &str,
        request: &VitaSidecarStartRequest,
        host_life_id: &str,
    ) -> Result<(), String> {
        if ready.session_id != session_id
            || ready.life_id != host_life_id
            || ready.task_id != request.task_id
            || ready.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || ready.profile_id != PRODUCTION_GIT_STATUS_PROFILE_ID
            || ready.tool_name != PRODUCTION_GIT_STATUS_TOOL_NAME
            || ready.workspace_identity.is_empty()
        {
            return Err("Vita sidecar ready identity was not exact".to_string());
        }
        Ok(())
    }

    fn receive_vita_message_with_timeout(
        mut reader: BufReader<File>,
        timeout: Duration,
        label: &'static str,
    ) -> Result<(VitaMessage, BufReader<File>), String> {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("vita-sidecar-{label}"))
            .spawn(move || {
                let result = protocol::read_frame(&mut reader)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("{label} channel closed"))
                    .and_then(|body| {
                        protocol::decode_frame::<VitaMessage>(&body).map_err(|e| e.to_string())
                    });
                let _ = sender.send(result.map(|value| (value, reader)));
                Ok::<(), String>(())
            })
            .map_err(|_| format!("{label} reader could not start"))?;
        match receiver.recv_timeout(timeout) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(format!("{label} failed: {error}")),
            Err(RecvTimeoutError::Timeout) => Err(format!("{label} timed out")),
            Err(RecvTimeoutError::Disconnected) => Err(format!("{label} reader failed")),
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SidecarPathBinding {
        path: PathBuf,
        resource_dir: PathBuf,
    }

    fn app_owned_sidecar_path<R: Runtime>(
        app: &AppHandle<R>,
    ) -> Result<SidecarPathBinding, String> {
        let resource_dir = sidecar_resource_dir(app)?;
        let resource_dir = fs::canonicalize(&resource_dir)
            .map_err(|_| "Vita resource directory could not be canonicalized".to_string())?;
        let candidate = fs::canonicalize(resource_dir.join(SIDECAR_RESOURCE_NAME))
            .map_err(|_| "Vita sidecar image is not installed".to_string())?;
        if !candidate.is_file() || candidate.parent() != Some(resource_dir.as_path()) {
            return Err(
                "Vita sidecar image is outside the app-owned resource directory".to_string(),
            );
        }
        Ok(SidecarPathBinding {
            path: candidate,
            resource_dir,
        })
    }

    fn sidecar_app_data_root<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
        #[cfg(test)]
        if let Some(root) = std::env::var_os("D32_A_TEST_APP_DATA_ROOT") {
            return Ok(PathBuf::from(root));
        }
        #[cfg(all(feature = "d32-a-host-canary", not(test)))]
        if let Some(root) = std::env::var_os("D32_A_CANARY_APP_DATA_ROOT") {
            return Ok(PathBuf::from(root));
        }
        app.path()
            .app_data_dir()
            .map_err(|error| format!("Vita app data root unavailable: {error}"))
    }

    fn sidecar_resource_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
        #[cfg(test)]
        if let Some(root) = std::env::var_os("D32_A_TEST_RESOURCE_DIR") {
            return Ok(PathBuf::from(root));
        }
        #[cfg(all(feature = "d32-a-host-canary", not(test)))]
        if let Some(root) = std::env::var_os("D32_A_CANARY_RESOURCE_DIR") {
            return Ok(PathBuf::from(root));
        }
        app.path()
            .resource_dir()
            .map_err(|error| format!("Vita resource directory unavailable: {error}"))
    }

    fn resolve_git_path() -> Result<PathBuf, String> {
        // Absolute, fixed install locations only.  There is deliberately no
        // PATH lookup and no model/user-supplied executable path in this lane.
        let candidates = [
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
            PathBuf::from(r"E:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"E:\Program Files\Git\mingw64\bin\git.exe"),
        ];
        candidates
            .into_iter()
            .filter_map(|candidate| fs::canonicalize(candidate).ok())
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| "No trusted absolute Git image is installed".to_string())
    }

    fn validate_private_app_data_root(path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || path.components().any(|component| {
                component
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(".codex")
            })
        {
            return Err(
                "Vita app data root is outside the private application namespace".to_string(),
            );
        }
        Ok(())
    }

    fn normalize_sidecar_local_path(path: &Path) -> Result<PathBuf, String> {
        let value = path.to_string_lossy().replace('/', "\\");
        let value = value.strip_prefix(r"\\?\").unwrap_or(&value);
        if value.starts_with(r"\\")
            || value.starts_with(r"\Device\")
            || value.starts_with(r"\GlobalRoot\")
        {
            return Err("Vita sidecar path was not a local drive path".to_string());
        }
        let normalized = PathBuf::from(value);
        if !normalized.is_absolute() {
            return Err("Vita sidecar path was not absolute".to_string());
        }
        Ok(normalized)
    }

    fn spawn_stderr_drain(mut stderr: File) {
        let _ = thread::Builder::new()
            .name("vita-sidecar-stderr-drain".to_string())
            .spawn(move || {
                let mut buffer = [0_u8; 4096];
                let mut total = 0_usize;
                loop {
                    match std::io::Read::read(&mut stderr, &mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => total = total.saturating_add(read.min(16 * 1024 - total)),
                    }
                    if total >= 16 * 1024 {
                        // Continue draining without retaining unbounded data.
                        total = 16 * 1024;
                    }
                }
            });
    }

    fn validate_id(value: &str) -> Result<(), String> {
        if value.is_empty()
            || value.len() > protocol::MAX_ID_BYTES
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_-.".contains(&byte)))
        {
            return Err("Vita identity was invalid".to_string());
        }
        Ok(())
    }

    fn error_code(error: &str) -> String {
        if error == CAPABILITY_AUTHORITY_RESTART_REQUIRED {
            CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string()
        } else if matches!(error, LIFE_RESTART_REQUIRED | LIFE_UNAVAILABLE) {
            error.to_string()
        } else if error.starts_with("CAPABILITY_") {
            error.to_string()
        } else if error.contains("revision") {
            "STALE_AUTHORIZATION_REVISION".to_string()
        } else if error.contains("binding") {
            "BINDING_MISMATCH".to_string()
        } else {
            "AUTHORITY_DENIED".to_string()
        }
    }

    fn map_process_error(error: CodexRuntimeError) -> String {
        format!("Vita sidecar process boundary failed: {error}")
    }

    fn next_id(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn secure_id(prefix: &str) -> Result<String, String> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| "Vita Host cryptographic identity generation failed".to_string())?;
        let suffix = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("{prefix}-{suffix}"))
    }

    fn unix_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_millis().min(u64::MAX as u128) as u64
            })
    }

    pub fn start_vita_sidecar(
        app: AppHandle,
        coordinator: State<'_, VitaSidecarCoordinator>,
        request: VitaSidecarStartRequest,
    ) -> Result<VitaSidecarStartResponse, String> {
        coordinator.start(&app, request)
    }

    pub fn get_vita_sidecar_status(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarStatusResponse, String> {
        coordinator.status()
    }

    pub fn confirm_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
        pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.confirm(pending_id)
    }

    pub fn recover_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
        transaction_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.recover(transaction_id)
    }

    pub fn deny_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
        pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.deny(pending_id)
    }

    pub fn cancel_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.cancel()
    }

    pub fn start_vita_turn(
        coordinator: State<'_, VitaSidecarCoordinator>,
        request: VitaTurnStartRequest,
    ) -> Result<VitaTurnStartResponse, String> {
        coordinator.start_turn(request)
    }

    pub fn cancel_vita_turn(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.cancel_turn()
    }

    pub fn stop_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.stop()
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_not_executable(message: impl Into<String>) -> String {
        let message = message.into().to_ascii_lowercase();
        let code = if message.contains("cleanup") {
            "cleanup_failed"
        } else if message.contains("git") || message.contains("metadata") {
            "git_boundary"
        } else if message.contains("life") || message.contains("migration") {
            "life_state"
        } else if message.contains("cargo") || message.contains("toolchain") {
            "toolchain"
        } else if message.contains("credential") || message.contains("profile") {
            "auth_state"
        } else if message.contains("path")
            || message.contains("root")
            || message.contains("directory")
            || message.contains("resource")
        {
            "host_layout"
        } else {
            "preflight_failed"
        };
        format!("D32_A_NOT_EXECUTABLE: {code}")
    }

    #[cfg(feature = "d32-a-host-canary")]
    const D32_CANARY_CARGO_PROMPT: &str = "Do not answer with text. Your first and only action must be call vita_workspace_cargo_check exactly once with {} now; wait for its result, then summarize.";

    #[cfg(feature = "d32-a-host-canary")]
    const D32_CANARY_DIAGNOSTIC_MAX_TEXT_CHARS: usize = 512;

    #[cfg(feature = "d32-a-host-canary")]
    const D32_CANARY_DIAGNOSTIC_MAX_ERROR_CODE_CHARS: usize = 64;

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_canary_contains_sensitive_marker(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        [
            "authorization",
            "bearer",
            "token",
            "secret",
            "credential",
            "password",
            "api_key",
            "api-key",
            "apikey",
            "cookie",
            "set-cookie",
            "client_secret",
            "access_key",
            "private_key",
            "provider",
            "base_url",
            "base url",
            "endpoint",
            "request",
            "response",
            "body",
            "header",
            "environment",
            " env",
            "http://",
            "https://",
            "://",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_canary_contains_secret_like_token(value: &str) -> bool {
        value.split_whitespace().any(|token| {
            let token = token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric()
                    && !matches!(character, '_' | '-' | '.' | '/' | '+' | '=')
            });
            let length = token.chars().count();
            length >= 24
                && token.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(character, '_' | '-' | '.' | '/' | '+' | '=')
                })
        })
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_canary_sanitize_assistant_text(text: &str) -> String {
        let mut sanitized = String::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty()
                || d32_canary_contains_sensitive_marker(line)
                || d32_canary_contains_secret_like_token(line)
            {
                continue;
            }
            let line = line
                .chars()
                .filter(|character| !character.is_control())
                .collect::<String>();
            if line.is_empty() {
                continue;
            }
            if !sanitized.is_empty() {
                sanitized.push('\n');
            }
            sanitized.push_str(&line);
            if sanitized.chars().count() >= D32_CANARY_DIAGNOSTIC_MAX_TEXT_CHARS {
                break;
            }
        }
        sanitized
            .chars()
            .take(D32_CANARY_DIAGNOSTIC_MAX_TEXT_CHARS)
            .collect()
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_canary_sanitize_error_code(error_code: Option<&str>) -> String {
        let Some(error_code) = error_code else {
            return "<none>".to_string();
        };
        let error_code = error_code.trim();
        if error_code.is_empty()
            || error_code.chars().count() > D32_CANARY_DIAGNOSTIC_MAX_ERROR_CODE_CHARS
            || d32_canary_contains_sensitive_marker(error_code)
            || error_code.chars().any(|character| {
                !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-' | '.')
            })
        {
            return "<redacted>".to_string();
        }
        error_code.to_string()
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_canary_no_confirmation_diagnostic(
        assistant_text: Option<&str>,
        turn_phase: Option<protocol::TurnPhase>,
        turn_error: Option<&str>,
    ) -> String {
        let assistant_text_length = assistant_text.map_or(0, |text| text.chars().count());
        let assistant_text_preview = assistant_text
            .map(d32_canary_sanitize_assistant_text)
            .unwrap_or_default();
        let terminal_phase = turn_phase
            .map(|phase| format!("{phase:?}"))
            .unwrap_or_else(|| "<none>".to_string());
        let turn_error_code = d32_canary_sanitize_error_code(turn_error);
        format!(
            "provider produced no governed cargo confirmation; terminal_phase={terminal_phase}; turn_error_code={turn_error_code}; assistant_text_len_chars={assistant_text_length}; assistant_text_preview={assistant_text_preview:?}"
        )
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_require_cargo_root(storage: &StorageService, life_id: &str) -> Result<(), String> {
        let capability_id = CapabilityId::try_from(PRODUCTION_CARGO_CHECK_CAPABILITY_ID)
            .map_err(|_| d32_not_executable("Cargo capability id invalid"))?;
        let authority = storage
            .capability_authorization_scope()
            .map_err(|error| d32_not_executable(error.code))?;
        let row = authority
            .find_capability_authorization(life_id, &capability_id)
            .map_err(|_| d32_not_executable("Cargo capability authorization unavailable"))?;
        if row.is_some_and(|row| row.enabled) {
            Ok(())
        } else {
            Err(d32_not_executable("Cargo capability root is not enabled"))
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_parse_git_config_section(name: &str) -> Result<(String, bool), String> {
        if name.is_empty() || name.contains('\0') {
            return Err(d32_not_executable(
                "candidate Git config section was malformed",
            ));
        }
        let mut pieces = name.splitn(2, char::is_whitespace);
        let section = pieces.next().unwrap_or_default().trim();
        let remainder = pieces.next().unwrap_or_default().trim();
        if section.is_empty() {
            return Err(d32_not_executable(
                "candidate Git config section was malformed",
            ));
        }
        if remainder.is_empty() {
            return Ok((section.to_ascii_lowercase(), false));
        }
        if !remainder.starts_with('"') || !remainder.ends_with('"') || remainder.len() < 2 {
            return Err(d32_not_executable(
                "candidate Git config subsection was malformed",
            ));
        }
        Ok((section.to_ascii_lowercase(), true))
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_validate_git_config_bytes(bytes: &[u8]) -> Result<String, String> {
        const MAX_CONFIG_BYTES: usize = 256 * 1024;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(d32_not_executable(
                "candidate Git config exceeded its bound",
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| d32_not_executable("candidate Git config was not UTF-8"))?;
        let mut section = None;
        for raw_line in text.lines() {
            if raw_line.trim_end().ends_with('\\') {
                return Err(d32_not_executable(
                    "candidate Git config continuation was rejected",
                ));
            }
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                if !line.ends_with(']') || line.len() < 3 {
                    return Err(d32_not_executable(
                        "candidate Git config section was malformed",
                    ));
                }
                let parsed = d32_parse_git_config_section(&line[1..line.len() - 1])?;
                if parsed.0 == "include"
                    || parsed.0.starts_with("includeif")
                    || parsed.0.starts_with("include.")
                    || parsed.0 == "core.worktree"
                {
                    return Err(d32_not_executable(
                        "candidate Git config external indirection was rejected",
                    ));
                }
                section = Some(parsed);
                continue;
            }
            let (section, has_subsection) = section
                .as_ref()
                .map(|(name, has_subsection)| (name.as_str(), *has_subsection))
                .ok_or_else(|| {
                    d32_not_executable("candidate Git config key preceded its section")
                })?;
            let key_end = line
                .find(|character: char| character == '=' || character.is_ascii_whitespace())
                .unwrap_or(line.len());
            let key = line[..key_end].trim();
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(d32_not_executable("candidate Git config key was malformed"));
            }
            let key = key.to_ascii_lowercase();
            let dotted_key = if key.contains('.') {
                key.clone()
            } else {
                format!("{section}.{key}")
            };
            let filter_command = section == "filter"
                && has_subsection
                && matches!(key.as_str(), "clean" | "process" | "smudge");
            if dotted_key == "core.worktree"
                || dotted_key == "include.path"
                || dotted_key.starts_with("includeif.")
                || dotted_key == "extensions.worktreeconfig"
                || dotted_key == "core.excludesfile"
                || dotted_key == "core.attributesfile"
                || filter_command
                || (dotted_key.starts_with("filter.")
                    && (dotted_key.ends_with(".clean")
                        || dotted_key.ends_with(".process")
                        || dotted_key.ends_with(".smudge")))
            {
                return Err(d32_not_executable(
                    "candidate Git config external execution or indirection was rejected",
                ));
            }
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    struct D32GitMetadataFence {
        // All production authority below is retained-handle based.  The
        // command's repository pathname remains a launch projection only.
        workspace_root: D32RetainedDirectory,
        git_directory: D32RetainedDirectory,
        config_retained: D32RetainedFile,
        git_directory_identity: HostFileIdentity,
        config_identity: HostFileIdentity,
        config_bytes: Vec<u8>,
        config_hash: String,
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_optional_git_metadata_retained(
        git_directory: &D32RetainedDirectory,
        name: &OsStr,
        expect_directory: bool,
        description: &str,
    ) -> Result<Option<HostFileIdentity>, String> {
        if expect_directory {
            return git_directory
                .open_existing_child_if_present(name)
                .map(|child| child.map(|child| child.identity()))
                .map_err(|error| {
                    d32_not_executable(format!(
                        "candidate Git metadata fence failed for {description}: {error}"
                    ))
                });
        }
        git_directory
            .open_existing_file_if_present(name)
            .map(|file| file.map(|file| file.identity()))
            .map_err(|error| {
                d32_not_executable(format!(
                    "candidate Git metadata fence failed for {description}: {error}"
                ))
            })
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_validate_forbidden_git_metadata(
        git_directory: &D32RetainedDirectory,
        phase: &str,
    ) -> Result<(), String> {
        for (name, expect_directory, description) in [
            (OsStr::new("gitdir"), false, ".git/gitdir"),
            (OsStr::new("commondir"), false, ".git/commondir"),
            (OsStr::new("worktrees"), true, ".git/worktrees"),
        ] {
            if d32_optional_git_metadata_retained(
                git_directory,
                name,
                expect_directory,
                description,
            )?
            .is_some()
            {
                return Err(d32_not_executable(format!(
                    "forbidden Git metadata {phase}: {description}"
                )));
            }
        }
        let Some(objects) = git_directory.open_existing_child_if_present(OsStr::new("objects"))?
        else {
            return Ok(());
        };
        let Some(info) = objects.open_existing_child_if_present(OsStr::new("info"))? else {
            return Ok(());
        };
        if d32_optional_git_metadata_retained(
            &info,
            OsStr::new("alternates"),
            false,
            ".git/objects/info/alternates",
        )?
        .is_some()
        {
            return Err(d32_not_executable(format!(
                "forbidden Git metadata {phase}: .git/objects/info/alternates"
            )));
        }
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl D32GitMetadataFence {
        fn capture(workspace_root: D32RetainedDirectory) -> Result<Self, String> {
            workspace_root.revalidate("candidate Git workspace root before metadata capture")?;
            let git_directory = workspace_root
                .open_existing_child(OsStr::new(".git"))
                .map_err(|error| {
                    d32_not_executable(format!("candidate Git metadata identity failed: {error}"))
                })?;
            let config_retained = git_directory
                .open_existing_file(OsStr::new("config"))
                .map_err(|error| {
                    d32_not_executable(format!("candidate Git config identity failed: {error}"))
                })?;
            let config_bytes = config_retained
                .read_bounded(256 * 1024)
                .map_err(|error| d32_not_executable(error))?;
            let config_hash = d32_validate_git_config_bytes(&config_bytes)?;
            workspace_root.revalidate("candidate Git workspace root after metadata capture")?;
            git_directory.revalidate("candidate Git metadata after capture")?;
            config_retained.revalidate("candidate Git config after capture")?;
            d32_validate_forbidden_git_metadata(&git_directory, "was present")?;
            let git_directory_identity = git_directory.identity();
            let config_identity = config_retained.identity();
            Ok(Self {
                workspace_root,
                git_directory,
                config_retained,
                git_directory_identity,
                config_identity,
                config_bytes,
                config_hash,
            })
        }

        fn revalidate(&self) -> Result<(), String> {
            self.workspace_root
                .revalidate("candidate Git workspace root recheck")?;
            self.git_directory
                .revalidate("candidate Git metadata recheck")?;
            if self.git_directory.identity() != self.git_directory_identity {
                return Err(d32_not_executable(
                    "candidate Git metadata directory identity changed",
                ));
            }
            self.config_retained
                .revalidate("candidate Git config recheck")?;
            if self.config_retained.identity() != self.config_identity {
                return Err(d32_not_executable("candidate Git config identity changed"));
            }
            let bytes = self
                .config_retained
                .read_bounded(256 * 1024)
                .map_err(|error| d32_not_executable(error))?;
            if bytes != self.config_bytes
                || d32_validate_git_config_bytes(&bytes)? != self.config_hash
            {
                return Err(d32_not_executable("candidate Git config bytes changed"));
            }
            d32_validate_forbidden_git_metadata(&self.git_directory, "appeared")
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_validate_git_status_output(output: &[u8]) -> Result<bool, String> {
        if output.len() > 1024 * 1024 {
            return Err(d32_not_executable(
                "trusted Git status output exceeded its bound",
            ));
        }
        if output.is_empty() {
            return Ok(false);
        }
        if !output.ends_with(&[0]) {
            return Err(d32_not_executable(
                "trusted Git status output was not NUL framed",
            ));
        }
        let mut records = output
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty());
        let validate_path = |path: &[u8]| {
            if path.is_empty()
                || path.starts_with(b"/")
                || path.starts_with(b"\\")
                || path.windows(2).any(|pair| pair == b"..")
            {
                return Err(d32_not_executable(
                    "trusted Git status output contained an unsafe path",
                ));
            }
            Ok(())
        };
        while let Some(record) = records.next() {
            if record.len() < 4 || record[2] != b' ' {
                return Err(d32_not_executable(
                    "trusted Git status output was malformed",
                ));
            }
            let path = &record[3..];
            validate_path(path)?;
            if matches!(record[0], b'R' | b'C') || matches!(record[1], b'R' | b'C') {
                let Some(rename_source) = records.next() else {
                    return Err(d32_not_executable(
                        "trusted Git status rename record was incomplete",
                    ));
                };
                validate_path(rename_source)?;
            }
        }
        Ok(true)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_read_pipe_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
        const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| "trusted Git output could not be drained".to_string())?;
            if read == 0 {
                return Ok(bytes);
            }
            if bytes.len().saturating_add(read) > MAX_OUTPUT_BYTES {
                return Err("trusted Git output exceeded its bound".to_string());
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_run_bounded_git_command(
        command: &mut Command,
        timeout: Duration,
        pre_spawn_fence: impl FnOnce() -> Result<(), String>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), String> {
        // The fence is evaluated at the last possible point before
        // CreateProcessW is reached by std::process::Command.  Earlier
        // validation remains useful for diagnostics, but cannot be the final
        // authority check across command construction.
        pre_spawn_fence()?;
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "trusted Git status process failed to spawn".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "trusted Git stdout pipe was unavailable".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "trusted Git stderr pipe was unavailable".to_string())?;
        let (sender, receiver) = mpsc::channel::<(&'static str, Result<Vec<u8>, String>)>();
        let stdout_sender = sender.clone();
        let _stdout_reader = thread::spawn(move || {
            let _ = stdout_sender.send(("stdout", d32_read_pipe_bounded(stdout)));
        });
        let stderr_sender = sender;
        let _stderr_reader = thread::spawn(move || {
            let _ = stderr_sender.send(("stderr", d32_read_pipe_bounded(stderr)));
        });

        let deadline = Instant::now() + timeout;
        let mut status = None;
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;
        loop {
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| "trusted Git status process could not be reaped".to_string())?;
            }
            while let Ok((stream, result)) = receiver.try_recv() {
                let bytes = result.map_err(|error| {
                    let _ = child.kill();
                    let _ = child.wait();
                    error
                })?;
                match stream {
                    "stdout" => stdout_bytes = Some(bytes),
                    "stderr" => stderr_bytes = Some(bytes),
                    _ => return Err("trusted Git returned an unknown output stream".to_string()),
                }
            }
            if let (Some(status), Some(stdout), Some(stderr)) = (
                status.as_ref(),
                stdout_bytes.as_ref(),
                stderr_bytes.as_ref(),
            ) {
                return Ok((status.clone(), stdout.clone(), stderr.clone()));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("trusted Git status process exceeded its timeout".to_string());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_run_trusted_git_command(
        repository_root: &Path,
        git_path: &Path,
        args: &[&str],
        timeout: Duration,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), String> {
        let git_image = D32RetainedFile::open(git_path).map_err(|error| {
            d32_not_executable(format!("trusted Git image fence failed: {error}"))
        })?;
        let workspace_root = D32RetainedDirectory::open(repository_root).map_err(|error| {
            d32_not_executable(format!("trusted Git workspace retention failed: {error}"))
        })?;
        let metadata_fence = D32GitMetadataFence::capture(workspace_root)?;
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random)
            .map_err(|_| d32_not_executable("trusted Git home identity was unavailable"))?;
        let home = std::env::temp_dir().join(format!(
            "digital-life-d32a-git-home-{}-{}",
            std::process::id(),
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        fs::create_dir(&home)
            .map_err(|_| d32_not_executable("trusted Git home could not be created"))?;
        let ceiling = repository_root
            .parent()
            .ok_or_else(|| d32_not_executable("candidate repository root had no Git ceiling"))?;
        let result = (|| {
            metadata_fence.revalidate()?;
            git_image
                .revalidate("trusted Git image recheck before launch")
                .map_err(|error| {
                    d32_not_executable(format!("trusted Git image recheck failed: {error}"))
                })?;
            let mut command = Command::new(git_path);
            command
                .current_dir(repository_root)
                .args(args)
                .env_clear()
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_OPTIONAL_LOCKS", "0")
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GCM_INTERACTIVE", "Never")
                .env("GIT_CEILING_DIRECTORIES", ceiling)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("XDG_CONFIG_HOME", &home);
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", system_root);
            }
            d32_run_bounded_git_command(&mut command, timeout, || {
                metadata_fence.revalidate()?;
                git_image
                    .revalidate("trusted Git image final fence")
                    .map_err(|error| {
                        d32_not_executable(format!("trusted Git image final fence failed: {error}"))
                    })?;
                Ok(())
            })
            .map_err(d32_not_executable)
        })();
        let cleanup = fs::remove_dir_all(&home).map_err(|error| {
            d32_not_executable(format!("trusted Git home cleanup failed: {error}"))
        });
        let result = match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        };
        git_image
            .revalidate("trusted Git image recheck after launch")
            .map_err(|error| {
                d32_not_executable(format!("trusted Git image recheck failed: {error}"))
            })?;
        metadata_fence.revalidate()?;
        result
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_verify_trusted_git_status(
        repository_root: &Path,
        git_path: &Path,
    ) -> Result<(), String> {
        let (status, stdout, _stderr) = d32_run_trusted_git_command(
            repository_root,
            git_path,
            &[
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "submodule.recurse=false",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            Duration::from_secs(5),
        )?;
        if !status.success() {
            return Err(d32_not_executable("trusted Git status process was denied"));
        }
        if d32_validate_git_status_output(&stdout)? {
            return Err(d32_not_executable("candidate checkout was not clean"));
        }
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_candidate_release_image() -> Result<(PathBuf, String), String> {
        let configured = std::env::var_os("D32_A_CANDIDATE_RELEASE_IMAGE")
            .ok_or_else(|| d32_not_executable("candidate Vita release image is unavailable"))?;
        let path = fs::canonicalize(PathBuf::from(configured))
            .map_err(|_| d32_not_executable("candidate Vita release image is not readable"))?;
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| d32_not_executable("candidate repository root is unavailable"))?
            .to_path_buf();
        let expected_release_path = fs::canonicalize(
            repository_root
                .join("vita-agent")
                .join("target")
                .join("release")
                .join(SIDECAR_RESOURCE_NAME),
        )
        .map_err(|_| d32_not_executable("exact candidate Vita release image is unavailable"))?;
        if path != expected_release_path
            || path.file_name().and_then(|name| name.to_str()) != Some(SIDECAR_RESOURCE_NAME)
        {
            return Err(d32_not_executable(
                "candidate Vita release image is not the exact pinned production image",
            ));
        }
        host_file_identity(&path, false).map_err(|error| {
            d32_not_executable(format!("candidate sidecar identity failed: {error}"))
        })?;
        let expected = std::env::var("D32_A_CANDIDATE_RELEASE_IMAGE_SHA256")
            .map_err(|_| d32_not_executable("candidate Vita release image hash is unavailable"))?;
        if expected.len() != 64 || expected.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
            return Err(d32_not_executable(
                "candidate Vita release image hash is malformed",
            ));
        }
        let expected = expected.to_ascii_lowercase();
        let actual = host_hash_file(&path, D32_IMAGE_HASH_MAX_BYTES).map_err(|error| {
            d32_not_executable(format!("candidate sidecar hash failed: {error}"))
        })?;
        if actual != expected {
            return Err(d32_not_executable(
                "candidate Vita release image hash does not match the supplied evidence",
            ));
        }

        let candidate_sha = std::env::var("D32_A_CANDIDATE_SHA")
            .map_err(|_| d32_not_executable("candidate Git SHA is unavailable"))?;
        if candidate_sha.len() != 40
            || candidate_sha
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(d32_not_executable("candidate Git SHA is malformed"));
        }
        let git_path = resolve_git_path()
            .map_err(|error| d32_not_executable(format!("trusted Git is unavailable: {error}")))?;
        let (git_sha_status, git_sha_stdout, _git_sha_stderr) = d32_run_trusted_git_command(
            &repository_root,
            &git_path,
            &["rev-parse", "--verify", "HEAD"],
            Duration::from_secs(5),
        )?;
        let git_sha_stdout = std::str::from_utf8(&git_sha_stdout)
            .map_err(|_| d32_not_executable("candidate Git provenance output was not UTF-8"))?;
        let git_sha_line = git_sha_stdout.strip_suffix('\n').ok_or_else(|| {
            d32_not_executable(
                "candidate Git provenance output was not one newline-terminated line",
            )
        })?;
        if !git_sha_status.success()
            || git_sha_line != candidate_sha
            || git_sha_stdout[..git_sha_stdout.len() - 1]
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | b' ' | b'\t'))
        {
            return Err(d32_not_executable(
                "candidate release image is not bound to the exact repository SHA",
            ));
        }
        d32_verify_trusted_git_status(&repository_root, &git_path)?;

        let provenance_path = std::env::var_os("D32_A_CANDIDATE_PROVENANCE")
            .ok_or_else(|| d32_not_executable("candidate provenance manifest is unavailable"))?;
        let provenance_path = fs::canonicalize(provenance_path)
            .map_err(|_| d32_not_executable("candidate provenance manifest is unreadable"))?;
        host_file_identity(&provenance_path, false).map_err(|error| {
            d32_not_executable(format!("candidate provenance identity failed: {error}"))
        })?;
        let metadata = fs::metadata(&provenance_path)
            .map_err(|_| d32_not_executable("candidate provenance metadata is unavailable"))?;
        if metadata.len() > 64 * 1024 {
            return Err(d32_not_executable(
                "candidate provenance manifest exceeded its bound",
            ));
        }
        let provenance: serde_json::Value =
            serde_json::from_slice(&fs::read(&provenance_path).map_err(|_| {
                d32_not_executable("candidate provenance manifest could not be read")
            })?)
            .map_err(|_| d32_not_executable("candidate provenance manifest was not valid JSON"))?;
        let field = |name: &str| provenance.get(name).and_then(serde_json::Value::as_str);
        if field("candidate_sha") != Some(candidate_sha.as_str())
            || field("source_repo") != Some(repository_root.to_string_lossy().as_ref())
            || field("image_path") != Some(path.to_string_lossy().as_ref())
            || field("image_sha256") != Some(expected.as_str())
            || field("git_status") != Some("clean")
            || field("build_profile") != Some("release")
            || field("build_command")
                != Some("cargo build --manifest-path vita-agent/Cargo.toml --release --locked --bin vita-agent")
        {
            return Err(d32_not_executable(
                "candidate provenance manifest did not match the exact release contract",
            ));
        }
        Ok((path, expected))
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_restore_revoke(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        life_id: &str,
        control: &D32HostCanaryControl,
    ) -> Result<(), String> {
        let Some(revision) = control.take_revoke_restore_revision() else {
            return Ok(());
        };
        let restored = apply_transition_for_host_canary(
            storage,
            registry,
            PRODUCTION_CARGO_CHECK_CAPABILITY_ID,
            true,
            revision,
            life_id,
        )
        .map_err(|error| format!("D32_A_HOST_FAILURE: revoke restoration failed: {error:?}"))?;
        if !restored.enabled {
            return Err(
                "D32_A_HOST_FAILURE: revoke restoration did not re-enable Cargo".to_string(),
            );
        }
        Ok(())
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_validate_trace(
        mode: D32HostCanaryMode,
        trace: &D32HostCanaryTraceSnapshot,
        terminal_phase: Option<protocol::TurnPhase>,
        turn_error: Option<&str>,
    ) -> Result<(), String> {
        let common_exact = trace.exact_capability
            && trace.exact_tool
            && trace.exact_profile
            && trace.exact_cargo_check;
        let expected_revalidate_count = if mode == D32HostCanaryMode::GrantReplay {
            2
        } else {
            1
        };
        if !common_exact
            || trace.authority_evaluate != 1
            || trace.confirmation_required != 1
            || trace.issue_grant != 1
            || trace.revalidate_grant != expected_revalidate_count
            || trace.replay_wire_responses != 1
        {
            return Err(format!(
                "D32_A_HOST_FAILURE: Host trace was not exact for {mode:?}: {trace:?}"
            ));
        }
        if mode.expects_deny() {
            if trace.grant_revalidated_allowed != 0
                || trace.grant_revalidated_denied != 1
                || trace.turn_completed + trace.turn_failed + trace.action_cancelled != 1
                || trace.grant_denial_code.as_deref().is_none()
                || !matches!(
                    terminal_phase,
                    Some(
                        protocol::TurnPhase::Completed
                            | protocol::TurnPhase::Failed
                            | protocol::TurnPhase::Cancelled
                            | protocol::TurnPhase::TimedOut
                    )
                )
                || (mode == D32HostCanaryMode::CancelBeforeRevalidation
                    && (trace.action_cancelled != 1
                        || terminal_phase != Some(protocol::TurnPhase::Cancelled)))
            {
                return Err(format!(
                    "D32_A_HOST_FAILURE: negative Host trace was not fail-closed: {trace:?}"
                ));
            }
        } else if trace.grant_revalidated_allowed != 1
            || trace.grant_revalidated_denied != 0
            || trace.turn_completed != 1
            || trace.turn_failed != 0
            || trace.grant_denial_code.is_some()
            || turn_error.is_some()
            || !trace.binding_fields_validated
            || terminal_phase != Some(protocol::TurnPhase::Completed)
        {
            return Err(format!(
                "D32_A_HOST_FAILURE: positive Host trace was not exact: {trace:?}"
            ));
        }
        if mode == D32HostCanaryMode::GrantReplay {
            if !trace.replay_checked
                || !trace.replay_denied
                || trace.replay_exact_request_count != 2
                || trace.replay_exact_session_count != 2
                || trace.replay_first_allowed != 1
                || trace.replay_second_denied != 1
            {
                return Err(
                    "D32_A_HOST_FAILURE: GrantReplay did not prove exact canonical pre-native denial"
                        .to_string(),
                );
            }
        } else if trace.replay_exact_request_count != 0
            || trace.replay_exact_session_count != 0
            || trace.replay_first_allowed != 0
            || trace.replay_second_denied != 0
        {
            return Err(format!(
                "D32_A_HOST_FAILURE: unexpected replay evidence for {mode:?}: {trace:?}"
            ));
        }
        if matches!(
            mode,
            D32HostCanaryMode::ExecutableIdentityTamper
                | D32HostCanaryMode::EnvironmentProfileTamper
        ) && !trace.tamper_denied
        {
            return Err("D32_A_HOST_FAILURE: tamper lane was not denied".to_string());
        }
        if mode == D32HostCanaryMode::RevokeBeforeRevalidation && !trace.revoke_applied {
            return Err("D32_A_HOST_FAILURE: revoke seam was not applied".to_string());
        }
        if mode == D32HostCanaryMode::CancelBeforeRevalidation && trace.action_cancelled == 0 {
            return Err(
                "D32_A_HOST_FAILURE: cancellation acknowledgement was not observed".to_string(),
            );
        }
        if mode == D32HostCanaryMode::LifeBeforeRevalidation && !trace.life_switch_applied {
            return Err("D32_A_HOST_FAILURE: isolated Life seam was not applied".to_string());
        }
        if mode == D32HostCanaryMode::MigrationBeforeRevalidation
            && !trace.isolated_migration_applied
        {
            return Err("D32_A_HOST_FAILURE: isolated migration seam was not applied".to_string());
        }
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
    struct D32TreeManifestEntry {
        relative_path: String,
        kind: &'static str,
        identity: String,
        length: u64,
        readonly: bool,
        file_attributes: u32,
        last_write_time: u64,
        sha256: Option<String>,
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct D32TreeManifest {
        exists: bool,
        entries: Vec<D32TreeManifestEntry>,
        digest: String,
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_hash_file_exact(path: &Path) -> Result<String, String> {
        let mut file = File::open(path)
            .map_err(|_| format!("D32 Host audit could not open {}", path.display()))?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| format!("D32 Host audit could not read {}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_tree_manifest_entry(
        path: &Path,
        relative_path: String,
    ) -> Result<D32TreeManifestEntry, String> {
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            format!(
                "D32 Host audit metadata was unavailable: {}",
                path.display()
            )
        })?;
        if host_metadata_is_reparse(&metadata) {
            return Err(format!(
                "D32 Host audit rejected a reparse entry: {}",
                path.display()
            ));
        }
        let is_directory = metadata.is_dir();
        let is_file = metadata.is_file();
        if !is_directory && !is_file {
            return Err(format!(
                "D32 Host audit encountered an unsupported entry: {}",
                path.display()
            ));
        }
        let identity = host_file_identity(path, is_directory)?.namespace_wire();
        let length = if is_file { metadata.len() } else { 0 };
        if length > D32_AUDIT_MAX_BYTES {
            return Err(format!(
                "D32 Host audit file exceeded its byte bound: {}",
                path.display()
            ));
        }
        let mut entry = D32TreeManifestEntry {
            relative_path,
            kind: if is_directory { "directory" } else { "file" },
            identity,
            length,
            readonly: metadata.permissions().readonly(),
            file_attributes: metadata.file_attributes(),
            last_write_time: metadata.last_write_time(),
            sha256: None,
        };
        if is_file {
            entry.sha256 = Some(d32_hash_file_exact(path)?);
        }
        let after = fs::symlink_metadata(path)
            .map_err(|_| format!("D32 Host audit metadata changed: {}", path.display()))?;
        let after_identity = host_file_identity(path, is_directory)?.namespace_wire();
        let after_sha256 = if is_file {
            Some(d32_hash_file_exact(path)?)
        } else {
            None
        };
        if host_metadata_is_reparse(&after)
            || after_identity != entry.identity
            || (is_file && after.len() != entry.length)
            || after.file_attributes() != entry.file_attributes
            || after.last_write_time() != entry.last_write_time
            || after_sha256 != entry.sha256
        {
            return Err(format!(
                "D32 Host audit observed a concurrent metadata/content change: {}",
                path.display()
            ));
        }
        Ok(entry)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_collect_tree_manifest(
        current: &Path,
        relative_path: &str,
        entries: &mut Vec<D32TreeManifestEntry>,
        total_bytes: &mut u64,
        path_bytes: &mut u64,
        name_bytes: &mut u64,
        depth: usize,
    ) -> Result<(), String> {
        if depth > D32_TREE_MAX_DEPTH {
            return Err("D32 Host audit tree exceeded its path-depth bound".to_string());
        }
        d32_audit_path_bytes(current)?;
        if relative_path.as_bytes().len() > D32_AUDIT_MAX_PATH_BYTES {
            return Err("D32 Host audit relative path exceeded its bound".to_string());
        }
        if entries.len() >= D32_AUDIT_MAX_ENTRIES {
            return Err("D32 Host audit tree exceeded its entry bound".to_string());
        }
        let entry = d32_tree_manifest_entry(current, relative_path.to_string())?;
        *total_bytes = total_bytes
            .checked_add(entry.length)
            .ok_or_else(|| "D32 Host audit tree byte bound overflowed".to_string())?;
        if *total_bytes > D32_AUDIT_MAX_BYTES {
            return Err("D32 Host audit tree exceeded its byte bound".to_string());
        }
        entries.push(entry);
        if current.is_dir() {
            let mut children = Vec::new();
            let mut projected_total_bytes = *total_bytes;
            for child in fs::read_dir(current)
                .map_err(|_| format!("D32 Host audit enumeration failed: {}", current.display()))?
            {
                if children.len() >= D32_AUDIT_MAX_ENTRIES {
                    return Err(
                        "D32 Host audit tree exceeded its per-directory entry bound".to_string()
                    );
                }
                let child = child.map_err(|_| "D32 Host audit enumeration failed".to_string())?;
                let child_name_os = child.file_name();
                let child_name_bytes = d32_audit_name_bytes(&child_name_os)?;
                d32_audit_namespace_bytes_add(name_bytes, child_name_bytes)?;
                let child_path = child.path();
                let child_path_bytes = d32_audit_path_bytes(&child_path)?;
                d32_audit_namespace_bytes_add(path_bytes, child_path_bytes)?;
                let child_name = child_name_os.to_string_lossy().into_owned();
                let child_relative = if relative_path == "." {
                    child_name.clone()
                } else {
                    format!("{relative_path}/{child_name}")
                };
                if child_relative.as_bytes().len() > D32_AUDIT_MAX_PATH_BYTES {
                    return Err("D32 Host audit relative path exceeded its bound".to_string());
                }
                let projected_entries = entries
                    .len()
                    .checked_add(children.len())
                    .and_then(|count| count.checked_add(1))
                    .ok_or_else(|| "D32 Host audit tree entry bound overflowed".to_string())?;
                if projected_entries > D32_AUDIT_MAX_ENTRIES {
                    return Err("D32 Host audit tree exceeded its entry bound".to_string());
                }
                let child_metadata = fs::symlink_metadata(&child_path).map_err(|_| {
                    format!(
                        "D32 Host audit metadata was unavailable: {}",
                        child_path.display()
                    )
                })?;
                if host_metadata_is_reparse(&child_metadata) {
                    return Err(format!(
                        "D32 Host audit rejected a reparse entry: {}",
                        child_path.display()
                    ));
                }
                if child_metadata.is_file() {
                    projected_total_bytes = projected_total_bytes
                        .checked_add(child_metadata.len())
                        .ok_or_else(|| "D32 Host audit tree byte bound overflowed".to_string())?;
                    if projected_total_bytes > D32_AUDIT_MAX_BYTES {
                        return Err("D32 Host audit tree exceeded its byte bound".to_string());
                    }
                }
                children.push((child_path, child_name, child_relative));
            }
            children.sort_unstable_by(|left, right| left.1.cmp(&right.1));
            for (child_path, _child_name, child_relative) in children {
                d32_collect_tree_manifest(
                    &child_path,
                    &child_relative,
                    entries,
                    total_bytes,
                    path_bytes,
                    name_bytes,
                    depth.saturating_add(1),
                )?;
            }
        }
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_tree_manifest(path: &Path) -> Result<D32TreeManifest, String> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(D32TreeManifest {
                    exists: false,
                    entries: Vec::new(),
                    digest: format!("{:x}", Sha256::digest(b"D32_A_MISSING_TREE")),
                });
            }
            Err(_) => {
                return Err(format!(
                    "D32 Host audit metadata was unavailable: {}",
                    path.display()
                ));
            }
        };
        if !metadata.is_dir() || host_metadata_is_reparse(&metadata) {
            return Err(format!(
                "D32 Host audit root was not a regular non-reparse directory: {}",
                path.display()
            ));
        }
        let canonical = fs::canonicalize(path).map_err(|_| {
            format!(
                "D32 Host audit root could not be canonicalized: {}",
                path.display()
            )
        })?;
        if canonical != path {
            // Canonicalization is part of the identity fence.  Callers pass
            // canonical roots; accepting a different path here would reopen a
            // potentially redirected namespace during the post-audit check.
            return Err(format!(
                "D32 Host audit root was not canonical: {}",
                path.display()
            ));
        }
        let mut entries = Vec::new();
        let mut total_bytes = 0;
        let mut path_bytes = 0_u64;
        let mut name_bytes = 0_u64;
        d32_audit_namespace_bytes_add(&mut path_bytes, d32_audit_path_bytes(path)?)?;
        d32_collect_tree_manifest(
            path,
            ".",
            &mut entries,
            &mut total_bytes,
            &mut path_bytes,
            &mut name_bytes,
            0,
        )?;
        let encoded = serde_json::to_vec(&entries)
            .map_err(|_| "D32 Host audit manifest serialization failed".to_string())?;
        Ok(D32TreeManifest {
            exists: true,
            entries,
            digest: format!("{:x}", Sha256::digest(encoded)),
        })
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    #[derive(Debug)]
    struct HostDirectoryFence {
        raw: PathBuf,
        canonical: PathBuf,
        raw_identity: HostFileIdentity,
        canonical_identity: HostFileIdentity,
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl HostDirectoryFence {
        fn capture(path: &Path, description: &str) -> Result<Self, String> {
            if !path.is_absolute() {
                return Err(d32_not_executable(format!(
                    "{description} was not absolute"
                )));
            }
            host_verify_no_reparse_path(path, path).map_err(|error| {
                d32_not_executable(format!(
                    "{description} raw no-reparse fence failed: {error}"
                ))
            })?;
            let raw_identity = host_file_identity(path, true).map_err(|error| {
                d32_not_executable(format!("{description} raw identity fence failed: {error}"))
            })?;
            let canonical = fs::canonicalize(path).map_err(|_| {
                d32_not_executable(format!("{description} could not be canonicalized"))
            })?;
            host_verify_no_reparse_path(&canonical, &canonical).map_err(|error| {
                d32_not_executable(format!(
                    "{description} canonical no-reparse fence failed: {error}"
                ))
            })?;
            let canonical_identity = host_file_identity(&canonical, true).map_err(|error| {
                d32_not_executable(format!(
                    "{description} canonical identity fence failed: {error}"
                ))
            })?;
            if raw_identity != canonical_identity {
                return Err(d32_not_executable(format!(
                    "{description} raw/canonical identity disagreed"
                )));
            }
            Ok(Self {
                raw: path.to_path_buf(),
                canonical,
                raw_identity,
                canonical_identity,
            })
        }

        fn revalidate(&self, description: &str) -> Result<(), String> {
            host_verify_no_reparse_path(&self.raw, &self.raw).map_err(|error| {
                d32_not_executable(format!(
                    "{description} raw no-reparse recheck failed: {error}"
                ))
            })?;
            let raw_identity = host_file_identity(&self.raw, true).map_err(|error| {
                d32_not_executable(format!(
                    "{description} raw identity recheck failed: {error}"
                ))
            })?;
            host_verify_no_reparse_path(&self.canonical, &self.canonical).map_err(|error| {
                d32_not_executable(format!(
                    "{description} canonical no-reparse recheck failed: {error}"
                ))
            })?;
            let canonical_identity =
                host_file_identity(&self.canonical, true).map_err(|error| {
                    d32_not_executable(format!(
                        "{description} canonical identity recheck failed: {error}"
                    ))
                })?;
            if raw_identity != self.raw_identity
                || canonical_identity != self.canonical_identity
                || raw_identity != canonical_identity
            {
                return Err(d32_not_executable(format!(
                    "{description} raw/canonical identity changed"
                )));
            }
            Ok(())
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_real_app_data_root(identifier: &str) -> Result<PathBuf, String> {
        let root = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| d32_not_executable("Windows RoamingAppData root is unavailable"))?;
        if !root.is_absolute() {
            return Err(d32_not_executable(
                "Windows RoamingAppData root was not absolute",
            ));
        }
        let app_root = root.join(identifier);
        let app_fence = HostDirectoryFence::capture(&app_root, "real app-data root")?;
        app_fence.revalidate("real app-data root")?;
        Ok(app_fence.canonical)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_real_storage_roots(default_root: &Path) -> Result<Vec<HostDirectoryFence>, String> {
        let default_fence = HostDirectoryFence::capture(default_root, "default storage root")?;
        let active_root =
            crate::storage::d32_a_resolve_active_root(default_root).map_err(|error| {
                d32_not_executable(format!("active storage root resolution failed: {error:?}"))
            })?;
        default_fence.revalidate("default storage root")?;
        let active_fence = HostDirectoryFence::capture(&active_root, "active storage root")?;
        let mut roots = vec![default_fence];
        if !roots
            .iter()
            .any(|root| root.canonical == active_fence.canonical)
        {
            roots.push(active_fence);
        }
        Ok(roots)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    fn d32_real_resource_roots() -> Result<Vec<HostDirectoryFence>, String> {
        let mut candidates = Vec::new();
        if let Some(root) = std::env::var_os("D32_A_REAL_RESOURCE_DIR") {
            candidates.push(PathBuf::from(root));
        }
        if let Ok(executable) = std::env::current_exe() {
            if let Some(parent) = executable.parent() {
                candidates.push(parent.to_path_buf());
                candidates.push(parent.join("resources"));
            }
        }
        candidates.sort();
        candidates.dedup();
        let mut roots: Vec<HostDirectoryFence> = Vec::new();
        for candidate in candidates {
            let Ok(fence) = HostDirectoryFence::capture(&candidate, "real resource root") else {
                continue;
            };
            if fence.revalidate("real resource root").is_err() {
                continue;
            }
            if !roots.iter().any(|root| root.canonical == fence.canonical) {
                roots.push(fence);
            }
        }
        if roots.is_empty() {
            return Err(d32_not_executable("real Host resource tree is unavailable"));
        }
        Ok(roots)
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    pub(super) struct D32HostIntegrationEnvironment {
        root: PathBuf,
        real_roots: Vec<PathBuf>,
        real_root_fences: Vec<HostDirectoryFence>,
        real_tree_manifests: Option<Vec<(PathBuf, D32TreeManifest)>>,
        previous_environment: Vec<(String, Option<OsString>)>,
        cleaned: bool,
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl D32HostIntegrationEnvironment {
        pub(super) fn prepare(identifier: &str) -> Result<Self, String> {
            let real_app_data_root = d32_real_app_data_root(identifier)?;
            let storage_roots = d32_real_storage_roots(&real_app_data_root)?;
            let resource_roots = d32_real_resource_roots()?;
            let real_root_fences = storage_roots
                .into_iter()
                .chain(resource_roots)
                .collect::<Vec<_>>();
            let real_roots = real_root_fences
                .iter()
                .map(|fence| fence.canonical.clone())
                .collect::<Vec<_>>();
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| d32_not_executable("canary isolation identity unavailable"))?;
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = std::env::temp_dir().join(format!(
                "digital-life-d32a-canary-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&root)
                .map_err(|_| d32_not_executable("canary isolation root could not be created"))?;
            let app_data_root = root.join("app-data");
            let resource_root = root.join("resource");
            let temp_root = root.join("temp");
            let setup = (|| {
                fs::create_dir(&app_data_root).map_err(|_| {
                    d32_not_executable("canary isolated app-data root could not be created")
                })?;
                fs::create_dir(&resource_root).map_err(|_| {
                    d32_not_executable("canary isolated resource root could not be created")
                })?;
                fs::create_dir(&temp_root).map_err(|_| {
                    d32_not_executable("canary isolated temp root could not be created")
                })?;
                crate::storage::d32_a_snapshot_app_data(&real_app_data_root, &app_data_root)
                    .map_err(|error| {
                        d32_not_executable(format!(
                            "canary app-data snapshot failed: {}",
                            error.message
                        ))
                    })?;
                Ok::<_, String>(())
            })();
            if let Err(error) = setup {
                let _ = fs::remove_dir_all(&root);
                return Err(error);
            }

            let environment_values = [
                (
                    "D32_A_CANARY_APP_DATA_ROOT",
                    OsString::from(app_data_root.as_os_str()),
                ),
                (
                    "D32_A_CANARY_RESOURCE_DIR",
                    OsString::from(resource_root.as_os_str()),
                ),
                ("TMP", OsString::from(temp_root.as_os_str())),
                ("TEMP", OsString::from(temp_root.as_os_str())),
            ];
            let mut previous_environment = Vec::with_capacity(environment_values.len());
            for (name, value) in environment_values {
                previous_environment.push((name.to_string(), std::env::var_os(name)));
                std::env::set_var(name, value);
            }
            Ok(Self {
                root,
                real_roots,
                real_root_fences,
                real_tree_manifests: None,
                previous_environment,
                cleaned: false,
            })
        }

        pub(super) fn establish_stable_baseline(&mut self) -> Result<(), String> {
            if self.real_tree_manifests.is_some() {
                return Err("D32_A_HOST_FAILURE: real_host_audit_failed".to_string());
            }
            for fence in &self.real_root_fences {
                fence
                    .revalidate("real Host root")
                    .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())?;
            }
            let manifests = self
                .real_roots
                .iter()
                .map(|root| d32_tree_manifest(root).map(|manifest| (root.clone(), manifest)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())?;
            self.real_tree_manifests = Some(manifests);
            Ok(())
        }

        pub(super) fn verify_real_roots_unchanged(&self) -> Result<(), String> {
            let Some(expected_manifests) = self.real_tree_manifests.as_ref() else {
                return Err("D32_A_HOST_FAILURE: real_host_audit_failed".to_string());
            };
            for fence in &self.real_root_fences {
                fence
                    .revalidate("real Host root")
                    .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())?;
            }
            for (path, expected) in expected_manifests {
                let current = d32_tree_manifest(path)
                    .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())?;
                if &current != expected {
                    return Err("D32_A_HOST_FAILURE: real_host_audit_failed".to_string());
                }
            }
            for fence in &self.real_root_fences {
                fence
                    .revalidate("real Host root")
                    .map_err(|_| "D32_A_HOST_FAILURE: real_host_audit_failed".to_string())?;
            }
            Ok(())
        }

        pub(super) fn cleanup(&mut self) -> Result<(), String> {
            if self.cleaned {
                return Ok(());
            }
            match fs::symlink_metadata(&self.root) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.cleaned = true;
                    Ok(())
                }
                Err(_) => Err("D32_A_HOST_FAILURE: cleanup_failed".to_string()),
                Ok(metadata) => {
                    if host_metadata_is_reparse(&metadata) {
                        return Err("D32_A_HOST_FAILURE: cleanup_unsafe_state".to_string());
                    }
                    host_verify_no_reparse_tree(&self.root)
                        .map_err(|_| "D32_A_HOST_FAILURE: cleanup_unsafe_state".to_string())?;
                    fs::remove_dir_all(&self.root)
                        .map_err(|_| "D32_A_HOST_FAILURE: cleanup_failed".to_string())?;
                    if fs::symlink_metadata(&self.root).is_ok() {
                        return Err("D32_A_HOST_FAILURE: cleanup_unsafe_state".to_string());
                    }
                    self.cleaned = true;
                    Ok(())
                }
            }
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl Drop for D32HostIntegrationEnvironment {
        fn drop(&mut self) {
            for (name, value) in self.previous_environment.iter().rev() {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            if !self.cleaned {
                if let Err(error) = self.cleanup() {
                    eprintln!(
                        "D32_A_HOST_FAILURE: cleanup outcome error_code={}",
                        d32_host_error_code(&error)
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    struct D32ProductionCanaryEnvironment {
        workspace: PathBuf,
        staged_sidecar: Option<PathBuf>,
        cleaned: bool,
    }

    #[cfg(feature = "d32-a-host-canary")]
    const D32_CANARY_GIT_CONFIG_BYTES: &[u8] =
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n";

    #[cfg(feature = "d32-a-host-canary")]
    const D32_CANARY_GIT_HEAD_BYTES: &[u8] = b"ref: refs/heads/main\n";

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_create_new_fixture_directory(
        root: &Path,
        path: &Path,
        description: &str,
    ) -> Result<(), String> {
        fs::create_dir(path)
            .map_err(|_| d32_not_executable(format!("{description} could not be created")))?;
        host_verify_no_reparse_path(root, path).map_err(|error| {
            d32_not_executable(format!("{description} was not app-owned: {error}"))
        })?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| d32_not_executable(format!("{description} metadata was unavailable")))?;
        if !metadata.is_dir() || host_metadata_is_reparse(&metadata) {
            return Err(d32_not_executable(format!(
                "{description} was not a regular non-reparse directory"
            )));
        }
        host_file_identity(path, true).map_err(|error| {
            d32_not_executable(format!("{description} identity was unavailable: {error}"))
        })?;
        Ok(())
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_create_new_fixture_file(
        root: &Path,
        path: &Path,
        bytes: &[u8],
        description: &str,
    ) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| d32_not_executable(format!("{description} could not be created")))?;
        file.write_all(bytes)
            .map_err(|_| d32_not_executable(format!("{description} could not be written")))?;
        file.flush()
            .map_err(|_| d32_not_executable(format!("{description} could not be flushed")))?;
        file.sync_all()
            .map_err(|_| d32_not_executable(format!("{description} could not be synced")))?;
        drop(file);
        host_verify_no_reparse_path(root, path).map_err(|error| {
            d32_not_executable(format!("{description} was not app-owned: {error}"))
        })?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| d32_not_executable(format!("{description} metadata was unavailable")))?;
        if !metadata.is_file() || host_metadata_is_reparse(&metadata) {
            return Err(d32_not_executable(format!(
                "{description} was not a regular non-reparse file"
            )));
        }
        let identity = host_file_identity(path, false).map_err(|error| {
            d32_not_executable(format!("{description} identity was unavailable: {error}"))
        })?;
        if identity.file_size != bytes.len() as u64 {
            return Err(d32_not_executable(format!(
                "{description} size changed during creation"
            )));
        }
        Ok(())
    }

    #[cfg(feature = "d32-a-host-canary")]
    fn d32_create_minimal_git_metadata(workspace: &Path) -> Result<(), String> {
        let git = workspace.join(".git");
        let objects = git.join("objects");
        let refs = git.join("refs");
        let heads = refs.join("heads");
        d32_create_new_fixture_directory(workspace, &git, "canary Git metadata root")?;
        d32_create_new_fixture_directory(workspace, &objects, "canary Git objects directory")?;
        d32_create_new_fixture_directory(workspace, &refs, "canary Git refs directory")?;
        d32_create_new_fixture_directory(workspace, &heads, "canary Git refs/heads directory")?;
        d32_create_new_fixture_file(
            workspace,
            &git.join("HEAD"),
            D32_CANARY_GIT_HEAD_BYTES,
            "canary Git HEAD",
        )?;
        d32_create_new_fixture_file(
            workspace,
            &git.join("config"),
            D32_CANARY_GIT_CONFIG_BYTES,
            "canary Git config",
        )?;
        host_verify_no_reparse_tree(&git).map_err(|error| {
            d32_not_executable(format!("canary Git metadata tree was unsafe: {error}"))
        })?;
        Ok(())
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl D32ProductionCanaryEnvironment {
        fn prepare<R: Runtime>(app: &AppHandle<R>) -> Result<Self, String> {
            let workspace = Self::create_workspace()?;
            let mut environment = Self {
                workspace,
                staged_sidecar: None,
                cleaned: false,
            };
            if let Err(error) = environment.stage_sidecar(app) {
                return Err(error);
            }
            Ok(environment)
        }

        fn create_workspace() -> Result<PathBuf, String> {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random).map_err(|_| {
                d32_not_executable("canary workspace identity could not be generated")
            })?;
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let workspace = std::env::temp_dir().join(format!(
                "digital-life-d32a-host-{}-{suffix}",
                std::process::id()
            ));
            let mut created = false;
            let result = (|| {
                fs::create_dir(&workspace)
                    .map_err(|_| d32_not_executable("canary workspace could not be created"))?;
                created = true;
                fs::create_dir(workspace.join("src")).map_err(|_| {
                    d32_not_executable("canary workspace source root could not be created")
                })?;
                d32_create_minimal_git_metadata(&workspace)?;
                fs::write(
                    workspace.join("Cargo.toml"),
                    b"[package]\nname = \"d32_a_real_canary\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .map_err(|_| d32_not_executable("canary workspace manifest could not be written"))?;
                fs::write(
                    workspace.join("Cargo.lock"),
                    b"# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = \"d32_a_real_canary\"\nversion = \"0.1.0\"\n",
                )
                .map_err(|_| d32_not_executable("canary workspace lockfile could not be written"))?;
                fs::write(
                    workspace.join("src/lib.rs"),
                    b"pub fn d32_a_real_canary() -> u32 { 32 }\n",
                )
                .map_err(|_| d32_not_executable("canary workspace source could not be written"))?;
                fs::write(
                    workspace.join("unrelated.txt"),
                    b"D32-A unrelated fixture must remain unchanged\n",
                )
                .map_err(|_| d32_not_executable("canary unrelated fixture could not be written"))?;
                Ok(workspace.clone())
            })();
            if created && result.is_err() {
                let _ = fs::remove_dir_all(&workspace);
            }
            result
        }

        fn stage_sidecar<R: Runtime>(&mut self, app: &AppHandle<R>) -> Result<(), String> {
            let (candidate, expected_hash) = d32_candidate_release_image()?;
            let resource_dir = sidecar_resource_dir(app).map_err(|error| {
                d32_not_executable(format!("resource directory unavailable: {error}"))
            })?;
            let resource_dir = fs::canonicalize(&resource_dir)
                .map_err(|_| d32_not_executable("resource directory could not be canonicalized"))?;
            host_verify_no_reparse_path(&resource_dir, &resource_dir).map_err(|error| {
                d32_not_executable(format!("resource directory is not app-owned: {error}"))
            })?;
            let destination = resource_dir.join(SIDECAR_RESOURCE_NAME);
            match fs::symlink_metadata(&destination) {
                Ok(metadata) => {
                    if host_metadata_is_reparse(&metadata) || !metadata.is_file() {
                        return Err(d32_not_executable(
                            "installed Vita sidecar resource is not a regular file",
                        ));
                    }
                    let installed = fs::canonicalize(&destination).map_err(|_| {
                        d32_not_executable(
                            "installed Vita sidecar resource could not be canonicalized",
                        )
                    })?;
                    if installed.parent() != Some(resource_dir.as_path()) {
                        return Err(d32_not_executable(
                            "installed Vita sidecar resource escaped its app-owned directory",
                        ));
                    }
                    let installed_hash = host_hash_file(&installed, D32_IMAGE_HASH_MAX_BYTES)
                        .map_err(|error| {
                            d32_not_executable(format!("installed sidecar hash failed: {error}"))
                        })?;
                    if installed_hash != expected_hash {
                        return Err(d32_not_executable(
                            "installed Vita sidecar does not match the candidate image",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut input = File::open(&candidate).map_err(|_| {
                        d32_not_executable("candidate Vita release image could not be opened")
                    })?;
                    let mut output = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination)
                        .map_err(|_| {
                            d32_not_executable("app-owned sidecar resource could not be staged")
                        })?;
                    // Own the destination before any copy/identity/hash
                    // validation can fail so the environment Drop removes a
                    // partial or rejected staged image as well.
                    self.staged_sidecar = Some(destination.clone());
                    std::io::copy(&mut input, &mut output).map_err(|_| {
                        d32_not_executable("app-owned sidecar resource copy failed")
                    })?;
                    output.flush().map_err(|_| {
                        d32_not_executable("app-owned sidecar resource flush failed")
                    })?;
                    host_verify_no_reparse_path(&resource_dir, &destination).map_err(|error| {
                        d32_not_executable(format!(
                            "staged sidecar resource was not app-owned: {error}"
                        ))
                    })?;
                    let staged_hash = host_hash_file(&destination, D32_IMAGE_HASH_MAX_BYTES)
                        .map_err(|error| {
                            d32_not_executable(format!("staged sidecar hash failed: {error}"))
                        })?;
                    if staged_hash != expected_hash {
                        return Err(d32_not_executable(
                            "staged Vita sidecar does not match the candidate image",
                        ));
                    }
                }
                Err(_) => {
                    return Err(d32_not_executable(
                        "installed Vita sidecar resource metadata was unavailable",
                    ));
                }
            }
            Ok(())
        }

        fn cleanup(&mut self) -> D32CleanupOutcome {
            if self.cleaned {
                return D32CleanupOutcome {
                    attempted: false,
                    validated: true,
                    removed: true,
                    unsafe_left: false,
                    error: None,
                };
            }
            let mut outcome = D32CleanupOutcome {
                attempted: true,
                validated: false,
                removed: false,
                unsafe_left: false,
                error: None,
            };
            let mut errors = Vec::new();
            if let Some(path) = self.staged_sidecar.as_ref() {
                match fs::symlink_metadata(path) {
                    Ok(metadata) => {
                        if host_metadata_is_reparse(&metadata) || !metadata.is_file() {
                            outcome.unsafe_left = true;
                            errors.push(format!(
                                "staged sidecar was not a regular non-reparse file: {}",
                                path.display()
                            ));
                        } else if let Err(error) = fs::remove_file(path) {
                            errors.push(format!(
                                "staged sidecar could not be removed: {}: {error}",
                                path.display()
                            ));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => errors.push(format!(
                        "staged sidecar metadata unavailable: {}: {error}",
                        path.display()
                    )),
                }
                if fs::symlink_metadata(path).is_ok() {
                    outcome.unsafe_left = true;
                }
            }
            match fs::symlink_metadata(&self.workspace) {
                Ok(metadata) => {
                    if host_metadata_is_reparse(&metadata) {
                        outcome.unsafe_left = true;
                        errors.push("canary workspace became a reparse point".to_string());
                    } else if let Err(error) = host_verify_no_reparse_tree(&self.workspace) {
                        outcome.unsafe_left = true;
                        errors.push(error);
                    } else if let Err(error) = fs::remove_dir_all(&self.workspace) {
                        errors.push(format!("canary workspace could not be removed: {error}"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    errors.push(format!("canary workspace metadata unavailable: {error}"))
                }
            }
            if fs::symlink_metadata(&self.workspace).is_ok() {
                outcome.unsafe_left = true;
            }
            outcome.validated = errors.is_empty() && !outcome.unsafe_left;
            outcome.removed = outcome.validated;
            if !errors.is_empty() {
                outcome.error = Some(if outcome.unsafe_left {
                    "cleanup_unsafe_state".to_string()
                } else {
                    "cleanup_failed".to_string()
                });
            } else if outcome.unsafe_left {
                outcome.error = Some("cleanup_unsafe_state".to_string());
            }
            if outcome.validated {
                self.cleaned = true;
                self.staged_sidecar = None;
            }
            outcome
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    impl Drop for D32ProductionCanaryEnvironment {
        fn drop(&mut self) {
            if !self.cleaned {
                let outcome = self.cleanup();
                if outcome.error.is_some() || outcome.unsafe_left {
                    eprintln!(
                        "D32_A_HOST_FAILURE: canary cleanup outcome: {}",
                        d32_cleanup_summary(&outcome)
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "d32-a-host-canary", not(test)))]
    pub(super) fn run_d32_a_host_integration_impl(
        app: &mut tauri::App<tauri::Wry>,
        mode: &str,
    ) -> Result<D32HostCanaryReport, String> {
        let mode = D32HostCanaryMode::parse(mode)?;
        let app_handle = app.handle().clone();
        let storage = app_handle.state::<StorageService>();
        let secrets = app_handle.state::<WindowsCredentialSecretStore>();
        let provider = active_chat_provider_configuration(storage.inner(), secrets.inner())
            .map_err(|error| {
                d32_not_executable(format!(
                    "active Chat provider metadata read failed: {error}"
                ))
            })?;
        require_production_provider(provider)?;
        let life = storage
            .get_current_life()
            .map_err(|error| {
                d32_not_executable(format!("current Life read failed: {}", error.message))
            })?
            .ok_or_else(|| d32_not_executable("current Life is unavailable"))?;
        d32_require_cargo_root(storage.inner(), &life.id)?;

        let mut environment = D32ProductionCanaryEnvironment::prepare(&app_handle)?;
        let app_data_root = sidecar_app_data_root(&app_handle)?;
        let coordinator = app_handle.state::<VitaSidecarCoordinator>();
        let control = D32HostCanaryControl::new(mode);
        coordinator.configure_d32_host_canary(Arc::clone(&control))?;
        control.trace.stage_started(D32HostCanaryStage::Layout);
        control.trace.stage_passed(D32HostCanaryStage::Layout);
        let cancel_worker = if mode == D32HostCanaryMode::CancelBeforeRevalidation {
            let worker_control = Arc::clone(&control);
            let worker_app = app_handle.clone();
            let barrier = control.cancel_barrier();
            Some(
                thread::Builder::new()
                    .name("d32-a-cancel-coordinator-worker".to_string())
                    .spawn(move || {
                        worker_control.wait_for_cancel_signal();
                        let result = {
                            let coordinator = worker_app.state::<VitaSidecarCoordinator>();
                            coordinator.cancel_turn().map(|_| ())
                        };
                        barrier.wait();
                        result
                    })
                    .map_err(|_| d32_not_executable("cancel coordinator worker unavailable"))?,
            )
        } else {
            None
        };
        let mut app_data_root_retained = None;
        let run_result = (|| {
            coordinator.start(
                &app_handle,
                VitaSidecarStartRequest {
                    life_id: life.id.clone(),
                    task_id: "d32-a-real-production-canary".to_string(),
                    workspace_path: environment.workspace.to_string_lossy().into_owned(),
                },
            )?;
            let retained = coordinator
                .d32_app_data_root_retained()
                .map_err(d32_not_executable)?;
            retained
                .revalidate("D32 native evidence app-data root before canary")
                .map_err(d32_not_executable)?;
            control.trace.stage_started(D32HostCanaryStage::Evidence);
            if let Err(error) = d32_prepare_native_evidence(&retained) {
                control.trace.stage_failed(
                    D32HostCanaryStage::Evidence,
                    D32StageFailureCode::OperationFailed,
                );
                return Err(error);
            }
            app_data_root_retained = Some(retained);
            coordinator.start_turn(VitaTurnStartRequest {
                prompt: D32_CANARY_CARGO_PROMPT.to_string(),
            })?;

            let deadline = std::time::Instant::now() + Duration::from_secs(360);
            let mut confirmation_seen = false;
            let mut action_taken = false;
            let terminal = loop {
                let status = coordinator.status()?;
                if status.pending.is_some() {
                    confirmation_seen = true;
                    if !action_taken {
                        action_taken = true;
                        if let Some(pending) = status.pending.as_ref() {
                            coordinator.confirm(pending.pending_id.clone())?;
                        }
                    }
                }
                if matches!(
                    status.turn_phase,
                    Some(
                        protocol::TurnPhase::Completed
                            | protocol::TurnPhase::Failed
                            | protocol::TurnPhase::Cancelled
                            | protocol::TurnPhase::TimedOut
                    )
                ) && status.active_turn_id.is_none()
                {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    return Err("D32-A production real canary timed out".to_string());
                }
                thread::sleep(Duration::from_millis(100));
            };
            if !confirmation_seen {
                let diagnostic = d32_canary_no_confirmation_diagnostic(
                    terminal.assistant_text.as_deref(),
                    terminal.turn_phase,
                    terminal.turn_error.as_deref(),
                );
                let trace = control.trace.snapshot();
                let native_diagnostic = d32_native_diagnostic_summary(&trace);
                let stage_telemetry = d32_stage_telemetry_summary(&trace);
                return Err(d32_not_executable(format!(
                    "{diagnostic}; d32_stage_telemetry={stage_telemetry}; d32_native_diagnostic={native_diagnostic}"
                )));
            }
            if mode.expects_deny() {
                if !matches!(
                    terminal.turn_phase,
                    Some(
                        protocol::TurnPhase::Completed
                            | protocol::TurnPhase::Failed
                            | protocol::TurnPhase::Cancelled
                            | protocol::TurnPhase::TimedOut
                    )
                ) {
                    return Err(format!(
                        "D32-A negative lane unexpectedly completed: {:?}",
                        terminal.turn_phase
                    ));
                }
            } else {
                if terminal.turn_phase != Some(protocol::TurnPhase::Completed)
                    || terminal.turn_error.is_some()
                    || terminal.assistant_text.is_none()
                {
                    return Err(format!(
                        "D32-A production provider/tool turn did not complete: {:?}",
                        terminal.turn_error
                    ));
                }
            }
            Ok(terminal)
        })();
        let stop_result = coordinator.stop().map(|_| ());
        let worker_result = if let Some(worker) = cancel_worker {
            control.signal_cancel_worker();
            if !control.trace.snapshot().pre_native_fence_seen {
                control.cancel_barrier().wait();
            }
            worker
                .join()
                .map_err(|_| "D32_A_HOST_FAILURE: cancel coordinator worker panicked".to_string())?
        } else {
            Ok(())
        };
        // The revalidation reader owns the coordinator's authority view.  A
        // revoke must be restored through that same view so the canary cannot
        // accidentally prove a different StorageService path than the one
        // that performed the canonical transition.
        let restore_result = d32_restore_revoke(
            coordinator.authority_storage.as_ref(),
            &coordinator.registry,
            &life.id,
            &control,
        );
        let result = run_result
            .and_then(|terminal| stop_result.map(|_| terminal))
            .and_then(|terminal| worker_result.map(|_| terminal))
            .and_then(|terminal| restore_result.map(|_| terminal));
        let terminal = match result {
            Ok(terminal) => terminal,
            Err(error) => {
                control.trace.stage_started(D32HostCanaryStage::Cleanup);
                let cleanup = environment.cleanup();
                if cleanup.validated && cleanup.removed && cleanup.error.is_none() {
                    control.trace.stage_passed(D32HostCanaryStage::Cleanup);
                } else {
                    control.trace.stage_failed(
                        D32HostCanaryStage::Cleanup,
                        D32StageFailureCode::OperationFailed,
                    );
                }
                return Err(d32_failure_context(&control, &error, Some(&cleanup), false));
            }
        };
        let report_result = (|| -> Result<D32HostCanaryReport, String> {
            if environment.workspace.join("target").exists() {
                return Err(
                    "D32_A_HOST_FAILURE: production cargo lane wrote into the governed workspace"
                        .to_string(),
                );
            }
            let unrelated = environment.workspace.join("unrelated.txt");
            if !fs::read(&unrelated)
                .map(|bytes| bytes == b"D32-A unrelated fixture must remain unchanged\n")
                .unwrap_or(false)
            {
                return Err(
                    "D32_A_HOST_FAILURE: production cargo lane mutated an unrelated fixture"
                        .to_string(),
                );
            }
            let runs_root = app_data_root
                .join(D32_EXECUTION_ROOT_NAME)
                .join(D32_RUNS_DIR_NAME);
            if runs_root.exists()
                && fs::read_dir(&runs_root)
                    .map_err(|_| {
                        "D32_A_HOST_FAILURE: production run root enumeration failed".to_string()
                    })?
                    .next()
                    .is_some()
            {
                return Err(
                    "D32_A_HOST_FAILURE: production cargo run root was not cleaned".to_string(),
                );
            }
            let trace_for_validation = control.trace.snapshot();
            d32_validate_trace(
                mode,
                &trace_for_validation,
                terminal.turn_phase,
                terminal.turn_error.as_deref(),
            )?;
            let app_data_root_retained = app_data_root_retained
                .as_ref()
                .ok_or_else(|| d32_not_executable("D32 app-data authority was not retained"))?;
            let native_evidence =
                match d32_read_native_evidence(app_data_root_retained, &trace_for_validation, mode)
                {
                    Ok(evidence) => {
                        control.trace.stage_passed(D32HostCanaryStage::Evidence);
                        evidence
                    }
                    Err(error) => {
                        control.trace.stage_failed(
                            D32HostCanaryStage::Evidence,
                            D32StageFailureCode::OperationFailed,
                        );
                        return Err(error);
                    }
                };
            let trace = control.trace.snapshot();
            let native_diagnostic = trace.native_diagnostic.clone();
            Ok(D32HostCanaryReport {
                mode: mode.as_str().to_string(),
                status: if mode.expects_deny() {
                    "DENIED".to_string()
                } else {
                    "EXECUTED".to_string()
                },
                trace,
                native_evidence,
                terminal_phase: terminal.turn_phase,
                turn_error: terminal.turn_error,
                native_diagnostic,
                cleanup: D32CleanupOutcome {
                    attempted: false,
                    validated: false,
                    removed: false,
                    unsafe_left: false,
                    error: None,
                },
            })
        })();
        let clear_result = coordinator.clear_d32_host_canary();
        control.trace.stage_started(D32HostCanaryStage::Cleanup);
        let cleanup = environment.cleanup();
        if cleanup.validated && cleanup.removed && cleanup.error.is_none() {
            control.trace.stage_passed(D32HostCanaryStage::Cleanup);
        } else {
            control.trace.stage_failed(
                D32HostCanaryStage::Cleanup,
                D32StageFailureCode::OperationFailed,
            );
        }
        match (report_result, clear_result, cleanup.error.clone()) {
            (Ok(mut report), Ok(()), None) if cleanup.validated && cleanup.removed => {
                report.trace = control.trace.snapshot();
                report.cleanup = cleanup;
                Ok(report)
            }
            (Ok(_), Ok(()), _) => Err(d32_failure_context(
                &control,
                "cleanup did not validate",
                Some(&cleanup),
                false,
            )),
            (Err(error), Ok(()), _) => {
                Err(d32_failure_context(&control, &error, Some(&cleanup), false))
            }
            (result, clear, _) => {
                let clear_failed = clear.is_err();
                let error = if result.is_err() {
                    "report failed"
                } else if clear_failed {
                    "clear failed"
                } else {
                    "host finalization failed"
                };
                Err(d32_failure_context(
                    &control,
                    error,
                    Some(&cleanup),
                    clear_failed,
                ))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::capability::activation::apply_transition_for_test;
        use crate::capability::authorization::{
            CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationRepository,
            LifeCapabilityAuthorizationCreateRequest, LifeCapabilityAuthorizationUpdateRequest,
        };
        use crate::capability::descriptor::{
            ApprovalFloor, CapabilityDescriptor, RiskClass, ScopeRequirement,
        };
        use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};
        use std::process::Command;
        use std::sync::{mpsc, Arc, Barrier};
        use std::thread;

        #[test]
        fn d32_minimal_git_fixture_is_fixed_non_reparse_and_create_new() {
            let fixture = tempfile::tempdir().expect("D32 minimal Git fixture");
            let workspace = fixture.path().join("workspace");
            fs::create_dir(&workspace).expect("D32 minimal Git workspace");

            d32_create_minimal_git_metadata(&workspace)
                .expect("D32 minimal Git metadata should be created");
            host_verify_no_reparse_tree(&workspace).expect("D32 minimal Git tree is safe");

            let git = D32RetainedDirectory::open(&workspace.join(".git"))
                .expect("D32 minimal Git metadata root should be retained");
            assert_eq!(
                git.read_file(OsStr::new("HEAD"), 1024)
                    .expect("D32 minimal Git HEAD should be readable"),
                D32_CANARY_GIT_HEAD_BYTES
            );
            assert_eq!(
                git.read_file(OsStr::new("config"), 1024)
                    .expect("D32 minimal Git config should be readable"),
                D32_CANARY_GIT_CONFIG_BYTES
            );

            let mut git_children = git
                .enumerate_children()
                .expect("D32 minimal Git metadata should enumerate");
            git_children.sort();
            assert_eq!(
                git_children,
                vec![
                    OsString::from("HEAD"),
                    OsString::from("config"),
                    OsString::from("objects"),
                    OsString::from("refs"),
                ]
            );
            let objects = git
                .open_existing_child(OsStr::new("objects"))
                .expect("D32 minimal Git objects directory");
            assert!(objects
                .enumerate_children()
                .expect("D32 minimal Git objects should enumerate")
                .is_empty());
            let refs = git
                .open_existing_child(OsStr::new("refs"))
                .expect("D32 minimal Git refs directory");
            assert_eq!(
                refs.enumerate_children()
                    .expect("D32 minimal Git refs should enumerate"),
                vec![OsString::from("heads")]
            );
            let heads = refs
                .open_existing_child(OsStr::new("heads"))
                .expect("D32 minimal Git refs/heads directory");
            assert!(heads
                .enumerate_children()
                .expect("D32 minimal Git refs/heads should enumerate")
                .is_empty());

            assert!(
                d32_create_minimal_git_metadata(&workspace).is_err(),
                "recreating fixed metadata must fail closed"
            );
        }

        #[test]
        fn d32_canary_prompt_and_no_confirmation_diagnostic_are_bounded_and_redacted() {
            assert_eq!(
                D32_CANARY_CARGO_PROMPT
                    .matches("vita_workspace_cargo_check")
                    .count(),
                1
            );
            assert!(D32_CANARY_CARGO_PROMPT.starts_with("Do not answer with text."));
            assert!(D32_CANARY_CARGO_PROMPT.contains(
                "first and only action must be call vita_workspace_cargo_check exactly once with {} now"
            ));
            assert!(D32_CANARY_CARGO_PROMPT.contains("wait for its result, then summarize"));

            let long_safe_line = "safe cargo result ".repeat(64);
            let assistant_text = format!(
                "safe result: cargo check completed\nAuthorization: Bearer should-not-appear\nbody={{\"secret\":\"should-not-appear\"}}\n{long_safe_line}"
            );
            let diagnostic = d32_canary_no_confirmation_diagnostic(
                Some(&assistant_text),
                Some(protocol::TurnPhase::Completed),
                Some("TURN_FAILED"),
            );
            assert!(diagnostic.contains("terminal_phase=Completed"));
            assert!(diagnostic.contains("turn_error_code=TURN_FAILED"));
            assert!(diagnostic.contains("assistant_text_len_chars="));
            assert!(diagnostic.contains("safe result: cargo check completed"));
            assert!(!diagnostic.contains("should-not-appear"));
            assert!(
                d32_canary_sanitize_assistant_text(&assistant_text)
                    .chars()
                    .count()
                    <= D32_CANARY_DIAGNOSTIC_MAX_TEXT_CHARS
            );
            assert_eq!(
                d32_canary_sanitize_error_code(Some("provider_token=should-not-appear")),
                "<redacted>"
            );
        }

        #[cfg(feature = "d32-a-host-canary")]
        #[test]
        fn d32_native_safe_diagnostic_accepts_only_static_fields() {
            let message = "provider gateway protocol error: D32 native Responses rejected phase=http_status round=initial_request attempts=1 http_status=429 error_code=http_status output_kind=unknown content_type_is_json=true gateway_requests=1 provider_results=0 sse_created=1 sse_failed=1 sse_completed=0";
            let diagnostic =
                parse_d32_native_safe_diagnostic(message).expect("canonical D32 native diagnostic");
            assert_eq!(diagnostic.phase, "http_status");
            assert_eq!(diagnostic.round, "initial_request");
            assert_eq!(diagnostic.attempts, Some(1));
            assert_eq!(diagnostic.http_status, Some(429));
            assert_eq!(diagnostic.error_code, "http_status");
            assert_eq!(diagnostic.gateway_requests, 1);
            assert_eq!(diagnostic.sse_failed, 1);

            let hostile = format!(
                "{message} provider-message Authorization: Bearer provider-token https://evil.example"
            );
            assert!(parse_d32_native_safe_diagnostic(&hostile).is_none());
            assert!(
                parse_d32_native_safe_diagnostic(&format!("{message} gateway_requests=2"))
                    .is_none()
            );
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_stage_failure_fixture_matrix_is_bounded_and_static() {
            let trace = D32HostCanaryTrace::default();
            for stage in D32HostCanaryStage::ALL {
                trace.stage_started(stage);
                trace.stage_failed(stage, D32StageFailureCode::Fixture);
            }
            trace.bridge_sent();
            trace.bridge_pending();
            trace.bridge_pending();
            trace.bridge_replied(D32BridgeDecision::Confirm);
            let snapshot = trace.snapshot();
            let json =
                serde_json::to_string(&snapshot.stage_telemetry).expect("D32 stage telemetry JSON");
            for field in [
                "layout",
                "catalog",
                "sandbox",
                "actionPrepare",
                "scopeAuthority",
                "populate",
                "confirmationBridge",
                "grant",
                "revalidate",
                "evidence",
                "cleanup",
            ] {
                assert_eq!(json.matches(&format!("\"{field}\"")).count(), 1);
            }
            assert_eq!(snapshot.stage_telemetry.bridge_sent, 1);
            assert_eq!(snapshot.stage_telemetry.bridge_pending, 1);
            assert!(!snapshot.stage_telemetry.bridge_pending_active);
            assert_eq!(snapshot.stage_telemetry.bridge_state, "replied");
            assert!(json.contains("\"lastFailureCode\":\"fixture\""));
            assert!(!json.to_ascii_lowercase().contains("provider"));
            assert!(!json.to_ascii_lowercase().contains("token"));
            assert!(!json.to_ascii_lowercase().contains("credential"));
            assert!(!json.to_ascii_lowercase().contains("authorization"));
            assert!(!json.to_ascii_lowercase().contains("body"));
            assert!(!json.to_ascii_lowercase().contains("environment"));
            assert!(!json.contains("http://"));
            assert!(!json.contains("https://"));
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_full_report_json_has_unique_safe_stage_fields() {
            let trace = D32HostCanaryTrace::default();
            trace.stage_started(D32HostCanaryStage::Layout);
            trace.stage_passed(D32HostCanaryStage::Layout);
            trace.stage_started(D32HostCanaryStage::ConfirmationBridge);
            trace.bridge_sent();
            trace.bridge_replied(D32BridgeDecision::Confirm);
            let report = D32HostCanaryReport {
                mode: "positive".to_string(),
                status: "EXECUTED".to_string(),
                trace: trace.snapshot(),
                native_evidence: D32NativeEvidenceReport {
                    record: serde_json::json!({}),
                    sha256: "sha256-placeholder".to_string(),
                    identity: "identity-placeholder".to_string(),
                    bytes: 0,
                },
                terminal_phase: None,
                turn_error: Some("TURN_FAILED".to_string()),
                native_diagnostic: Some(D32NativeSafeDiagnostic {
                    phase: "http_status".to_string(),
                    round: "initial_request".to_string(),
                    attempts: Some(1),
                    http_status: Some(429),
                    error_code: "http_status".to_string(),
                    output_kind: "unknown".to_string(),
                    content_type_is_json: true,
                    gateway_requests: 1,
                    provider_results: 1,
                    sse_created: 1,
                    sse_failed: 1,
                    sse_completed: 0,
                }),
                cleanup: D32CleanupOutcome {
                    attempted: true,
                    validated: true,
                    removed: true,
                    unsafe_left: false,
                    error: None,
                },
            };
            let json = serde_json::to_string(&report).expect("D32 report JSON");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("D32 report must remain valid JSON");
            assert_eq!(parsed.as_object().map(serde_json::Map::len), Some(8));
            for field in [
                "mode",
                "status",
                "trace",
                "nativeEvidence",
                "terminalPhase",
                "turnError",
            ] {
                assert_eq!(json.matches(&format!("\"{field}\"")).count(), 1);
            }
            assert_eq!(json.matches("\"nativeDiagnostic\"").count(), 2);
            assert_eq!(json.matches("\"cleanup\":{\"attempted\"").count(), 1);
            let telemetry_json =
                serde_json::to_string(&report.trace.stage_telemetry).expect("stage telemetry JSON");
            for field in [
                "layout",
                "catalog",
                "sandbox",
                "actionPrepare",
                "scopeAuthority",
                "populate",
                "confirmationBridge",
                "grant",
                "revalidate",
                "evidence",
                "cleanup",
            ] {
                assert_eq!(telemetry_json.matches(&format!("\"{field}\"")).count(), 1);
            }
            for marker in [
                "provider secret",
                "token",
                "credential",
                "authorization",
                "body",
                "environment",
                "path",
                "http://",
                "https://",
            ] {
                assert!(
                    !json.to_ascii_lowercase().contains(marker),
                    "report leaked forbidden marker {marker:?}"
                );
            }
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_no_confirmation_diagnostic_does_not_infer_vita_stages() {
            let trace = D32HostCanaryTrace::default();
            let summary = d32_stage_telemetry_summary(&trace.snapshot());
            for stage in ["actionPrepare", "populate", "confirmationBridge"] {
                assert!(summary.contains(&format!("\"{stage}\":{{\"started\":0")));
                assert!(!summary.contains("not_observed"));
            }
            assert!(summary.contains("\"bridgeState\":\"idle\""));
            for marker in [
                "provider",
                "token",
                "credential",
                "authorization",
                "body",
                "environment",
                "http://",
                "https://",
            ] {
                assert!(!summary.to_ascii_lowercase().contains(marker));
            }
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_vita_stage_failure_is_mapped_only_from_safe_turn_failed_message() {
            let message = "D32 Vita stage failure stage=populate code=operation_failed bridge_sent=1 bridge_pending=1 bridge_replied=1 bridge_pending_active=false bridge_decision=confirm bridge_confirmed=1 bridge_denied=0 bridge_cancelled=0 bridge_timed_out=0 bridge_failed=0";
            let diagnostic =
                parse_d32_vita_safe_stage_diagnostic(message).expect("safe Vita stage diagnostic");
            let trace = D32HostCanaryTrace::default();
            trace.update(|snapshot| snapshot.stage_telemetry.mark_vita_failure(&diagnostic));
            let snapshot = trace.snapshot();
            assert_eq!(snapshot.stage_telemetry.populate.failed, 1);
            assert_eq!(
                snapshot
                    .stage_telemetry
                    .populate
                    .last_failure_code
                    .as_deref(),
                Some("operation_failed")
            );
            assert_eq!(snapshot.stage_telemetry.bridge_confirmed, 1);
            assert_eq!(snapshot.stage_telemetry.bridge_decision, "confirm");
            assert_eq!(snapshot.stage_telemetry.layout.started, 0);
            assert_eq!(snapshot.stage_telemetry.catalog.started, 0);
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_vita_stage_parser_rejects_duplicate_or_provider_controlled_fields() {
            let canonical = "D32 Vita stage failure stage=cleanup code=operation_failed bridge_sent=0 bridge_pending=0 bridge_replied=0 bridge_pending_active=false bridge_decision=none bridge_confirmed=0 bridge_denied=0 bridge_cancelled=0 bridge_timed_out=0 bridge_failed=0";
            assert!(parse_d32_vita_safe_stage_diagnostic(canonical).is_some());
            assert!(
                parse_d32_vita_safe_stage_diagnostic(&format!("{canonical} stage=grant")).is_none()
            );
            assert!(parse_d32_vita_safe_stage_diagnostic(&format!(
                "{canonical} provider_message=secret"
            ))
            .is_none());
            assert!(parse_d32_vita_safe_stage_diagnostic(
                &canonical.replace("bridge_failed=0", "bridge_failed=17")
            )
            .is_none());
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_vita_stage_parser_preserves_primary_cleanup_and_success_trace() {
            let stage_trace = "layout:1/1/0,catalog:1/0/1,sandbox:1/1/0,action_prepare:1/1/0,scope_authority:1/1/0,populate:1/1/0,confirmation_bridge:1/1/0,grant:1/1/0,revalidate:1/1/0,evidence:1/1/0,cleanup:1/0/1";
            let message = format!(
                "D32 Vita stage failure stage=cleanup code=operation_failed primary_stage=catalog primary_code=operation_failed secondary_stage=cleanup secondary_code=operation_failed stage_trace={stage_trace} bridge_sent=1 bridge_pending=1 bridge_replied=1 bridge_pending_active=false bridge_decision=confirm bridge_confirmed=1 bridge_denied=0 bridge_cancelled=0 bridge_timed_out=0 bridge_failed=0"
            );
            let diagnostic =
                parse_d32_vita_safe_stage_diagnostic(&message).expect("combined Vita failure");
            let trace = D32HostCanaryTrace::default();
            trace.update(|snapshot| snapshot.stage_telemetry.mark_vita_failure(&diagnostic));
            let snapshot = trace.snapshot();
            assert_eq!(snapshot.stage_telemetry.catalog.failed, 1);
            assert_eq!(
                snapshot
                    .stage_telemetry
                    .catalog
                    .last_failure_code
                    .as_deref(),
                Some("operation_failed")
            );
            assert_eq!(snapshot.stage_telemetry.cleanup.failed, 1);
            assert_eq!(snapshot.stage_telemetry.layout.started, 1);
            assert_eq!(snapshot.stage_telemetry.layout.passed, 1);
            assert_eq!(snapshot.stage_telemetry.bridge_confirmed, 1);
            assert!(parse_d32_vita_safe_stage_diagnostic(
                &message.replace("catalog:1/0/1", "catalog:1/0/1,catalog:1/0/1")
            )
            .is_none());
        }

        #[cfg(all(windows, feature = "d32-a-host-canary"))]
        #[test]
        fn d32_failure_context_redacts_cleanup_and_transport_details() {
            let control = D32HostCanaryControl::new(D32HostCanaryMode::Positive);
            let cleanup = D32CleanupOutcome {
                attempted: true,
                validated: false,
                removed: false,
                unsafe_left: true,
                error: Some("C:\\Users\\secret\\workspace\\provider-message=token".to_string()),
            };
            let context = d32_failure_context(
                &control,
                "provider body Authorization: Bearer token at C:\\secret",
                Some(&cleanup),
                true,
            );
            assert!(context.contains("error_code=turn"));
            assert!(context.contains("clear_failed=true"));
            assert!(context.contains("error_present=true"));
            for marker in [
                "Users",
                "secret",
                "provider-message",
                "Authorization",
                "Bearer",
                "token",
                "C:\\",
            ] {
                assert!(
                    !context.contains(marker),
                    "failure context leaked {marker:?}"
                );
            }
        }

        #[test]
        fn d32_precontrol_error_codes_never_echo_raw_paths_or_credentials() {
            let error = d32_not_executable(
                "cleanup failed for C:\\Users\\secret\\workspace; credential token=secret-value",
            );
            assert_eq!(error, "D32_A_NOT_EXECUTABLE: cleanup_failed");
            assert!(!error.contains("Users"));
            assert!(!error.contains("secret"));
            assert!(!error.contains("token"));
        }

        #[test]
        fn d32_stages_directory_indexes_before_full_identity_capture() {
            let fixture = tempfile::tempdir().expect("D32 namespace staging fixture");
            let root = fixture.path().join("runtime");
            fs::create_dir(&root).expect("D32 namespace staging root");
            fs::create_dir(root.join("bin")).expect("D32 namespace staging bin");
            fs::write(root.join("bin/cargo.exe"), b"cargo").expect("D32 namespace staging cargo");
            fs::write(root.join("runtime.dll"), b"runtime").expect("D32 namespace staging runtime");

            let mut entries = 0usize;
            let mut bytes = 0u64;
            d32_stage_directory_tree_before_capture(&root, 0, &mut entries, &mut bytes)
                .expect("D32 namespace staging must complete before capture");
            assert_eq!(entries, 3);
            assert_eq!(bytes, b"cargo".len() as u64 + b"runtime".len() as u64);

            let retained = D32RetainedDirectory::open(&root).expect("D32 retained fixture root");
            let identity = retained.identity();
            retained
                .enumerate_children()
                .expect("D32 retained fixture enumeration");
            assert_eq!(retained.identity(), identity);
            assert_eq!(identity, retained.identity());

            let retained_file = retained
                .open_existing_file(OsStr::new("runtime.dll"))
                .expect("D32 retained fixture file");
            let file_identity = retained_file.identity();
            fs::write(root.join("runtime.dll"), b"tampered").expect("D32 retained fixture tamper");
            let tampered_identity =
                host_file_identity(&root.join("runtime.dll"), false).expect("D32 tampered file");
            assert_ne!(tampered_identity, file_identity);
            assert!(retained_file
                .revalidate("D32 retained fixture tamper")
                .is_err());
            drop(retained_file);

            let replacement = fixture.path().join("replacement");
            fs::rename(&root, &replacement).expect("D32 namespace replacement rename");
            fs::create_dir(&root).expect("D32 namespace replacement root");
            assert!(retained.revalidate("D32 namespace replacement").is_err());
            drop(retained);
            fs::remove_dir_all(replacement).expect("D32 namespace replacement cleanup");
        }

        #[test]
        fn d32_mutable_mirror_seals_after_writes_and_denies_tamper_or_replacement() {
            let fixture = tempfile::tempdir().expect("D32 mutable mirror fixture");
            let source = fixture.path().join("source");
            let destination = fixture.path().join("destination");
            let source_bin = source.join("bin");
            fs::create_dir_all(&source_bin).expect("D32 mutable mirror source bin");
            fs::create_dir(&destination).expect("D32 mutable mirror destination");
            fs::write(source_bin.join("cargo.exe"), b"cargo").expect("D32 mutable mirror cargo");
            fs::write(source_bin.join("rustc.exe"), b"rustc").expect("D32 mutable mirror rustc");

            let source_retained =
                D32RetainedDirectory::open(&source).expect("D32 mutable mirror source retained");
            let destination_retained = D32RetainedDirectory::open(&destination)
                .expect("D32 mutable mirror destination retained");
            let staging = destination_retained
                .open_or_create_mutable_child(OsStr::new("staging"))
                .expect("D32 mutable mirror staging child");
            let mut files = 0usize;
            let mut bytes = 0u64;
            let sealed =
                host_copy_toolchain_tree(&source_retained, &staging, &mut files, &mut bytes, 0)
                    .expect("D32 mutable mirror seal");
            drop(staging);
            assert_eq!(files, 2);
            assert_eq!(bytes, (b"cargo".len() + b"rustc".len()) as u64);

            let sealed_bin = sealed
                .open_existing_child(OsStr::new("bin"))
                .expect("D32 sealed mirror bin");
            let sealed_bin_identity = sealed_bin.identity();
            sealed_bin
                .enumerate_children()
                .expect("D32 sealed mirror enumeration");
            assert_eq!(sealed_bin.identity(), sealed_bin_identity);
            let expected_manifest =
                host_toolchain_manifest_hash_retained(&sealed).expect("D32 sealed mirror manifest");

            fs::write(sealed.path().join("bin/cargo.exe"), b"cargo-tampered")
                .expect("D32 sealed mirror tamper");
            let tampered_manifest = host_toolchain_manifest_hash_retained(&sealed)
                .expect("D32 sealed mirror tampered manifest");
            assert_ne!(
                tampered_manifest, expected_manifest,
                "sealed mirror tamper must fail the expected manifest comparison"
            );
            drop(sealed_bin);

            let sealed_path = sealed.path().to_path_buf();
            let replacement = fixture.path().join("replacement");
            fs::rename(&sealed_path, &replacement).expect("D32 sealed mirror replacement rename");
            fs::create_dir(&sealed_path).expect("D32 sealed mirror replacement root");
            assert!(sealed.revalidate("D32 sealed mirror replacement").is_err());
        }

        #[test]
        fn d32_mutable_mirror_failure_cleanup_is_validated_and_bounded() {
            let fixture = tempfile::tempdir().expect("D32 mutable mirror cleanup fixture");
            let source = fixture.path().join("source");
            let destination = fixture.path().join("destination");
            fs::create_dir(&source).expect("D32 mutable cleanup source");
            fs::create_dir(&destination).expect("D32 mutable cleanup destination");
            let source_retained =
                D32RetainedDirectory::open(&source).expect("D32 mutable cleanup source retained");
            let destination_retained = D32RetainedDirectory::open(&destination)
                .expect("D32 mutable cleanup destination retained");
            let staging = destination_retained
                .open_or_create_mutable_child(OsStr::new("failed-staging"))
                .expect("D32 mutable cleanup staging child");
            let staging_path = staging.path().to_path_buf();
            let mut files = 0usize;
            let mut bytes = 0u64;
            let copy_result = host_copy_toolchain_tree(
                &source_retained,
                &staging,
                &mut files,
                &mut bytes,
                D32_TREE_MAX_DEPTH + 1,
            );
            let copy_error = match copy_result {
                Ok(_) => panic!("D32 mutable cleanup depth bound must fail"),
                Err(error) => error,
            };
            let rendered = host_staging_error(copy_error, staging.remove_for_cleanup());
            assert!(rendered.contains("D32 staging cleanup validated and removed"));
            assert!(
                !staging_path.exists(),
                "failed staging root must be removed"
            );
        }

        #[test]
        fn d32_selection_marker_publishes_and_atomically_replaces_handle_relative() {
            let fixture = tempfile::tempdir().expect("D32 selection marker fixture");
            let first_source = fixture.path().join("first-selection.tmp");
            let second_source = fixture.path().join("second-selection.tmp");
            let marker = fixture.path().join(D32_CARGO_SELECTION_FILE_NAME);
            fs::write(&first_source, b"first-selection")
                .expect("D32 selection marker first source");
            fs::write(&second_source, b"replacement-selection")
                .expect("D32 selection marker second source");
            fs::write(&marker, b"stale-selection").expect("D32 selection marker stale target");
            let retained = D32RetainedDirectory::open(fixture.path())
                .expect("D32 selection marker retained root");

            retained
                .rename_file(
                    OsStr::new("first-selection.tmp"),
                    OsStr::new(D32_CARGO_SELECTION_FILE_NAME),
                    true,
                )
                .expect("D32 selection marker initial publication");
            assert_eq!(
                retained
                    .read_file(OsStr::new(D32_CARGO_SELECTION_FILE_NAME), 16 * 1024)
                    .expect("D32 selection marker initial read"),
                b"first-selection"
            );

            retained
                .rename_file(
                    OsStr::new("second-selection.tmp"),
                    OsStr::new(D32_CARGO_SELECTION_FILE_NAME),
                    true,
                )
                .expect("D32 selection marker replacement");
            assert_eq!(
                retained
                    .read_file(OsStr::new(D32_CARGO_SELECTION_FILE_NAME), 16 * 1024)
                    .expect("D32 selection marker replacement read"),
                b"replacement-selection"
            );
            retained
                .revalidate("D32 selection marker after replacement")
                .expect("D32 selection marker root must remain stable");
        }

        #[test]
        fn d32_selection_marker_rejects_reparse_destination_before_replace() {
            use std::os::windows::fs::symlink_file;

            let fixture = tempfile::tempdir().expect("D32 selection reparse fixture");
            let source = fixture.path().join("reparse-source.tmp");
            let outside = fixture.path().join("outside-selection");
            let marker = fixture.path().join(D32_CARGO_SELECTION_FILE_NAME);
            fs::write(&source, b"must-not-publish").expect("D32 selection reparse source");
            fs::write(&outside, b"outside-selection").expect("D32 selection reparse target");
            if let Err(error) = symlink_file(&outside, &marker) {
                panic!("D32 selection reparse fixture could not be created: {error}");
            }
            let retained = D32RetainedDirectory::open(fixture.path())
                .expect("D32 selection reparse retained root");

            let error = retained
                .rename_file(
                    OsStr::new("reparse-source.tmp"),
                    OsStr::new(D32_CARGO_SELECTION_FILE_NAME),
                    true,
                )
                .expect_err("D32 selection marker must reject reparse destination");
            assert!(
                error.contains("reparse") || error.contains("bounded regular file"),
                "unexpected reparse rejection: {error}"
            );
            assert_eq!(
                fs::read(&outside).expect("D32 selection reparse target read"),
                b"outside-selection"
            );
            assert!(
                fs::symlink_metadata(&marker)
                    .expect("D32 selection reparse metadata")
                    .file_type()
                    .is_symlink(),
                "reparse destination must remain untouched"
            );
        }

        fn test_binding(session_id: &str) -> ProcessBinding {
            test_binding_for(session_id, "turn", "call")
        }

        fn test_binding_for(session_id: &str, turn_id: &str, tool_call_id: &str) -> ProcessBinding {
            ProcessBinding {
                session_id: session_id.to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                program_id: PROGRAM_ID.to_string(),
                executable_identity: "v1f1".to_string(),
                executable_sha256: "0".repeat(64),
                argv_hash: "1".repeat(64),
                argv_count: 1,
                working_directory_identity: "v1f2".to_string(),
                environment_policy_hash: "2".repeat(64),
                stdout_bound: 1,
                stderr_bound: 1,
                timeout_ms: 1,
                tool_call_id: tool_call_id.to_string(),
                turn_id: turn_id.to_string(),
                workspace_root_identity: "workspace".to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                git_metadata_fence_hash: "3".repeat(64),
            }
        }

        fn test_cargo_profile_evidence(workspace_identity: &str) -> HostCargoCheckProfileEvidence {
            HostCargoCheckProfileEvidence {
                executable_identity: "v1f1".to_string(),
                executable_sha256: "0".repeat(64),
                rustc_identity: "rustc-id".to_string(),
                rustc_sha256: "5".repeat(64),
                rustdoc_identity: "rustdoc-id".to_string(),
                rustdoc_sha256: "6".repeat(64),
                toolchain_root_identity: "toolchain-root".to_string(),
                toolchain_manifest_hash: "4".repeat(64),
                staged_working_directory_identity: workspace_identity.to_string(),
                environment_policy_hash: CARGO_ENVIRONMENT_POLICY_HASH.to_string(),
                profile_id: PRODUCTION_CARGO_CHECK_PROFILE_ID.to_string(),
            }
        }

        fn synthetic_published_cargo_profile(
            app_data_root: &Path,
            label: &str,
            cargo_bytes: &[u8],
        ) -> HostPublishedCargoProfile {
            let mirror_parent = app_data_root.join(D32_TOOLCHAIN_MIRROR_ROOT_NAME);
            fs::create_dir_all(&mirror_parent).expect("D32 startup tamper mirror parent");
            let staging = mirror_parent.join(format!("staging-{label}"));
            fs::create_dir_all(staging.join("bin")).expect("D32 startup tamper bin");
            fs::write(staging.join("bin/cargo.exe"), cargo_bytes)
                .expect("D32 startup tamper cargo");
            fs::write(staging.join("bin/rustc.exe"), b"rustc-image")
                .expect("D32 startup tamper rustc");
            fs::write(staging.join("bin/rustdoc.exe"), b"rustdoc-image")
                .expect("D32 startup tamper rustdoc");
            let manifest =
                host_toolchain_manifest_hash(&staging).expect("D32 startup tamper manifest");
            let mirror = mirror_parent.join(&manifest);
            fs::rename(&staging, &mirror).expect("D32 startup tamper mirror finalize");
            let cargo = mirror.join("bin/cargo.exe");
            let selection = HostCargoSelection {
                path: cargo.to_string_lossy().into_owned(),
                sha256: host_hash_file(&cargo, D32_IMAGE_HASH_MAX_BYTES)
                    .expect("D32 startup tamper cargo hash"),
                toolchain_path: mirror.to_string_lossy().into_owned(),
                toolchain_manifest_sha256: manifest,
            };
            let app_data_root_retained =
                D32RetainedDirectory::open(app_data_root).expect("D32 startup retained root");
            let expected_profile_evidence =
                host_cargo_profile_evidence_for_selection(&app_data_root_retained, &selection)
                    .expect("D32 startup tamper expected evidence");
            HostPublishedCargoProfile {
                selection,
                expected_profile_evidence,
            }
        }

        fn write_cargo_selection_marker(app_data_root: &Path, selection: &HostCargoSelection) {
            fs::write(
                host_cargo_selection_path(app_data_root),
                serde_json::to_vec(selection).expect("D32 startup tamper marker encoding"),
            )
            .expect("D32 startup tamper marker write");
        }

        #[test]
        fn d32_host_startup_tamper_cannot_redefine_expected_profile() {
            let app_data = tempfile::tempdir().expect("D32 startup tamper app data");
            let published = synthetic_published_cargo_profile(app_data.path(), "e1", b"cargo-e1");
            let replacement = synthetic_published_cargo_profile(app_data.path(), "e2", b"cargo-e2");
            write_cargo_selection_marker(app_data.path(), &published.selection);
            assert!(host_finalize_published_cargo_profile(app_data.path(), &published).is_ok());

            // A valid-looking marker digest cannot replace the in-memory E1
            // authority, even when it points at a real mirror generation.
            let mut marker_sha_tamper = published.selection.clone();
            marker_sha_tamper.sha256 = "a".repeat(64);
            write_cargo_selection_marker(app_data.path(), &marker_sha_tamper);
            assert!(host_finalize_published_cargo_profile(app_data.path(), &published).is_err());

            // A complete, valid-looking E2 marker/mirror pair is still not
            // accepted as the expected profile for this startup.
            write_cargo_selection_marker(app_data.path(), &replacement.selection);
            assert!(host_finalize_published_cargo_profile(app_data.path(), &published).is_err());

            // Restoring E1's marker and changing the mirror image itself is
            // also detected by the post-Ready exact comparison.
            write_cargo_selection_marker(app_data.path(), &published.selection);
            fs::write(
                app_data
                    .path()
                    .join(D32_TOOLCHAIN_MIRROR_ROOT_NAME)
                    .join(&published.selection.toolchain_manifest_sha256)
                    .join("bin/cargo.exe"),
                b"cargo-e1-tampered",
            )
            .expect("D32 startup tamper cargo replacement");
            assert!(host_finalize_published_cargo_profile(app_data.path(), &published).is_err());
        }

        #[test]
        fn d32_host_toolchain_prepare_reuses_verified_mirror() {
            let app_data = tempfile::tempdir().expect("D32 mirror reuse app data");
            let source = tempfile::tempdir().expect("D32 mirror reuse source");
            let source_bin = source.path().join("bin");
            fs::create_dir_all(&source_bin).expect("D32 mirror reuse source bin");
            let source_cargo = source_bin.join("cargo.exe");
            fs::write(&source_cargo, b"cargo-source").expect("D32 mirror reuse cargo");
            fs::write(source_bin.join("rustc.exe"), b"rustc-source")
                .expect("D32 mirror reuse rustc");
            fs::write(source_bin.join("rustdoc.exe"), b"rustdoc-source")
                .expect("D32 mirror reuse rustdoc");
            let selection = HostCargoSelection {
                path: source_cargo.to_string_lossy().into_owned(),
                sha256: host_hash_file(&source_cargo, D32_IMAGE_HASH_MAX_BYTES)
                    .expect("D32 mirror reuse cargo hash"),
                toolchain_path: source.path().to_string_lossy().into_owned(),
                toolchain_manifest_sha256: host_toolchain_manifest_hash(source.path())
                    .expect("D32 mirror reuse manifest"),
            };

            let first = host_prepare_toolchain_mirror(app_data.path(), &selection)
                .expect("D32 mirror first prepare");
            assert!(first.join("bin/cargo.exe").is_file());

            // A valid cache hit must not reread or recopy the source tree.  Make
            // the selected source path a directory after the first prepare:
            // canonicalization still succeeds, but any attempted copy would
            // fail, while the verified app-owned mirror remains usable.
            fs::remove_file(&source_cargo).expect("D32 mirror source cargo removal");
            fs::create_dir(&source_cargo).expect("D32 mirror source cargo sentinel");
            let second = host_prepare_toolchain_mirror(app_data.path(), &selection)
                .expect("D32 mirror cached prepare");
            assert_eq!(second, first);
            assert_eq!(
                fs::read(first.join("bin/cargo.exe")).unwrap(),
                b"cargo-source"
            );
        }

        struct GrowingReader {
            prefix: Vec<u8>,
            suffix: Vec<u8>,
            offset: usize,
        }

        impl GrowingReader {
            fn new(prefix: Vec<u8>, suffix: Vec<u8>) -> Self {
                Self {
                    prefix,
                    suffix,
                    offset: 0,
                }
            }
        }

        impl std::io::Read for GrowingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let total = self.prefix.len() + self.suffix.len();
                if self.offset >= total {
                    return Ok(0);
                }
                let (source, source_offset) = if self.offset < self.prefix.len() {
                    (&self.prefix, self.offset)
                } else {
                    (&self.suffix, self.offset - self.prefix.len())
                };
                let read = (source.len() - source_offset).min(buffer.len());
                buffer[..read].copy_from_slice(&source[source_offset..source_offset + read]);
                self.offset += read;
                Ok(read)
            }
        }

        #[test]
        fn d32_host_retained_bounded_reader_rejects_growth_without_delivering_extra() {
            let max_bytes = 5_u64;
            let mut buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let mut delivered = Vec::new();
            let result = read_retained_bounded(
                &mut GrowingReader::new(vec![0x11; max_bytes as usize], vec![0xee]),
                max_bytes,
                &mut buffer,
                |chunk| {
                    delivered.extend_from_slice(chunk);
                    Ok(())
                },
            );
            assert!(result.is_err(), "growth beyond the bound must fail closed");
            assert_eq!(delivered.len(), max_bytes as usize);
            assert!(delivered.iter().all(|byte| *byte == 0x11));

            let mut exact_buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let mut exact = Vec::new();
            let total = read_retained_bounded(
                &mut GrowingReader::new(vec![0x22; max_bytes as usize], Vec::new()),
                max_bytes,
                &mut exact_buffer,
                |chunk| {
                    exact.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .expect("an exact-bound source must be accepted");
            assert_eq!(total, max_bytes);
            assert_eq!(exact.len(), max_bytes as usize);

            let mut oversized_buffer = vec![0_u8; D32_RETAINED_READ_CHUNK_BYTES];
            let mut oversized_delivered = Vec::new();
            assert!(read_retained_bounded(
                &mut GrowingReader::new(vec![0x33; max_bytes as usize + 1], Vec::new()),
                max_bytes,
                &mut oversized_buffer,
                |chunk| {
                    oversized_delivered.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .is_err());
            assert!(oversized_delivered.is_empty());
        }

        #[test]
        fn d32_retained_file_io_does_not_consume_default_stack_for_buffers() {
            // Production Host/Vita workers use ordinary Windows thread
            // stacks.  Run both retained streaming paths on a deliberately
            // small stack so a regression to a 1 MiB stack array fails as a
            // process-level STATUS_STACK_OVERFLOW instead of being hidden by
            // the test harness's larger worker stack.
            let worker = thread::Builder::new()
                .name("d32-retained-io-stack-regression".to_string())
                .stack_size(256 * 1024)
                .spawn(|| {
                    let source = tempfile::tempdir().expect("D32 stack source tempdir");
                    let destination = tempfile::tempdir().expect("D32 stack destination tempdir");
                    let payload = vec![0x5a_u8; 2 * 1024 * 1024];
                    fs::write(source.path().join("cargo.exe"), &payload)
                        .expect("D32 stack source payload");

                    let source_retained = D32RetainedDirectory::open(source.path())
                        .expect("D32 stack source retained root");
                    let destination_retained = D32RetainedDirectory::open(destination.path())
                        .expect("D32 stack destination retained root");
                    let (source_identity, source_digest) = source_retained
                        .hash_file_with_identity(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)
                        .expect("D32 stack source hash");
                    destination_retained
                        .copy_file_from(
                            &source_retained,
                            OsStr::new("cargo.exe"),
                            OsStr::new("cargo.exe"),
                            D32_IMAGE_HASH_MAX_BYTES,
                        )
                        .expect("D32 stack retained copy");
                    let (destination_identity, destination_digest) = destination_retained
                        .hash_file_with_identity(OsStr::new("cargo.exe"), D32_IMAGE_HASH_MAX_BYTES)
                        .expect("D32 stack destination hash");
                    assert_eq!(source_identity.file_size, payload.len() as u64);
                    assert_eq!(destination_identity.file_size, payload.len() as u64);
                    assert_eq!(source_digest, destination_digest);
                })
                .expect("D32 retained I/O regression worker");
            worker
                .join()
                .expect("D32 retained I/O must not overflow its stack");
        }

        #[test]
        fn d32_retained_file_read_bounded_rejects_oversize_and_accepts_boundary() {
            let root = tempfile::tempdir().expect("D32 retained read root");
            let path = root.path().join("config");
            let payload = b"0123456789";
            fs::write(&path, payload).expect("D32 retained read payload");
            let retained = D32RetainedFile::open(&path).expect("D32 retained read file");

            assert_eq!(
                retained
                    .read_bounded(payload.len())
                    .expect("D32 retained read exact boundary"),
                payload
            );
            let error = retained
                .read_bounded(payload.len() - 1)
                .expect_err("D32 retained read must reject oversize content");
            assert!(
                error.contains("exceeded its bound"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn d32_host_no_reparse_tree_fails_closed_on_excess_entries() {
            let root = tempfile::tempdir().expect("D32 no-reparse entry root");
            fs::write(root.path().join("a"), b"a").expect("D32 no-reparse first entry");
            fs::write(root.path().join("b"), b"b").expect("D32 no-reparse second entry");

            // The production wrapper supplies the frozen 262,144-entry
            // bound.  A smaller private limit keeps this regression focused
            // without manufacturing hundreds of thousands of files.
            let error = host_verify_no_reparse_tree_with_limits(
                root.path(),
                2,
                D32_AUDIT_MAX_BYTES,
                D32_TREE_MAX_DEPTH,
            )
            .expect_err("D32 no-reparse tree must reject excess entries");
            assert!(error.contains("entry bound"), "unexpected error: {error}");
        }

        #[test]
        fn d32_host_no_reparse_tree_fails_closed_on_excessive_depth() {
            let root = tempfile::tempdir().expect("D32 no-reparse depth root");
            let mut current = root.path().to_path_buf();
            for index in 0..=D32_TREE_MAX_DEPTH {
                current.push(format!("d{index:03}"));
                fs::create_dir(&current).expect("D32 no-reparse depth directory");
            }

            let error = host_verify_no_reparse_tree(root.path())
                .expect_err("D32 no-reparse tree must reject excessive depth");
            assert!(
                error.contains("path-depth"),
                "unexpected depth-bound error: {error}"
            );
        }

        #[test]
        fn d32_host_manifest_fails_closed_on_excessive_depth() {
            let root = tempfile::tempdir().expect("D32 depth-bound root");
            let mut current = root.path().to_path_buf();
            for index in 0..=D32_TREE_MAX_DEPTH {
                current.push(format!("d{index:03}"));
                fs::create_dir(&current).expect("D32 depth-bound directory");
            }

            let error = host_toolchain_manifest_hash(root.path())
                .expect_err("D32 host manifest must reject excessive depth");
            assert!(
                error.contains("path-depth"),
                "unexpected depth-bound error: {error}"
            );
        }

        #[test]
        fn d32_a_same_valid_host_grant_replay_is_denied() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (_root, storage, registry, revision) = authority_fixture(&session);
            let host_turn_id = "turn".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("D32 replay provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("D32 replay Host turn");
            let binding = test_binding(&session.session_id);
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d32-replay-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("D32 replay authority evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("D32 replay authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply { allowed: true, .. })
            ));
            let mut grant = test_grant(&session.session_id, "d32-valid-replay", binding.clone());
            grant.authorization_revision = revision;
            session
                .grants
                .lock()
                .expect("D32 replay grant lock")
                .insert(
                    grant.grant_id.clone(),
                    HostStoredGrant {
                        host_turn_id: host_turn_id.clone(),
                        grant: grant.clone(),
                    },
                );
            let request = RevalidateGrant {
                request_id: "d32-replay-first".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: host_turn_id.clone(),
                binding: binding.clone(),
                grant: grant.clone(),
            };
            handle_revalidate_grant(&session, &storage, &registry, request.clone())
                .expect("D32 first valid grant revalidation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("D32 first replay reply"),
                HostMessage::GrantRevalidated(GrantRevalidated { allowed: true, .. })
            ));
            handle_revalidate_grant(&session, &storage, &registry, request)
                .expect("D32 replay denial response");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("D32 replay denial"),
                HostMessage::GrantRevalidated(GrantRevalidated { allowed: false, .. })
            ));
            session.retire();
        }

        fn test_grant(session_id: &str, grant_id: &str, binding: ProcessBinding) -> ProcessGrant {
            ProcessGrant {
                session_id: session_id.to_string(),
                grant_id: grant_id.to_string(),
                confirmation_id: format!("confirmation-{grant_id}"),
                binding,
                authorization_revision: 7,
                issued_at_unix_ms: unix_millis(),
                expires_at_unix_ms: unix_millis().saturating_add(60_000),
                single_use: true,
                used: false,
            }
        }

        fn test_provider() -> protocol::ProviderConfiguration {
            protocol::ProviderConfiguration {
                profile_id: "profile-chat".to_string(),
                purpose: "chat".to_string(),
                provider_kind: "openai_compatible".to_string(),
                base_url: "https://api.example.test/v1".to_string(),
                model: "model-test".to_string(),
                credential_ref: "credential-chat".to_string(),
                credential_destination: "https://api.example.test/v1".to_string(),
            }
        }

        fn authority_fixture(
            session: &HostSessionState,
        ) -> (tempfile::TempDir, StorageService, CapabilityRegistry, i64) {
            let root = tempfile::tempdir().expect("authority fixture root");
            let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .expect("authority fixture storage");
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d29h9-r3-persona".to_string(),
                    name: "D29-H9-R3 fixture persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("authority fixture persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: session.life_id.clone(),
                    name: "D29-H9-R3 fixture life".to_string(),
                    created_at: "2026-09-11T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d29h9-r3-body".to_string(),
                    persona_id: "d29h9-r3-persona".to_string(),
                    persona_version: 1,
                })
                .expect("authority fixture life");
            let capability_id =
                CapabilityId::try_from(PRODUCTION_GIT_STATUS_CAPABILITY_ID).expect("capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: session.life_id.clone(),
                        capability_id: capability_id.clone(),
                    })
                    .expect("authority fixture authorization root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let registry = CapabilityRegistry::production().expect("production registry");
            let transition = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                true,
                1,
                &session.life_id,
            )
            .expect("authority fixture authorization enable");
            assert_eq!(transition.previous_revision, 1);
            assert_eq!(transition.revision, 2);
            (root, storage, registry, transition.revision)
        }

        fn workspace_replace_authority_fixture(
            session: &HostSessionState,
        ) -> (tempfile::TempDir, StorageService, CapabilityRegistry, i64) {
            let root = tempfile::tempdir().expect("workspace replace authority fixture root");
            let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .expect("workspace replace authority fixture storage");
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-c-replace-persona".to_string(),
                    name: "D31-C replace fixture persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("workspace replace fixture persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: session.life_id.clone(),
                    name: "D31-C replace fixture life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-c-replace-body".to_string(),
                    persona_id: "d31-c-replace-persona".to_string(),
                    persona_version: 1,
                })
                .expect("workspace replace fixture life");
            let registry = CapabilityRegistry::production().expect("production registry");
            let capability_id = CapabilityId::try_from(PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID)
                .expect("workspace replace capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: session.life_id.clone(),
                        capability_id,
                    })
                    .expect("workspace replace authorization root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let transition = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
                true,
                1,
                &session.life_id,
            )
            .expect("enable workspace replace authorization");
            assert_eq!(transition.revision, 2);
            (root, storage, registry, transition.revision)
        }

        fn workspace_replace_binding(
            session: &Arc<HostSessionState>,
            provider: &protocol::ProviderConfiguration,
            host_turn_id: &str,
        ) -> protocol::WorkspaceReplaceBinding {
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, host_turn_id, provider)
                    .expect("workspace replace provider binding");
            protocol::WorkspaceReplaceBinding {
                session_id: session.session_id.clone(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
                tool_name: PRODUCTION_WORKSPACE_REPLACE_TOOL_NAME.to_string(),
                workspace_root_identity: session.workspace_identity.clone(),
                relative_path: "notes/today.txt".to_string(),
                target_identity: "workspace-replace-target".to_string(),
                target_kind: protocol::WorkspaceReplaceTargetKind::File,
                expected_sha256: "a".repeat(64),
                replacement_sha256: "b".repeat(64),
                replacement_bytes: 16,
                tool_call_id: "workspace-replace-call".to_string(),
                codex_turn_id: "workspace-replace-codex-turn".to_string(),
                provider_binding_hash: provider_binding.binding_hash,
            }
        }

        fn workspace_replace_issued_grant(
            session: &Arc<HostSessionState>,
            storage: &StorageService,
            registry: &CapabilityRegistry,
            provider: &protocol::ProviderConfiguration,
            host_turn_id: &str,
        ) -> (
            protocol::WorkspaceReplaceBinding,
            WorkspaceReplaceGrant,
            i64,
        ) {
            let binding = workspace_replace_binding(session, provider, host_turn_id);
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, host_turn_id, provider)
                    .expect("workspace replace provider binding");
            session
                .begin_turn(host_turn_id.to_string(), provider.clone(), provider_binding)
                .expect("workspace replace Host turn");
            if let Ok(mut authority) = session.turn_authority.lock() {
                if let HostTurnAuthority::Active(active) = &mut *authority {
                    active.h7_codex_turn_id = Some(binding.codex_turn_id.clone());
                }
            }
            let revision = current_workspace_replace_revision(storage, registry, session, &binding)
                .expect("workspace replace authorization revision");
            session
                .workspace_replace_approvals
                .lock()
                .expect("workspace replace approval lock")
                .insert(
                    workspace_replace_approval_key(host_turn_id, &binding),
                    WorkspaceReplaceApprovedAction {
                        host_turn_id: host_turn_id.to_string(),
                        binding: binding.clone(),
                        authorization_revision: revision,
                        confirmation_id: "workspace-replace-confirmation".to_string(),
                        expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    },
                );
            let issued = issue_workspace_replace_grant(
                storage,
                registry,
                session,
                &WorkspaceReplaceIssueGrant {
                    request_id: "workspace-replace-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    authorization_revision: revision,
                },
            )
            .expect("workspace replace grant issue");
            (binding, issued, revision)
        }

        fn recovery_authority_fixture(
            session: &HostSessionState,
        ) -> (tempfile::TempDir, StorageService, CapabilityRegistry, i64) {
            let root = tempfile::tempdir().expect("recovery authority fixture root");
            let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .expect("recovery authority fixture storage");
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-c-recovery-persona".to_string(),
                    name: "D31-C recovery fixture persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("recovery fixture persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: session.life_id.clone(),
                    name: "D31-C recovery fixture life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-c-recovery-body".to_string(),
                    persona_id: "d31-c-recovery-persona".to_string(),
                    persona_version: 1,
                })
                .expect("recovery fixture life");
            let registry = CapabilityRegistry::production().expect("production registry");
            let capability_id = CapabilityId::try_from(PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID)
                .expect("recovery capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: session.life_id.clone(),
                        capability_id,
                    })
                    .expect("recovery authorization root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let transition = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
                true,
                1,
                &session.life_id,
            )
            .expect("enable recovery authorization");
            assert_eq!(transition.revision, 2);
            (root, storage, registry, transition.revision)
        }

        fn recovery_issued_grant(
            session: &Arc<HostSessionState>,
            storage: &StorageService,
            registry: &CapabilityRegistry,
        ) -> (protocol::RecoveryBinding, RecoveryGrant, i64) {
            let action_id = "recovery-race-action".to_string();
            let generation = "recovery-race-generation".to_string();
            let pending = protocol::RecoveryPending {
                request_id: "recovery-race-pending".to_string(),
                session_id: session.session_id.clone(),
                transaction_id: "recovery-race-transaction".to_string(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID.to_string(),
                workspace_root_identity: session.workspace_identity.clone(),
                relative_path: "notes/today.txt".to_string(),
                target_identity: "recovery-race-target".to_string(),
                journal_integrity_hash: "a".repeat(64),
                current_sha256: "b".repeat(64),
                current_bytes: 16,
                restore_sha256: "c".repeat(64),
                restore_bytes: 12,
                original_replacement_sha256: "d".repeat(64),
            };
            let binding = protocol::RecoveryBinding {
                session_id: session.session_id.clone(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID.to_string(),
                workspace_root_identity: session.workspace_identity.clone(),
                relative_path: pending.relative_path.clone(),
                target_identity: pending.target_identity.clone(),
                transaction_id: pending.transaction_id.clone(),
                journal_integrity_hash: pending.journal_integrity_hash.clone(),
                current_sha256: pending.current_sha256.clone(),
                current_bytes: pending.current_bytes,
                restore_sha256: pending.restore_sha256.clone(),
                restore_bytes: pending.restore_bytes,
                original_replacement_sha256: pending.original_replacement_sha256.clone(),
                recovery_action_id: action_id.clone(),
                recovery_generation: generation.clone(),
            };
            binding.validate().expect("recovery race binding");
            session
                .recovery_actions
                .lock()
                .expect("recovery action lock")
                .insert(
                    action_id.clone(),
                    HostRecoveryAction {
                        recovery_action_id: action_id.clone(),
                        recovery_generation: generation.clone(),
                        transaction_id: pending.transaction_id.clone(),
                        pending,
                        phase: HostRecoveryActionPhase::GrantIssued,
                    },
                );
            let authority_scope = storage
                .capability_authorization_scope()
                .expect("recovery race authority scope");
            let revision =
                current_recovery_revision_in_scope(&authority_scope, registry, session, &binding)
                    .expect("recovery race revision");
            drop(authority_scope);
            let grant = RecoveryGrant {
                session_id: session.session_id.clone(),
                grant_id: "recovery-race-grant".to_string(),
                confirmation_id: "recovery-race-confirmation".to_string(),
                binding: binding.clone(),
                authorization_revision: revision,
                issued_at_unix_ms: unix_millis(),
                expires_at_unix_ms: unix_millis().saturating_add(5_000),
                single_use: true,
                used: false,
            };
            grant.validate().expect("recovery race grant");
            session
                .recovery_grants
                .lock()
                .expect("recovery grant lock")
                .insert(
                    grant.grant_id.clone(),
                    RecoveryGrantState {
                        recovery_action_id: action_id,
                        recovery_generation: generation,
                        grant: grant.clone(),
                        phase: RecoveryGrantPhase::Issued,
                    },
                );
            (binding, grant, revision)
        }

        fn synthetic_workspace_read_descriptor() -> CapabilityDescriptor {
            CapabilityDescriptor::synthetic(
                CapabilityId::try_from(protocol::WORKSPACE_READ_CAPABILITY_ID)
                    .expect("D31 workspace read capability ID"),
                "Synthetic D31 workspace read",
                RiskClass::Critical,
                ApprovalFloor::ExplicitPerAction,
                ScopeRequirement::WorkspaceRequired,
            )
            .expect("synthetic D31 workspace read descriptor")
        }

        fn synthetic_multi_capability_registry() -> CapabilityRegistry {
            let git = CapabilityDescriptor::synthetic(
                CapabilityId::try_from(PRODUCTION_GIT_STATUS_CAPABILITY_ID)
                    .expect("production Git capability ID"),
                "Synthetic Git status",
                RiskClass::Critical,
                ApprovalFloor::ExplicitPerAction,
                ScopeRequirement::WorkspaceRequired,
            )
            .expect("synthetic Git descriptor");
            CapabilityRegistry::synthetic([git, synthetic_workspace_read_descriptor()])
                .expect("synthetic two-capability registry")
        }

        fn synthetic_multi_capability_fixture(
            session: &HostSessionState,
            git_enabled: Option<bool>,
            read_enabled: Option<bool>,
        ) -> (tempfile::TempDir, StorageService, CapabilityRegistry) {
            let root = tempfile::tempdir().expect("multi-capability fixture root");
            let storage = StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .expect("multi-capability fixture storage");
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-a-persona".to_string(),
                    name: "D31-A fixture persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("multi-capability fixture persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: session.life_id.clone(),
                    name: "D31-A fixture life".to_string(),
                    created_at: "2026-09-13T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-a-body".to_string(),
                    persona_id: "d31-a-persona".to_string(),
                    persona_version: 1,
                })
                .expect("multi-capability fixture life");
            let registry = synthetic_multi_capability_registry();
            for (capability_id, enabled, event_id) in [
                (
                    PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                    git_enabled,
                    "d31-a-synthetic-git",
                ),
                (
                    protocol::WORKSPACE_READ_CAPABILITY_ID,
                    read_enabled,
                    "d31-a-synthetic-read",
                ),
            ] {
                let Some(enabled) = enabled else { continue };
                let capability_id =
                    CapabilityId::try_from(capability_id).expect("synthetic capability ID");
                assert!(matches!(
                    storage
                        .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                            life_id: session.life_id.clone(),
                            capability_id: capability_id.clone(),
                        })
                        .expect("synthetic authorization root"),
                    CapabilityAuthorizationCreateOutcome::Applied(_)
                ));
                if enabled {
                    storage
                        .update_capability_authorization(
                            LifeCapabilityAuthorizationUpdateRequest::for_test(
                                event_id,
                                session.life_id.clone(),
                                capability_id,
                                true,
                                1,
                            ),
                        )
                        .expect("enable synthetic root");
                }
            }
            (root, storage, registry)
        }

        fn independently_initialized_storage(storage: &StorageService) -> StorageService {
            let active_root = storage.active_root_for_test();
            StorageService::initialize_with_roots(active_root, None)
                .expect("independent storage service")
        }

        fn switch_current_life_for_test(storage: &StorageService) {
            storage
                .save_life(LifeIdentityRecord {
                    id: "d31-life-b".to_string(),
                    name: "D31 second life".to_string(),
                    created_at: "2026-09-13T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-b-body".to_string(),
                    persona_id: "d31-a-persona".to_string(),
                    persona_version: 1,
                })
                .expect("switch current Life");
        }

        fn assert_independent_storage_gate_identities(
            first: &StorageService,
            second: &StorageService,
        ) {
            assert_ne!(
                first.capability_authorization_process_local_identity_for_test(),
                second.capability_authorization_process_local_identity_for_test()
            );
            assert_eq!(
                first.capability_authorization_gate_name_for_test(),
                second.capability_authorization_gate_name_for_test()
            );
        }

        fn workspace_read_binding(
            session: &Arc<HostSessionState>,
            provider: &protocol::ProviderConfiguration,
            host_turn_id: &str,
        ) -> protocol::WorkspaceReadBinding {
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, host_turn_id, provider)
                    .expect("provider binding");
            protocol::WorkspaceReadBinding {
                session_id: session.session_id.clone(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: protocol::WORKSPACE_READ_CAPABILITY_ID.to_string(),
                tool_name: protocol::WORKSPACE_READ_TOOL_NAME.to_string(),
                workspace_root_identity: session.workspace_identity.clone(),
                relative_path: "notes/today.txt".to_string(),
                target_identity: "workspace-target".to_string(),
                target_kind: protocol::WorkspaceReadTargetKind::File,
                max_bytes: protocol::MAX_WORKSPACE_READ_BYTES,
                tool_call_id: "read-call".to_string(),
                codex_turn_id: "codex-read-turn".to_string(),
                provider_binding_hash: provider_binding.binding_hash,
            }
        }

        fn workspace_read_issued_grant(
            session: &Arc<HostSessionState>,
            storage: &StorageService,
            registry: &CapabilityRegistry,
            provider: &protocol::ProviderConfiguration,
            host_turn_id: &str,
        ) -> (protocol::WorkspaceReadBinding, WorkspaceReadGrant) {
            let binding = workspace_read_binding(session, provider, host_turn_id);
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, host_turn_id, provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.to_string(), provider.clone(), provider_binding)
                .expect("active Host turn");
            let revision = current_workspace_read_revision(storage, registry, session, &binding)
                .expect("workspace read revision");
            if let Ok(mut authority) = session.turn_authority.lock() {
                if let HostTurnAuthority::Active(active) = &mut *authority {
                    active.h7_codex_turn_id = Some(binding.codex_turn_id.clone());
                }
            }
            session.install_workspace_read_approval(
                host_turn_id,
                binding.clone(),
                revision,
                "read-confirmation",
                unix_millis().saturating_add(5_000),
            );
            let issued = issue_workspace_read_grant(
                storage,
                registry,
                session,
                &protocol::WorkspaceReadIssueGrant {
                    request_id: "read-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    authorization_revision: revision,
                },
            )
            .expect("workspace read issue");
            assert!(!issued.used);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&issued.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Issued)
            );
            (binding, issued)
        }

        fn workspace_read_release_request(
            session: &Arc<HostSessionState>,
            storage: &StorageService,
            registry: &CapabilityRegistry,
            provider: &protocol::ProviderConfiguration,
            host_turn_id: &str,
            content: &[u8],
        ) -> protocol::WorkspaceReadReleaseCheck {
            let (binding, issued) =
                workspace_read_issued_grant(session, storage, registry, provider, host_turn_id);
            let revalidated = revalidate_workspace_read_grant(
                storage,
                registry,
                session,
                &protocol::WorkspaceReadRevalidateGrant {
                    request_id: "read-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    grant: issued,
                },
            )
            .expect("workspace read revalidate");
            assert!(revalidated.used);
            let content_sha256 = format!("{:x}", Sha256::digest(content));
            protocol::WorkspaceReadReleaseCheck {
                request_id: "read-release".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: host_turn_id.to_string(),
                binding,
                grant: revalidated,
                bytes_read: content.len() as u64,
                content_sha256,
            }
        }

        #[test]
        fn stale_sidecar_provider_requires_explicit_restart() {
            let provider_a = test_provider();
            let mut provider_b = provider_a.clone();
            provider_b.profile_id = "profile-chat-b".to_string();
            assert!(sidecar_provider_requires_restart(
                true,
                Some(&provider_a),
                Some(&provider_b)
            ));
            assert!(sidecar_provider_requires_restart(
                true,
                None,
                Some(&provider_a)
            ));
            assert!(!sidecar_provider_requires_restart(
                true,
                Some(&provider_a),
                Some(&provider_a)
            ));
            assert!(!sidecar_provider_requires_restart(
                false,
                None,
                Some(&provider_a)
            ));
        }

        #[test]
        fn sidecar_start_uses_host_current_life_fence_before_process_work() {
            let (session, receiver) = test_session();
            let (_root, storage, _registry, _revision) = authority_fixture(&session);
            storage
                .save_life(LifeIdentityRecord {
                    id: "life-b".to_string(),
                    name: "D30-B second life".to_string(),
                    created_at: "2026-09-12T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d29h9-r3-body".to_string(),
                    persona_id: "d29h9-r3-persona".to_string(),
                    persona_version: 1,
                })
                .expect("switch current Life");

            assert_eq!(
                observed_current_life(&storage, &session.life_id).unwrap_err(),
                RUNTIME_LIFE_CHANGED
            );
            // The fence is checked before start_inner, so no Host session,
            // workspace authority, or native process can exist to observe.
            assert!(receiver.try_recv().is_err());
        }

        #[test]
        fn running_session_rejects_new_turn_after_current_life_changes() {
            let (session, _receiver) = test_session();
            let (_root, storage, _registry, _revision) = authority_fixture(&session);
            storage
                .save_life(LifeIdentityRecord {
                    id: "life-b".to_string(),
                    name: "D30-B second life".to_string(),
                    created_at: "2026-09-12T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d29h9-r3-body".to_string(),
                    persona_id: "d29h9-r3-persona".to_string(),
                    persona_version: 1,
                })
                .expect("switch current Life");

            assert_eq!(
                require_current_session_life(&storage, &session).unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
            assert!(session
                .active_turn_id
                .lock()
                .expect("active turn lock")
                .is_none());
        }

        #[test]
        fn runtime_preflight_uses_d30_transition_and_fails_closed() {
            let (session, receiver) = test_session();
            let (_root, storage, registry, enabled_revision) = authority_fixture(&session);

            assert_eq!(
                preflight_capability_roots(&storage, &registry, &session),
                Ok(())
            );
            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.previous_revision, enabled_revision);
            assert_eq!(disabled.revision, enabled_revision + 1);
            assert_eq!(
                preflight_capability_roots(&storage, &registry, &session).unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );

            let (missing_session, _missing_receiver) = test_session_for_life("life-missing");
            assert_eq!(
                preflight_capability_roots(&storage, &registry, &missing_session).unwrap_err(),
                "CAPABILITY_AUTHORIZATION_REQUIRED"
            );
            // A denied preflight does not create a Host turn generation or a
            // StartTurn frame, which is the zero-provider disabled canary.
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
            assert!(receiver.try_recv().is_err());
        }

        #[test]
        fn d31_synthetic_multi_capability_admission_allows_any_usable_root() {
            for (case, git_enabled, read_enabled, admitted) in [
                ("git enabled/read disabled", Some(true), Some(false), true),
                ("git disabled/read enabled", Some(false), Some(true), true),
                ("both enabled", Some(true), Some(true), true),
                ("both disabled", Some(false), Some(false), false),
                ("git missing/read enabled", None, Some(true), true),
                ("git enabled/read missing", Some(true), None, true),
                ("all missing", None, None, false),
            ] {
                let provider = test_provider();
                let (session, receiver) = test_session_with_provider(provider.clone());
                let (root, storage, registry) =
                    synthetic_multi_capability_fixture(&session, git_enabled, read_enabled);
                let coordinator = VitaSidecarCoordinator::new(Arc::new(storage), registry);
                *coordinator
                    .test_provider_override
                    .lock()
                    .expect("provider override lock") = Some(provider);
                coordinator.install_test_session(Arc::clone(&session));

                let result = coordinator.start_turn(VitaTurnStartRequest {
                    prompt: format!("D31 multi-capability {case}"),
                });
                if admitted {
                    let response = result.expect(case);
                    assert!(response.accepted, "{case}");
                    assert!(matches!(
                        receiver.recv_timeout(Duration::from_secs(1)),
                        Ok(HostMessage::StartTurn(protocol::StartTurn { turn_id, .. }))
                            if turn_id == response.turn_id
                    ));
                    assert!(receiver.recv_timeout(Duration::from_millis(25)).is_err());
                    session.retire();
                } else {
                    assert!(result.is_err(), "{case} must deny");
                    assert!(matches!(
                        session.authority_snapshot(),
                        Some(HostTurnAuthority::Idle)
                    ));
                    assert!(receiver.try_recv().is_err());
                }
                drop(coordinator);
                drop(root);
            }
        }

        #[test]
        fn d31_status_projects_each_trusted_capability_without_authority_cache() {
            let (session, _receiver) = test_session();
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, Some(false), Some(true));
            let (aggregate, states, current_life_id) =
                capability_readiness(&storage, &registry, Some(&session.life_id));
            assert_eq!(aggregate, VitaCapabilityReadiness::RootEnabled);
            assert_eq!(current_life_id.as_deref(), Some(session.life_id.as_str()));
            assert_eq!(states.len(), 2);
            assert!(states.iter().any(|state| {
                state.capability_id == PRODUCTION_GIT_STATUS_CAPABILITY_ID
                    && state.readiness == VitaCapabilityReadiness::RootDisabled
                    && state.revision == Some(1)
            }));
            assert!(states.iter().any(|state| {
                state.capability_id == protocol::WORKSPACE_READ_CAPABILITY_ID
                    && state.readiness == VitaCapabilityReadiness::RootEnabled
                    && state.revision == Some(2)
            }));
            drop(root);
        }

        #[test]
        fn d31_r7_gate_error_mapper_preserves_restart_and_gate_classes() {
            assert_eq!(
                capability_authorization_gate_error(
                    StorageError::capability_authority_restart_required()
                ),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            assert_eq!(
                capability_authorization_gate_error(
                    StorageError::capability_authorization_gate_unavailable()
                ),
                "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE"
            );
            assert_eq!(
                capability_authorization_gate_error(StorageError::connection_open_failed()),
                "CAPABILITY_AUTHORIZATION_UNAVAILABLE"
            );
        }

        #[test]
        fn d31_r7_stale_generation_preserves_restart_through_h7_confirmation() {
            let provider = test_provider();
            let (session, receiver) = test_session();
            let (root, primary_storage, registry, enabled_revision) = authority_fixture(&session);
            let stale_storage = independently_initialized_storage(&primary_storage);
            let host_turn_id = "d31-r7-h7-host-turn".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let binding = test_binding_for(
                &session.session_id,
                "d31-r7-h7-codex-turn",
                "d31-r7-h7-call",
            );
            handle_authority_evaluate(
                &session,
                &primary_storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d31-r7-h7-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("H7 authority evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("H7 authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == enabled_revision
            ));
            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "d31-r7-h7-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding.clone(),
                },
            )
            .expect("H7 confirmation pending");
            let pending_id = session
                .pending_summary()
                .expect("pending H7 confirmation")
                .pending_id;

            let target = root.path().join("d31-r7-h7-target");
            let migration = primary_storage.migrate_location(target.to_str().expect("target path"));
            assert!(migration.success, "{migration:?}");
            assert!(migration.restart_required);

            assert_eq!(
                current_workspace_revision(&stale_storage, &registry, &session, &binding,)
                    .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            let coordinator = VitaSidecarCoordinator::new(Arc::new(stale_storage), registry);
            coordinator.install_test_session(Arc::clone(&session));
            assert_eq!(
                coordinator
                    .decide_pending(pending_id, ConfirmationDecision::Confirm)
                    .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("restart denial reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                    ..
                })
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            session.retire();
            drop(coordinator);
            drop(primary_storage);
            drop(root);
        }

        #[test]
        fn d31_r7_stale_generation_denies_preread_with_restart_and_preserves_issued() {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let stale_storage = independently_initialized_storage(&primary_storage);
            let host_turn_id = "d31-r7-preread-host-turn";
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &stale_storage,
                &registry,
                &provider,
                host_turn_id,
            );
            let target = root.path().join("d31-r7-preread-target");
            let migration = primary_storage.migrate_location(target.to_str().expect("target path"));
            assert!(migration.success, "{migration:?}");
            assert!(migration.restart_required);

            assert_eq!(
                current_workspace_read_revision(&stale_storage, &registry, &session, &binding,)
                    .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            session.install_workspace_read_approval(
                host_turn_id,
                binding.clone(),
                issued.authorization_revision,
                "d31-r7-stale-issue-confirmation",
                unix_millis().saturating_add(5_000),
            );
            assert_eq!(
                issue_workspace_read_grant(
                    &stale_storage,
                    &registry,
                    &session,
                    &WorkspaceReadIssueGrant {
                        request_id: "d31-r7-stale-issue".to_string(),
                        session_id: session.session_id.clone(),
                        host_turn_id: host_turn_id.to_string(),
                        binding: binding.clone(),
                        authorization_revision: issued.authorization_revision,
                    },
                )
                .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            assert_eq!(
                revalidate_workspace_read_grant(
                    &stale_storage,
                    &registry,
                    &session,
                    &WorkspaceReadRevalidateGrant {
                        request_id: "d31-r7-stale-preread".to_string(),
                        session_id: session.session_id.clone(),
                        host_turn_id: host_turn_id.to_string(),
                        binding,
                        grant: issued.clone(),
                    },
                )
                .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&issued.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Issued, false))
            );
            session.retire();
            drop(stale_storage);
            drop(primary_storage);
            drop(root);
        }

        #[test]
        fn d31_r7_stale_generation_denies_release_with_restart_and_preserves_revalidated() {
            let provider = test_provider();
            let content = b"D31-R7 stale generation release bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let stale_storage = independently_initialized_storage(&primary_storage);
            let request = workspace_read_release_request(
                &session,
                &stale_storage,
                &registry,
                &provider,
                "d31-r7-release-host-turn",
                content,
            );
            let target = root.path().join("d31-r7-release-target");
            let migration = primary_storage.migrate_location(target.to_str().expect("target path"));
            assert!(migration.success, "{migration:?}");
            assert!(migration.restart_required);

            assert_eq!(
                authorize_workspace_read_release(
                    &stale_storage,
                    &registry,
                    &session,
                    &request,
                    content,
                )
                .unwrap_err(),
                CAPABILITY_AUTHORITY_RESTART_REQUIRED
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Revalidated, true))
            );
            session.retire();
            drop(stale_storage);
            drop(primary_storage);
            drop(root);
        }

        #[test]
        fn d31_workspace_read_lifecycle_is_host_ledger_linearized() {
            let provider = test_provider();
            let content = b"D31 confidential workspace bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-release-host-turn",
                content,
            );
            assert!(request.grant.used);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Revalidated)
            );
            assert_eq!(
                revalidate_workspace_read_grant(
                    &storage,
                    &registry,
                    &session,
                    &protocol::WorkspaceReadRevalidateGrant {
                        request_id: "read-revalidate-replay".to_string(),
                        session_id: session.session_id.clone(),
                        host_turn_id: "d31-release-host-turn".to_string(),
                        binding: request.binding.clone(),
                        grant: request.grant.clone(),
                    },
                )
                .unwrap_err(),
                "WORKSPACE_READ_REVALIDATION_INVALID"
            );
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &request, content),
                Ok(())
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );

            let disabled_after_release = apply_transition_for_test(
                &storage,
                &registry,
                protocol::WORKSPACE_READ_CAPABILITY_ID,
                false,
                2,
                &session.life_id,
            )
            .expect("revoke after committed release");
            assert_eq!(disabled_after_release.revision, 3);

            let mut replay = request.clone();
            replay.request_id = "read-release-replay".to_string();
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &replay, content)
                    .unwrap_err(),
                "WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH"
            );

            assert_eq!(
                session.begin_cancellation().expect("cancel after release"),
                Some("d31-release-host-turn".to_string())
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_workspace_read_production_handlers_complete_typed_chain() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let storage = Arc::new(storage);
            let host_turn_id = "d31-handler-host-turn";
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.to_string(), provider, provider_binding.clone())
                .expect("active Host turn");
            let binding = workspace_read_binding(&session, &test_provider(), host_turn_id);
            handle_workspace_read_authority_evaluate(
                &session,
                &storage,
                &registry,
                WorkspaceReadAuthorityEvaluate {
                    request_id: "d31-handler-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                },
            )
            .expect("workspace read authority handler");
            let revision = match receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("workspace authority reply")
            {
                HostMessage::WorkspaceReadAuthorityReply(reply) => {
                    assert!(reply.allowed);
                    reply.authorization_revision.expect("read revision")
                }
                other => panic!("unexpected workspace authority reply: {other:?}"),
            };
            handle_workspace_read_confirmation_required(
                &session,
                WorkspaceReadConfirmationRequired {
                    request_id: "d31-handler-confirm".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    workspace_summary: "handler fixture".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding.clone(),
                },
            )
            .expect("workspace read confirmation handler");
            let pending_id = session
                .pending_summary()
                .expect("workspace read pending summary")
                .pending_id;
            assert!(pending_id.starts_with("read-pending:"));
            let coordinator = VitaSidecarCoordinator::new(Arc::clone(&storage), registry.clone());
            coordinator.install_test_session(Arc::clone(&session));
            coordinator
                .confirm(pending_id)
                .expect("workspace read confirmation decision");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("workspace read confirmation reply"),
                HostMessage::WorkspaceReadConfirmationReply(
                    WorkspaceReadConfirmationReply {
                        decision: ConfirmationDecision::Confirm,
                        authorization_revision: Some(reply_revision),
                        ..
                    }
                ) if reply_revision == revision
            ));
            handle_workspace_read_issue_grant(
                &session,
                &storage,
                &registry,
                WorkspaceReadIssueGrant {
                    request_id: "d31-handler-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    authorization_revision: revision,
                },
            )
            .expect("workspace read grant handler");
            let issued = match receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("workspace read grant reply")
            {
                HostMessage::WorkspaceReadGrantIssued(reply) => {
                    assert!(reply.allowed);
                    reply.grant.expect("issued workspace read grant")
                }
                other => panic!("unexpected workspace grant reply: {other:?}"),
            };
            handle_workspace_read_revalidate_grant(
                &session,
                &storage,
                &registry,
                WorkspaceReadRevalidateGrant {
                    request_id: "d31-handler-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    grant: issued,
                },
            )
            .expect("workspace read revalidation handler");
            let revalidated = match receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("workspace read revalidation reply")
            {
                HostMessage::WorkspaceReadGrantRevalidated(reply) => {
                    assert!(reply.allowed);
                    reply.grant.expect("revalidated workspace read grant")
                }
                other => panic!("unexpected workspace revalidation reply: {other:?}"),
            };
            let content = b"D31-B handler content";
            handle_workspace_read_release_check(
                &session,
                &storage,
                &registry,
                WorkspaceReadReleaseCheck {
                    request_id: "d31-handler-release".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding,
                    grant: revalidated,
                    bytes_read: content.len() as u64,
                    content_sha256: format!("{:x}", Sha256::digest(content)),
                },
            )
            .expect("workspace read release handler");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("workspace read release reply"),
                HostMessage::WorkspaceReadReleaseChecked(WorkspaceReadReleaseChecked {
                    allowed: true,
                    error_code: None,
                    ..
                })
            ));
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .values()
                    .next()
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );
            session.retire();
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d31_life_switch_before_preread_denies_and_preserves_issued_grant() {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-life-switch-before-preread",
            );
            switch_current_life_for_test(&storage);
            let result = revalidate_workspace_read_grant(
                &storage,
                &registry,
                &session,
                &protocol::WorkspaceReadRevalidateGrant {
                    request_id: "d31-life-switch-before-preread-request".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: "d31-life-switch-before-preread".to_string(),
                    binding,
                    grant: issued.clone(),
                },
            );
            assert_eq!(result.unwrap_err(), LIFE_RESTART_REQUIRED);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&issued.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Issued, false))
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_life_switch_after_preread_denies_release_and_preserves_revalidated() {
            let provider = test_provider();
            let content = b"D31 life switch bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-life-switch-before-release",
                content,
            );
            switch_current_life_for_test(&storage);
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &request, content)
                    .unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Revalidated, true))
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_release_first_then_life_switch_preserves_released_decision() {
            let provider = test_provider();
            let content = b"D31 released before life switch";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-release-before-life-switch",
                content,
            );
            authorize_workspace_read_release(&storage, &registry, &session, &request, content)
                .expect("release commits before Life switch");
            switch_current_life_for_test(&storage);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_revoke_first_linearizes_before_pre_read_revalidation() {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &authority_storage,
                &registry,
                &provider,
                "d31-preread-revoke-first-host-turn",
            );
            assert!(!issued.used);
            let request = protocol::WorkspaceReadRevalidateGrant {
                request_id: "d31-preread-revoke-first".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-preread-revoke-first-host-turn".to_string(),
                binding,
                grant: issued.clone(),
            };
            let start = Arc::new(Barrier::new(2));
            let (revoke_done_tx, revoke_done_rx) = mpsc::channel();
            let revoke_storage = Arc::clone(&primary_storage);
            let revoke_registry = registry.clone();
            let revoke_life_id = session.life_id.clone();
            let revoke_start = Arc::clone(&start);
            let revoke_thread = thread::spawn(move || {
                revoke_start.wait();
                let transition = apply_transition_for_test(
                    &revoke_storage,
                    &revoke_registry,
                    protocol::WORKSPACE_READ_CAPABILITY_ID,
                    false,
                    2,
                    &revoke_life_id,
                )
                .expect("revoke must commit first");
                revoke_done_tx
                    .send(transition.revision)
                    .expect("revalidate thread must observe revoke commit");
                transition.revision
            });
            let revalidate_storage = Arc::clone(&authority_storage);
            let revalidate_registry = registry.clone();
            let revalidate_session = Arc::clone(&session);
            let revalidate_request = request.clone();
            let revalidate_start = Arc::clone(&start);
            let revalidate_thread = thread::spawn(move || {
                revalidate_start.wait();
                assert_eq!(revoke_done_rx.recv().expect("revoke-first barrier"), 3);
                revalidate_workspace_read_grant(
                    &revalidate_storage,
                    &revalidate_registry,
                    &revalidate_session,
                    &revalidate_request,
                )
            });

            assert_eq!(revoke_thread.join().expect("revoke thread"), 3);
            assert_eq!(
                revalidate_thread.join().expect("revalidate thread"),
                Err("CAPABILITY_ROOT_DISABLED".to_string())
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&issued.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Issued, false))
            );
            let row = primary_storage
                .find_capability_authorization(
                    &session.life_id,
                    &CapabilityId::try_from(protocol::WORKSPACE_READ_CAPABILITY_ID)
                        .expect("workspace read capability"),
                )
                .expect("authorization row")
                .expect("authorization row exists");
            assert!(!row.enabled);
            assert_eq!(row.revision, 3);
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_pre_read_revalidation_wins_then_later_revoke_blocks_release() {
            let provider = test_provider();
            let content: &'static [u8] = b"D31 pre-read authorized bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &authority_storage,
                &registry,
                &provider,
                "d31-preread-release-first-host-turn",
            );
            let request = protocol::WorkspaceReadRevalidateGrant {
                request_id: "d31-preread-release-first".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-preread-release-first-host-turn".to_string(),
                binding: binding.clone(),
                grant: issued,
            };
            let start = Arc::new(Barrier::new(2));
            let (revalidate_done_tx, revalidate_done_rx) = mpsc::channel();
            let revalidate_storage = Arc::clone(&authority_storage);
            let revalidate_registry = registry.clone();
            let revalidate_session = Arc::clone(&session);
            let revalidate_request = request.clone();
            let revalidate_start = Arc::clone(&start);
            let revalidate_thread = thread::spawn(move || {
                revalidate_start.wait();
                let result = revalidate_workspace_read_grant(
                    &revalidate_storage,
                    &revalidate_registry,
                    &revalidate_session,
                    &revalidate_request,
                );
                revalidate_done_tx
                    .send(result.is_ok())
                    .expect("revoke thread must observe revalidation commit");
                result
            });
            let revoke_storage = Arc::clone(&primary_storage);
            let revoke_registry = registry.clone();
            let revoke_life_id = session.life_id.clone();
            let revoke_start = Arc::clone(&start);
            let revoke_thread = thread::spawn(move || {
                revoke_start.wait();
                assert!(
                    revalidate_done_rx
                        .recv()
                        .expect("revalidation-first barrier"),
                    "pre-read revalidation must commit before revoke"
                );
                apply_transition_for_test(
                    &revoke_storage,
                    &revoke_registry,
                    protocol::WORKSPACE_READ_CAPABILITY_ID,
                    false,
                    2,
                    &revoke_life_id,
                )
                .expect("revoke after pre-read authorization")
                .revision
            });

            let revalidated = revalidate_thread
                .join()
                .expect("revalidate thread")
                .expect("pre-read revalidation wins");
            assert!(revalidated.used);
            assert_eq!(revoke_thread.join().expect("revoke thread"), 3);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&revalidated.grant_id)
                    .map(|state| (state.phase, state.grant.used)),
                Some((WorkspaceReadGrantPhase::Revalidated, true))
            );

            let release_request = protocol::WorkspaceReadReleaseCheck {
                request_id: "d31-preread-release-after-revoke".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-preread-release-first-host-turn".to_string(),
                binding,
                bytes_read: content.len() as u64,
                content_sha256: format!("{:x}", Sha256::digest(content)),
                grant: revalidated,
            };
            assert_eq!(
                authorize_workspace_read_release(
                    &authority_storage,
                    &registry,
                    &session,
                    &release_request,
                    content,
                )
                .unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&release_request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Revalidated)
            );
            let row = primary_storage
                .find_capability_authorization(
                    &session.life_id,
                    &CapabilityId::try_from(protocol::WORKSPACE_READ_CAPABILITY_ID)
                        .expect("workspace read capability"),
                )
                .expect("authorization row")
                .expect("authorization row exists");
            assert!(!row.enabled);
            assert_eq!(row.revision, 3);
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_cancel_before_pre_read_revalidation_denies_and_retires_issued_grant() {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-preread-cancel-host-turn",
            );
            let request = protocol::WorkspaceReadRevalidateGrant {
                request_id: "d31-preread-cancel".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-preread-cancel-host-turn".to_string(),
                binding,
                grant: issued,
            };
            session
                .begin_cancellation()
                .expect("cancel active Host turn");
            assert_eq!(
                revalidate_workspace_read_grant(&storage, &registry, &session, &request)
                    .unwrap_err(),
                "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
            );
            assert!(session
                .workspace_read_grants
                .lock()
                .expect("workspace read grant lock")
                .is_empty());
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_cancel_before_pre_read_commit_is_deny_only_without_a_read_start() {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-cancel-before-pre-read-commit",
            );
            let request = protocol::WorkspaceReadRevalidateGrant {
                request_id: "d31-cancel-before-pre-read-commit-request".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-cancel-before-pre-read-commit".to_string(),
                binding,
                grant: issued,
            };
            let start = Arc::new(Barrier::new(2));
            let (cancel_committed_tx, cancel_committed_rx) = mpsc::channel();
            let cancel_session = Arc::clone(&session);
            let cancel_start = Arc::clone(&start);
            let cancel_thread = thread::spawn(move || {
                cancel_start.wait();
                let result = cancel_session
                    .begin_cancellation()
                    .expect("Host cancellation must linearize");
                cancel_committed_tx
                    .send(result)
                    .expect("revalidation must observe cancellation commit");
            });
            let revalidate_storage = storage;
            let revalidate_registry = registry;
            let revalidate_session = Arc::clone(&session);
            let revalidate_start = Arc::clone(&start);
            let revalidate_thread = thread::spawn(move || {
                revalidate_start.wait();
                assert_eq!(
                    cancel_committed_rx
                        .recv()
                        .expect("cancel-before-pre-read-commit signal"),
                    Some("d31-cancel-before-pre-read-commit".to_string())
                );
                revalidate_workspace_read_grant(
                    &revalidate_storage,
                    &revalidate_registry,
                    &revalidate_session,
                    &request,
                )
            });

            cancel_thread.join().expect("cancellation thread");
            assert_eq!(
                revalidate_thread.join().expect("revalidation thread"),
                Err("WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE".to_string())
            );
            // No Issued -> Revalidated transition means no executable read
            // start can be imported by Vita, and cancellation retired the
            // complete pre-read ledger.
            assert!(session
                .workspace_read_grants
                .lock()
                .expect("workspace read grant lock")
                .is_empty());
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_cancel_after_pre_read_commit_before_release_denies_release() {
            let provider = test_provider();
            let content = b"D31 cancellation-after-pre-read-commit-before-release bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let storage = Arc::new(storage);
            let (binding, issued) = workspace_read_issued_grant(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-revalidation-first-read-start",
            );
            let start = Arc::new(Barrier::new(2));
            let (commit_tx, commit_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let revalidate_storage = Arc::clone(&storage);
            let revalidate_registry = registry.clone();
            let revalidate_session = Arc::clone(&session);
            let revalidate_start = Arc::clone(&start);
            let revalidate_request = protocol::WorkspaceReadRevalidateGrant {
                request_id: "d31-revalidation-first-read-start-request".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-revalidation-first-read-start".to_string(),
                binding: binding.clone(),
                grant: issued,
            };
            let revalidate_thread = thread::spawn(move || {
                revalidate_start.wait();
                let result = revalidate_workspace_read_grant(
                    &revalidate_storage,
                    &revalidate_registry,
                    &revalidate_session,
                    &revalidate_request,
                );
                let returned = result.expect("pre-read authority commit");
                commit_tx
                    .send(returned.clone())
                    .expect("cancellation must observe pre-read commit");
            });
            let cancel_session = Arc::clone(&session);
            let cancel_start = Arc::clone(&start);
            let cancel_thread = thread::spawn(move || {
                cancel_start.wait();
                let revalidated = commit_rx
                    .recv()
                    .expect("cancel-after-pre-read-commit signal");
                assert!(revalidated.used);
                cancel_session
                    .begin_cancellation()
                    .expect("Host cancellation must linearize after pre-read commit");
                release_tx
                    .send(revalidated)
                    .expect("main thread must receive committed grant");
            });
            revalidate_thread.join().expect("revalidation thread");
            cancel_thread.join().expect("cancellation thread");

            let revalidated = release_rx
                .recv()
                .expect("committed grant after cancellation");
            let release_request = protocol::WorkspaceReadReleaseCheck {
                request_id: "d31-revalidation-first-read-start-release".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: "d31-revalidation-first-read-start".to_string(),
                binding,
                grant: revalidated,
                bytes_read: content.len() as u64,
                content_sha256: format!("{:x}", Sha256::digest(content)),
            };
            // The physical bounded read is owned by Vita and is represented
            // here only by its count/hash evidence.  In the precise
            // cancel-after-pre-read-commit-before-release ordering,
            // cancellation must deny Host release, so no confidential bytes
            // can become model-visible.
            let release_result = authorize_workspace_read_release(
                &storage,
                &registry,
                &session,
                &release_request,
                content,
            );
            assert_eq!(
                release_result.unwrap_err(),
                "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
            );
            assert!(session
                .workspace_read_grants
                .lock()
                .expect("workspace read grant lock")
                .is_empty());
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_revoke_first_linearizes_before_workspace_release() {
            let provider = test_provider();
            let content: &'static [u8] = b"D31 revoke-first bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            // Revoke through one independently initialized Host service and
            // release through another to prove that both share the durable
            // database-identity-bound capability gate.
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let request = workspace_read_release_request(
                &session,
                &authority_storage,
                &registry,
                &provider,
                "d31-revoke-first-host-turn",
                content,
            );
            let start = Arc::new(Barrier::new(2));
            let (revoke_done_tx, revoke_done_rx) = mpsc::channel();
            let revoke_storage = Arc::clone(&primary_storage);
            let revoke_registry = registry.clone();
            let revoke_session = session.life_id.clone();
            let revoke_start = Arc::clone(&start);
            let revoke_thread = thread::spawn(move || {
                revoke_start.wait();
                let transition = apply_transition_for_test(
                    &revoke_storage,
                    &revoke_registry,
                    protocol::WORKSPACE_READ_CAPABILITY_ID,
                    false,
                    2,
                    &revoke_session,
                )
                .expect("revoke must commit first");
                revoke_done_tx
                    .send(transition.revision)
                    .expect("release thread must observe revoke commit");
                transition.revision
            });
            let release_storage = Arc::clone(&authority_storage);
            let release_registry = registry.clone();
            let release_session = Arc::clone(&session);
            let release_request = request.clone();
            let release_start = Arc::clone(&start);
            let release_thread = thread::spawn(move || {
                release_start.wait();
                assert_eq!(revoke_done_rx.recv().expect("revoke-first barrier"), 3);
                authorize_workspace_read_release(
                    &release_storage,
                    &release_registry,
                    &release_session,
                    &release_request,
                    content,
                )
            });

            assert_eq!(revoke_thread.join().expect("revoke thread"), 3);
            assert_eq!(
                release_thread.join().expect("release thread"),
                Err("CAPABILITY_ROOT_DISABLED".to_string())
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Revalidated)
            );
            let row = primary_storage
                .find_capability_authorization(
                    &session.life_id,
                    &CapabilityId::try_from(protocol::WORKSPACE_READ_CAPABILITY_ID)
                        .expect("workspace read capability"),
                )
                .expect("authorization row")
                .expect("authorization row exists");
            assert!(!row.enabled);
            assert_eq!(row.revision, 3);
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_workspace_release_first_linearizes_before_revoke() {
            let provider = test_provider();
            let content: &'static [u8] = b"D31 release-first bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, primary_storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let request = workspace_read_release_request(
                &session,
                &authority_storage,
                &registry,
                &provider,
                "d31-release-first-host-turn",
                content,
            );
            let start = Arc::new(Barrier::new(2));
            let (release_done_tx, release_done_rx) = mpsc::channel();
            let release_storage = Arc::clone(&authority_storage);
            let release_registry = registry.clone();
            let release_session = Arc::clone(&session);
            let release_request = request.clone();
            let release_start = Arc::clone(&start);
            let release_thread = thread::spawn(move || {
                release_start.wait();
                let result = authorize_workspace_read_release(
                    &release_storage,
                    &release_registry,
                    &release_session,
                    &release_request,
                    content,
                );
                release_done_tx
                    .send(result.is_ok())
                    .expect("revoke thread must observe release commit");
                result
            });
            let revoke_storage = Arc::clone(&primary_storage);
            let revoke_registry = registry.clone();
            let revoke_session = session.life_id.clone();
            let revoke_start = Arc::clone(&start);
            let revoke_thread = thread::spawn(move || {
                revoke_start.wait();
                assert!(
                    release_done_rx.recv().expect("release-first barrier"),
                    "release must commit before revoke"
                );
                apply_transition_for_test(
                    &revoke_storage,
                    &revoke_registry,
                    protocol::WORKSPACE_READ_CAPABILITY_ID,
                    false,
                    2,
                    &revoke_session,
                )
                .expect("revoke after release")
                .revision
            });

            assert_eq!(release_thread.join().expect("release thread"), Ok(()));
            assert_eq!(revoke_thread.join().expect("revoke thread"), 3);
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );
            let row = primary_storage
                .find_capability_authorization(
                    &session.life_id,
                    &CapabilityId::try_from(protocol::WORKSPACE_READ_CAPABILITY_ID)
                        .expect("workspace read capability"),
                )
                .expect("authorization row")
                .expect("authorization row exists");
            assert!(!row.enabled);
            assert_eq!(row.revision, 3);
            session.retire();
            drop(root);
        }

        fn switch_current_life_for_test_with_persona(storage: &StorageService, persona_id: &str) {
            storage
                .save_life(LifeIdentityRecord {
                    id: "d31-life-b".to_string(),
                    name: "D31 second life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-b-body".to_string(),
                    persona_id: persona_id.to_string(),
                    persona_version: 1,
                })
                .expect("switch current Life");
        }

        fn run_replace_final_fence_ordering(ordering: &'static str) {
            let provider = test_provider();
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (storage_root, primary_storage, registry, enabled_revision) =
                workspace_replace_authority_fixture(&session);
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let host_turn_id = format!("d31-c-replace-{ordering}");
            let (binding, issued, _) = workspace_replace_issued_grant(
                &session,
                &authority_storage,
                &registry,
                &provider,
                &host_turn_id,
            );
            let request = protocol::WorkspaceReplaceRevalidateGrant {
                request_id: format!("d31-c-replace-revalidate-{ordering}"),
                session_id: session.session_id.clone(),
                host_turn_id,
                binding,
                grant: issued.clone(),
            };
            let start = Arc::new(Barrier::new(2));
            let result = match ordering {
                "revoke-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let revoke_storage = Arc::clone(&primary_storage);
                    let revoke_registry = registry.clone();
                    let life_id = session.life_id.clone();
                    let revoke_start = Arc::clone(&start);
                    let revoke_thread = thread::spawn(move || {
                        revoke_start.wait();
                        let transition = apply_transition_for_test(
                            &revoke_storage,
                            &revoke_registry,
                            PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
                            false,
                            enabled_revision,
                            &life_id,
                        )
                        .expect("replace revoke must commit first");
                        done_tx
                            .send(transition.revision)
                            .expect("replace revalidation must observe revoke");
                        transition.revision
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        assert_eq!(done_rx.recv().expect("replace revoke-first signal"), 3);
                        revalidate_workspace_replace_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    assert_eq!(revoke_thread.join().expect("replace revoke thread"), 3);
                    revalidate_thread
                        .join()
                        .expect("replace revalidation thread")
                }
                "fence-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        let result = revalidate_workspace_replace_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        );
                        done_tx
                            .send(result.is_ok())
                            .expect("replace revoke must observe fence commit");
                        result
                    });
                    let revoke_storage = Arc::clone(&primary_storage);
                    let revoke_registry = registry.clone();
                    let life_id = session.life_id.clone();
                    let revoke_start = Arc::clone(&start);
                    let revoke_thread = thread::spawn(move || {
                        revoke_start.wait();
                        assert!(done_rx.recv().expect("replace fence-first signal"));
                        apply_transition_for_test(
                            &revoke_storage,
                            &revoke_registry,
                            PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
                            false,
                            enabled_revision,
                            &life_id,
                        )
                        .expect("replace revoke after fence")
                        .revision
                    });
                    let revalidated = revalidate_thread
                        .join()
                        .expect("replace revalidation thread");
                    assert!(revalidated.is_ok(), "replace final fence must commit first");
                    assert_eq!(revoke_thread.join().expect("replace revoke thread"), 3);
                    revalidated
                }
                "life-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let life_storage = Arc::clone(&primary_storage);
                    let life_start = Arc::clone(&start);
                    let persona_id = "d31-c-replace-persona".to_string();
                    let life_thread = thread::spawn(move || {
                        life_start.wait();
                        switch_current_life_for_test_with_persona(&life_storage, &persona_id);
                        done_tx
                            .send(())
                            .expect("replace revalidation must observe Life switch");
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        done_rx.recv().expect("replace Life-first signal");
                        revalidate_workspace_replace_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    life_thread.join().expect("replace Life thread");
                    revalidate_thread
                        .join()
                        .expect("replace revalidation thread")
                }
                "migration-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let migration_storage = Arc::clone(&primary_storage);
                    let migration_start = Arc::clone(&start);
                    let target = storage_root.path().join("d31-c-replace-migrated");
                    let migration_thread = thread::spawn(move || {
                        migration_start.wait();
                        let migration = migration_storage
                            .migrate_location(target.to_str().expect("migration target"));
                        assert!(migration.success, "{migration:?}");
                        assert!(migration.restart_required);
                        done_tx
                            .send(())
                            .expect("replace revalidation must observe migration");
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        done_rx.recv().expect("replace migration-first signal");
                        revalidate_workspace_replace_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    migration_thread.join().expect("replace migration thread");
                    revalidate_thread
                        .join()
                        .expect("replace revalidation thread")
                }
                other => panic!("unknown replace final-fence ordering: {other}"),
            };
            match ordering {
                "revoke-first" => {
                    assert_eq!(result, Err("CAPABILITY_ROOT_DISABLED".to_string()));
                    let permitted_mutation_count = session
                        .workspace_replace_grants
                        .lock()
                        .expect("replace grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == WorkspaceReplaceGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "replace modifying syscall count"
                    );
                }
                "life-first" => {
                    assert_eq!(result, Err(LIFE_RESTART_REQUIRED.to_string()));
                    let permitted_mutation_count = session
                        .workspace_replace_grants
                        .lock()
                        .expect("replace grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == WorkspaceReplaceGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "replace modifying syscall count"
                    );
                }
                "migration-first" => {
                    assert_eq!(
                        result,
                        Err(CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string())
                    );
                    let permitted_mutation_count = session
                        .workspace_replace_grants
                        .lock()
                        .expect("replace grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == WorkspaceReplaceGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "replace modifying syscall count"
                    );
                }
                "fence-first" => {
                    assert!(result.is_ok(), "replace final fence must commit first");
                    assert_eq!(
                        session
                            .workspace_replace_grants
                            .lock()
                            .expect("replace grant lock")
                            .get(&issued.grant_id)
                            .map(|state| (state.phase, state.grant.used)),
                        Some((WorkspaceReplaceGrantPhase::Revalidated, true))
                    );
                }
                _ => unreachable!(),
            }
            if ordering != "fence-first" {
                assert_eq!(
                    session
                        .workspace_replace_grants
                        .lock()
                        .expect("replace grant lock")
                        .get(&issued.grant_id)
                        .map(|state| (state.phase, state.grant.used)),
                    Some((WorkspaceReplaceGrantPhase::Issued, false))
                );
            }
            session.retire();
            drop(storage_root);
        }

        #[test]
        fn d31_c_replace_final_fence_linearization_matrix_has_zero_denied_mutation() {
            for ordering in [
                "revoke-first",
                "fence-first",
                "life-first",
                "migration-first",
            ] {
                run_replace_final_fence_ordering(ordering);
            }
        }

        fn run_recovery_final_fence_ordering(ordering: &'static str) {
            let (session, _receiver) = test_session();
            let (storage_root, primary_storage, registry, enabled_revision) =
                recovery_authority_fixture(&session);
            let authority_storage = independently_initialized_storage(&primary_storage);
            assert_independent_storage_gate_identities(&primary_storage, &authority_storage);
            let primary_storage = Arc::new(primary_storage);
            let authority_storage = Arc::new(authority_storage);
            let (binding, issued, _) =
                recovery_issued_grant(&session, &authority_storage, &registry);
            let request = protocol::RecoveryRevalidateGrant {
                request_id: format!("d31-c-recovery-revalidate-{ordering}"),
                session_id: session.session_id.clone(),
                recovery_action_id: binding.recovery_action_id.clone(),
                binding,
                grant: issued.clone(),
            };
            let start = Arc::new(Barrier::new(2));
            let result = match ordering {
                "revoke-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let revoke_storage = Arc::clone(&primary_storage);
                    let revoke_registry = registry.clone();
                    let life_id = session.life_id.clone();
                    let revoke_start = Arc::clone(&start);
                    let revoke_thread = thread::spawn(move || {
                        revoke_start.wait();
                        let transition = apply_transition_for_test(
                            &revoke_storage,
                            &revoke_registry,
                            PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
                            false,
                            enabled_revision,
                            &life_id,
                        )
                        .expect("recovery revoke must commit first");
                        done_tx
                            .send(transition.revision)
                            .expect("recovery revalidation must observe revoke");
                        transition.revision
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        assert_eq!(done_rx.recv().expect("recovery revoke-first signal"), 3);
                        revalidate_recovery_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    assert_eq!(revoke_thread.join().expect("recovery revoke thread"), 3);
                    revalidate_thread
                        .join()
                        .expect("recovery revalidation thread")
                }
                "fence-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        let result = revalidate_recovery_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        );
                        done_tx
                            .send(result.is_ok())
                            .expect("recovery revoke must observe fence commit");
                        result
                    });
                    let revoke_storage = Arc::clone(&primary_storage);
                    let revoke_registry = registry.clone();
                    let life_id = session.life_id.clone();
                    let revoke_start = Arc::clone(&start);
                    let revoke_thread = thread::spawn(move || {
                        revoke_start.wait();
                        assert!(done_rx.recv().expect("recovery fence-first signal"));
                        apply_transition_for_test(
                            &revoke_storage,
                            &revoke_registry,
                            PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
                            false,
                            enabled_revision,
                            &life_id,
                        )
                        .expect("recovery revoke after fence")
                        .revision
                    });
                    let revalidated = revalidate_thread
                        .join()
                        .expect("recovery revalidation thread");
                    assert!(
                        revalidated.is_ok(),
                        "recovery final fence must commit first"
                    );
                    assert_eq!(revoke_thread.join().expect("recovery revoke thread"), 3);
                    revalidated
                }
                "life-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let life_storage = Arc::clone(&primary_storage);
                    let life_start = Arc::clone(&start);
                    let persona_id = "d31-c-recovery-persona".to_string();
                    let life_thread = thread::spawn(move || {
                        life_start.wait();
                        switch_current_life_for_test_with_persona(&life_storage, &persona_id);
                        done_tx
                            .send(())
                            .expect("recovery revalidation must observe Life switch");
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        done_rx.recv().expect("recovery Life-first signal");
                        revalidate_recovery_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    life_thread.join().expect("recovery Life thread");
                    revalidate_thread
                        .join()
                        .expect("recovery revalidation thread")
                }
                "migration-first" => {
                    let (done_tx, done_rx) = mpsc::channel();
                    let migration_storage = Arc::clone(&primary_storage);
                    let migration_start = Arc::clone(&start);
                    let target = storage_root.path().join("d31-c-recovery-migrated");
                    let migration_thread = thread::spawn(move || {
                        migration_start.wait();
                        let migration = migration_storage
                            .migrate_location(target.to_str().expect("migration target"));
                        assert!(migration.success, "{migration:?}");
                        assert!(migration.restart_required);
                        done_tx
                            .send(())
                            .expect("recovery revalidation must observe migration");
                    });
                    let revalidate_storage = Arc::clone(&authority_storage);
                    let revalidate_registry = registry.clone();
                    let revalidate_session = Arc::clone(&session);
                    let revalidate_request = request.clone();
                    let revalidate_start = Arc::clone(&start);
                    let revalidate_thread = thread::spawn(move || {
                        revalidate_start.wait();
                        done_rx.recv().expect("recovery migration-first signal");
                        revalidate_recovery_grant(
                            &revalidate_storage,
                            &revalidate_registry,
                            &revalidate_session,
                            &revalidate_request,
                        )
                    });
                    migration_thread.join().expect("recovery migration thread");
                    revalidate_thread
                        .join()
                        .expect("recovery revalidation thread")
                }
                other => panic!("unknown recovery final-fence ordering: {other}"),
            };
            match ordering {
                "revoke-first" => {
                    assert_eq!(result, Err("CAPABILITY_ROOT_DISABLED".to_string()));
                    let permitted_mutation_count = session
                        .recovery_grants
                        .lock()
                        .expect("recovery grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == RecoveryGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "recovery modifying syscall count"
                    );
                }
                "life-first" => {
                    assert_eq!(result, Err(LIFE_RESTART_REQUIRED.to_string()));
                    let permitted_mutation_count = session
                        .recovery_grants
                        .lock()
                        .expect("recovery grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == RecoveryGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "recovery modifying syscall count"
                    );
                }
                "migration-first" => {
                    assert_eq!(
                        result,
                        Err(CAPABILITY_AUTHORITY_RESTART_REQUIRED.to_string())
                    );
                    let permitted_mutation_count = session
                        .recovery_grants
                        .lock()
                        .expect("recovery grant lock")
                        .get(&issued.grant_id)
                        .is_some_and(|state| state.phase == RecoveryGrantPhase::Revalidated)
                        as u8;
                    assert_eq!(
                        permitted_mutation_count, 0,
                        "recovery modifying syscall count"
                    );
                }
                "fence-first" => {
                    assert!(result.is_ok(), "recovery final fence must commit first");
                    assert_eq!(
                        session
                            .recovery_grants
                            .lock()
                            .expect("recovery grant lock")
                            .get(&issued.grant_id)
                            .map(|state| (state.phase, state.grant.used)),
                        Some((RecoveryGrantPhase::Revalidated, true))
                    );
                }
                _ => unreachable!(),
            }
            if ordering != "fence-first" {
                assert_eq!(
                    session
                        .recovery_grants
                        .lock()
                        .expect("recovery grant lock")
                        .get(&issued.grant_id)
                        .map(|state| (state.phase, state.grant.used)),
                    Some((RecoveryGrantPhase::Issued, false))
                );
            }
            session.retire();
            drop(storage_root);
        }

        #[test]
        fn d31_c_recovery_final_fence_linearization_matrix_has_zero_denied_mutation() {
            for ordering in [
                "revoke-first",
                "fence-first",
                "life-first",
                "migration-first",
            ] {
                run_recovery_final_fence_ordering(ordering);
            }
        }

        #[test]
        fn d31_c_recovery_grant_replay_is_denied_after_fence_commit() {
            let (session, _receiver) = test_session();
            let (root, storage, registry, _) = recovery_authority_fixture(&session);
            let storage = Arc::new(storage);
            let (binding, issued, _) = recovery_issued_grant(&session, &storage, &registry);
            let request = protocol::RecoveryRevalidateGrant {
                request_id: "d31-c-recovery-replay-first".to_string(),
                session_id: session.session_id.clone(),
                recovery_action_id: binding.recovery_action_id.clone(),
                binding: binding.clone(),
                grant: issued.clone(),
            };
            let first = revalidate_recovery_grant(&storage, &registry, &session, &request)
                .expect("first recovery final fence");
            assert!(first.used);
            let replay = revalidate_recovery_grant(&storage, &registry, &session, &request)
                .expect_err("recovery grant replay must be denied");
            assert_eq!(replay, "RECOVERY_ACTION_NOT_ACTIVE");
            let permitted_mutation_count = session
                .recovery_grants
                .lock()
                .expect("recovery grant lock")
                .get(&issued.grant_id)
                .is_some_and(|state| state.phase == RecoveryGrantPhase::Revalidated)
                as u8;
            assert_eq!(
                permitted_mutation_count, 1,
                "first recovery mutation admission"
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_cancel_first_denies_and_cannot_erase_committed_release() {
            let provider = test_provider();
            let content: &'static [u8] = b"D31 cancel-property bytes";

            let (cancel_session, _receiver) = test_session_with_provider(provider.clone());
            let (cancel_root, cancel_storage, cancel_registry) =
                synthetic_multi_capability_fixture(&cancel_session, None, Some(true));
            let cancel_request = workspace_read_release_request(
                &cancel_session,
                &cancel_storage,
                &cancel_registry,
                &provider,
                "d31-cancel-first-host-turn",
                content,
            );
            cancel_session
                .begin_cancellation()
                .expect("cancel active turn");
            assert_eq!(
                authorize_workspace_read_release(
                    &cancel_storage,
                    &cancel_registry,
                    &cancel_session,
                    &cancel_request,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
            );
            assert!(cancel_session
                .workspace_read_grants
                .lock()
                .expect("cancel grant lock")
                .is_empty());
            cancel_session.retire();
            drop(cancel_root);

            let (release_session, _receiver) = test_session_with_provider(provider.clone());
            let (release_root, release_storage, release_registry) =
                synthetic_multi_capability_fixture(&release_session, None, Some(true));
            let release_request = workspace_read_release_request(
                &release_session,
                &release_storage,
                &release_registry,
                &provider,
                "d31-cancel-after-release-host-turn",
                content,
            );
            assert_eq!(
                authorize_workspace_read_release(
                    &release_storage,
                    &release_registry,
                    &release_session,
                    &release_request,
                    content,
                ),
                Ok(())
            );
            release_session
                .begin_cancellation()
                .expect("cancel after release");
            assert_eq!(
                release_session
                    .workspace_read_grants
                    .lock()
                    .expect("release grant lock")
                    .get(&release_request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Released)
            );
            release_session.retire();
            drop(release_root);
        }

        #[test]
        fn d31_release_contract_rechecks_provenance_and_evidence() {
            let provider = test_provider();
            let content = b"D31 confidential workspace bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-provenance-host-turn",
                content,
            );

            let mut wrong_provider = request.clone();
            wrong_provider.binding.provider_binding_hash = "c".repeat(64);
            wrong_provider.grant.binding = wrong_provider.binding.clone();
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_provider,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
            );

            let mut wrong_grant_id = request.clone();
            wrong_grant_id.request_id = "wrong-grant-id".to_string();
            wrong_grant_id.grant.grant_id = "fabricated-read-grant".to_string();
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_grant_id,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_GRANT_NOT_FOUND"
            );

            let mut wrong_confirmation = request.clone();
            wrong_confirmation.request_id = "wrong-confirmation".to_string();
            wrong_confirmation.grant.confirmation_id = "fabricated-confirmation".to_string();
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_confirmation,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH"
            );

            let mut wrong_binding = request.clone();
            wrong_binding.request_id = "wrong-binding".to_string();
            wrong_binding.binding.relative_path = "notes/other.txt".to_string();
            wrong_binding.grant.binding = wrong_binding.binding.clone();
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_binding,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH"
            );

            let mut wrong_revision = request.clone();
            wrong_revision.request_id = "wrong-revision".to_string();
            wrong_revision.grant.authorization_revision = 1;
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_revision,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_GRANT_PROVENANCE_MISMATCH"
            );

            let mut wrong_content = request.clone();
            wrong_content.content_sha256 = "d".repeat(64);
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_content,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_CONTENT_EVIDENCE_MISMATCH"
            );

            let mut wrong_byte_count = request.clone();
            wrong_byte_count.bytes_read += 1;
            assert_eq!(
                authorize_workspace_read_release(
                    &storage,
                    &registry,
                    &session,
                    &wrong_byte_count,
                    content,
                )
                .unwrap_err(),
                "WORKSPACE_READ_CONTENT_EVIDENCE_MISMATCH"
            );

            let mut expired = request.clone();
            {
                let mut grants = session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock");
                let state = grants
                    .get_mut(&request.grant.grant_id)
                    .expect("revalidated grant");
                state.grant.expires_at_unix_ms = state.grant.issued_at_unix_ms;
            }
            expired.grant.expires_at_unix_ms = expired.grant.issued_at_unix_ms;
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &expired, content)
                    .unwrap_err(),
                "WORKSPACE_READ_GRANT_EXPIRED"
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_release_fabricated_grant_and_revision_revocation_are_denied() {
            let provider = test_provider();
            let content = b"D31 confidential workspace bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-revoke-host-turn",
                content,
            );
            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                protocol::WORKSPACE_READ_CAPABILITY_ID,
                false,
                2,
                &session.life_id,
            )
            .expect("D31 synthetic root revoke");
            assert_eq!(disabled.revision, 3);
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &request, content)
                    .unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );
            assert_eq!(
                session
                    .workspace_read_grants
                    .lock()
                    .expect("workspace read grant lock")
                    .get(&request.grant.grant_id)
                    .map(|state| state.phase),
                Some(WorkspaceReadGrantPhase::Revalidated)
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d31_release_contract_denies_after_turn_cancellation() {
            let provider = test_provider();
            let content = b"D31 confidential workspace bytes";
            let (session, _receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry) =
                synthetic_multi_capability_fixture(&session, None, Some(true));
            let request = workspace_read_release_request(
                &session,
                &storage,
                &registry,
                &provider,
                "d31-cancelled-release-host-turn",
                content,
            );
            session
                .begin_cancellation()
                .expect("cancel active Host turn");
            assert!(session
                .workspace_read_grants
                .lock()
                .expect("workspace read grant lock")
                .is_empty());
            assert_eq!(
                authorize_workspace_read_release(&storage, &registry, &session, &request, content)
                    .unwrap_err(),
                "WORKSPACE_READ_DISCLOSURE_TURN_NOT_ACTIVE"
            );
            session.retire();
            drop(root);
        }

        #[test]
        fn d30_production_enable_admits_exactly_one_start_turn() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, enabled_revision) = authority_fixture(&session);
            assert_eq!(enabled_revision, 2);
            let coordinator = VitaSidecarCoordinator::new(Arc::new(storage), registry);
            *coordinator
                .test_provider_override
                .lock()
                .expect("provider override lock") = Some(provider);
            coordinator.install_test_session(Arc::clone(&session));

            let response = coordinator
                .start_turn(VitaTurnStartRequest {
                    prompt: "inspect governed status".to_string(),
                })
                .expect("D30-enabled Host turn admission");
            assert!(response.accepted);
            let message = receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("one StartTurn frame");
            assert!(matches!(
                message,
                HostMessage::StartTurn(protocol::StartTurn { turn_id, .. })
                    if turn_id == response.turn_id
            ));
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Active(_))
            ));
            session.retire();
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_running_session_a_rejects_current_life_b_before_process_work() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, _enabled_revision) = authority_fixture(&session);
            storage
                .save_life(LifeIdentityRecord {
                    id: "life-b".to_string(),
                    name: "D30-C second life".to_string(),
                    created_at: "2026-09-12T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d29h9-r3-body".to_string(),
                    persona_id: "d29h9-r3-persona".to_string(),
                    persona_version: 1,
                })
                .expect("switch current Life");

            let coordinator = VitaSidecarCoordinator::new(Arc::new(storage), registry);
            *coordinator
                .test_provider_override
                .lock()
                .expect("provider override lock") = Some(provider);
            coordinator.install_test_session(Arc::clone(&session));

            assert_eq!(
                coordinator
                    .start_turn(VitaTurnStartRequest {
                        prompt: "must bind to current Life".to_string(),
                    })
                    .unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
            assert!(session
                .active_turn_id
                .lock()
                .expect("active turn lock")
                .is_none());
            assert!(receiver.try_recv().is_err());
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_start_turn_barrier_switch_first_emits_zero_frames() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, _enabled_revision) = authority_fixture(&session);
            let coordinator = Arc::new(VitaSidecarCoordinator::new(Arc::new(storage), registry));
            *coordinator
                .test_provider_override
                .lock()
                .expect("provider override lock") = Some(provider);
            coordinator.install_test_session(Arc::clone(&session));

            let start = Arc::new(Barrier::new(2));
            let (switch_done_tx, switch_done_rx) = mpsc::channel();
            let switch_storage = Arc::clone(&coordinator.authority_storage);
            let switch_start = Arc::clone(&start);
            let switch_thread = thread::spawn(move || {
                switch_start.wait();
                switch_storage
                    .save_life(LifeIdentityRecord {
                        id: "life-b".to_string(),
                        name: "D30-C second life".to_string(),
                        created_at: "2026-09-12T00:00:00.000Z".to_string(),
                        version: 1,
                        body_id: "d29h9-r3-body".to_string(),
                        persona_id: "d29h9-r3-persona".to_string(),
                        persona_version: 1,
                    })
                    .expect("switch current Life first");
                switch_done_tx.send(()).expect("switch completion");
            });
            let admission_coordinator = Arc::clone(&coordinator);
            let admission_start = Arc::clone(&start);
            let admission_thread = thread::spawn(move || {
                admission_start.wait();
                switch_done_rx.recv().expect("switch-first barrier");
                admission_coordinator.start_turn(VitaTurnStartRequest {
                    prompt: "must bind to current Life".to_string(),
                })
            });

            switch_thread.join().expect("switch thread");
            assert_eq!(
                admission_thread
                    .join()
                    .expect("admission thread")
                    .unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
            assert!(receiver.try_recv().is_err());
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_start_turn_barrier_admission_first_remains_bound_to_life_a() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, _enabled_revision) = authority_fixture(&session);
            let coordinator = Arc::new(VitaSidecarCoordinator::new(Arc::new(storage), registry));
            *coordinator
                .test_provider_override
                .lock()
                .expect("provider override lock") = Some(provider);
            coordinator.install_test_session(Arc::clone(&session));

            let start = Arc::new(Barrier::new(2));
            let (admission_done_tx, admission_done_rx) = mpsc::channel();
            let admission_coordinator = Arc::clone(&coordinator);
            let admission_start = Arc::clone(&start);
            let admission_thread = thread::spawn(move || {
                admission_start.wait();
                let result = admission_coordinator.start_turn(VitaTurnStartRequest {
                    prompt: "bind Life A".to_string(),
                });
                admission_done_tx
                    .send(result.is_ok())
                    .expect("admission completion");
                result
            });
            let switch_storage = Arc::clone(&coordinator.authority_storage);
            let switch_start = Arc::clone(&start);
            let switch_thread = thread::spawn(move || {
                switch_start.wait();
                assert!(
                    admission_done_rx.recv().expect("admission-first barrier"),
                    "Life A admission must commit first"
                );
                switch_storage
                    .save_life(LifeIdentityRecord {
                        id: "life-b".to_string(),
                        name: "D30-C second life".to_string(),
                        created_at: "2026-09-12T00:00:00.000Z".to_string(),
                        version: 1,
                        body_id: "d29h9-r3-body".to_string(),
                        persona_id: "d29h9-r3-persona".to_string(),
                        persona_version: 1,
                    })
                    .expect("switch current Life after admission");
            });

            let admitted = admission_thread
                .join()
                .expect("admission thread")
                .expect("Life A admission");
            switch_thread.join().expect("switch thread");
            assert!(admitted.accepted);
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)),
                Ok(HostMessage::StartTurn(protocol::StartTurn { .. }))
            ));
            // The active turn remains bound to Life A; a later admission after
            // the switch is rejected by the current-Life fence, not
            // transplanted to Life B.
            assert_eq!(
                coordinator
                    .start_turn(VitaTurnStartRequest {
                        prompt: "must not transplant".to_string(),
                    })
                    .unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            session.retire();
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_disabled_admission_emits_zero_start_turn_frames() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, enabled_revision) = authority_fixture(&session);
            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.revision, 3);
            let coordinator = VitaSidecarCoordinator::new(Arc::new(storage), registry);
            *coordinator
                .test_provider_override
                .lock()
                .expect("provider override lock") = Some(provider);
            coordinator.install_test_session(Arc::clone(&session));

            assert_eq!(
                coordinator
                    .start_turn(VitaTurnStartRequest {
                        prompt: "must not start".to_string(),
                    })
                    .unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
            assert!(session
                .active_turn_id
                .lock()
                .expect("active turn lock")
                .is_none());
            assert!(receiver.try_recv().is_err());
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_disable_denies_actual_decide_pending_path() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, enabled_revision) = authority_fixture(&session);
            let host_turn_id = "d30-direct-pending-host".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let binding = test_binding_for(
                &session.session_id,
                "d30-direct-pending-codex",
                "call-direct-pending",
            );
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d30-direct-pending-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("authority evaluation");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    ..
                }) if revision == enabled_revision
            ));
            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "d30-direct-pending-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id,
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding,
                },
            )
            .expect("pending confirmation");
            let pending_id = session
                .pending_summary()
                .expect("real pending entry")
                .pending_id;
            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.revision, 3);

            let coordinator = VitaSidecarCoordinator::new(Arc::new(storage), registry);
            coordinator.install_test_session(Arc::clone(&session));
            assert_eq!(
                coordinator
                    .decide_pending(pending_id, ConfirmationDecision::Confirm)
                    .unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("deny reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                    ..
                })
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            session.retire();
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_real_issue_grant_then_revoke_denies_revalidation() {
            let provider = test_provider();
            let (session, receiver) = test_session_with_provider(provider.clone());
            let (root, storage, registry, enabled_revision) = authority_fixture(&session);
            let storage = Arc::new(storage);
            let host_turn_id = "d30-real-grant-host".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let binding = test_binding_for(
                &session.session_id,
                "d30-real-grant-codex",
                "call-real-grant",
            );
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d30-real-grant-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("authority evaluation");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    ..
                }) if revision == enabled_revision
            ));
            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "d30-real-grant-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding.clone(),
                },
            )
            .expect("pending confirmation");
            let pending_id = session
                .pending_summary()
                .expect("real pending entry")
                .pending_id;
            let coordinator = VitaSidecarCoordinator::new(Arc::clone(&storage), registry.clone());
            coordinator.install_test_session(Arc::clone(&session));
            coordinator
                .decide_pending(pending_id, ConfirmationDecision::Confirm)
                .expect("real production confirmation");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("confirmation reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Confirm,
                    authorization_revision: Some(revision),
                    ..
                }) if revision == enabled_revision
            ));
            assert_eq!(session.approvals.lock().expect("approval lock").len(), 1);

            handle_issue_grant(
                &session,
                &storage,
                &registry,
                IssueGrant {
                    request_id: "d30-real-grant-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                    authorization_revision: enabled_revision,
                },
            )
            .expect("real Host ProcessGrant issuance");
            let grant = match receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("grant reply")
            {
                HostMessage::GrantIssued(GrantIssued {
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                    ..
                }) => grant,
                other => panic!("unexpected grant reply: {other:?}"),
            };
            assert_eq!(grant.authorization_revision, 2);

            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.revision, 3);
            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "d30-real-grant-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id,
                    binding,
                    grant,
                },
            )
            .expect("real final revalidation reply");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("revalidation reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "CAPABILITY_ROOT_DISABLED"
            ));
            session.retire();
            drop(coordinator);
            drop(root);
        }

        #[test]
        fn d30_disable_is_seen_by_final_grant_revalidation() {
            let (session, receiver) = test_session();
            let (_root, storage, registry, enabled_revision) = authority_fixture(&session);
            let provider = test_provider();
            let host_turn_id = "d30-revoke-host-turn".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let binding = test_binding_for(&session.session_id, "d30-revoke-codex", "call-revoke");
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d30-revoke-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("authority evaluation");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    ..
                }) if revision == enabled_revision
            ));
            let mut grant = test_grant(&session.session_id, "d30-revoke-grant", binding.clone());
            grant.authorization_revision = enabled_revision;
            session.grants.lock().expect("grant lock").insert(
                grant.grant_id.clone(),
                HostStoredGrant {
                    host_turn_id: host_turn_id.clone(),
                    grant: grant.clone(),
                },
            );

            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.revision, enabled_revision + 1);
            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "d30-revoke-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id,
                    binding,
                    grant,
                },
            )
            .expect("revoked grant is answered");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("revalidation reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "CAPABILITY_ROOT_DISABLED"
            ));
            assert_eq!(session.grants.lock().expect("grant lock").len(), 1);
        }

        #[test]
        fn d30_disable_rechecks_pending_confirmation_before_approval() {
            let (session, receiver) = test_session();
            let (_root, storage, registry, enabled_revision) = authority_fixture(&session);
            let provider = test_provider();
            let host_turn_id = "d30-pending-host-turn".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let binding =
                test_binding_for(&session.session_id, "d30-pending-codex", "call-pending");
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "d30-pending-authority".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("authority evaluation");
            let _ = receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("authority reply");
            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "d30-pending-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id,
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding,
                },
            )
            .expect("pending confirmation");
            let pending_id = session
                .pending_summary()
                .expect("pending summary")
                .pending_id;
            let pending = take_pending(&session, &pending_id).expect("pending action");

            let disabled = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_GIT_STATUS_CAPABILITY_ID,
                false,
                enabled_revision,
                &session.life_id,
            )
            .expect("D30 production disable");
            assert_eq!(disabled.revision, enabled_revision + 1);
            // `decide_pending` uses this same fresh read before minting an
            // approval; a stale preflight cannot authorize the confirmation.
            assert_eq!(
                current_workspace_revision(&storage, &registry, &session, &pending.binding)
                    .unwrap_err(),
                "CAPABILITY_ROOT_DISABLED"
            );
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(receiver.try_recv().is_err());
        }

        fn test_session() -> (Arc<HostSessionState>, mpsc::Receiver<HostMessage>) {
            test_session_for_life("life")
        }

        fn test_session_with_provider(
            provider: protocol::ProviderConfiguration,
        ) -> (Arc<HostSessionState>, mpsc::Receiver<HostMessage>) {
            test_session_for_life_and_provider("life", Some(provider))
        }

        fn test_session_for_life(
            life_id: &str,
        ) -> (Arc<HostSessionState>, mpsc::Receiver<HostMessage>) {
            test_session_for_life_and_provider(life_id, None)
        }

        fn test_session_for_life_and_provider(
            life_id: &str,
            provider: Option<protocol::ProviderConfiguration>,
        ) -> (Arc<HostSessionState>, mpsc::Receiver<HostMessage>) {
            let (sender, receiver) = mpsc::channel();
            let session = Arc::new(HostSessionState {
                session_id: "session-test".to_string(),
                life_id: life_id.to_string(),
                task_id: "task".to_string(),
                workspace_identity: "workspace".to_string(),
                cargo_profile: Some(test_cargo_profile_evidence("workspace")),
                app_data_root_retained: None,
                provider,
                writer: Mutex::new(None),
                pending: Mutex::new(HashMap::new()),
                workspace_read_pending: Mutex::new(HashMap::new()),
                workspace_replace_pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                workspace_read_approvals: Mutex::new(HashMap::new()),
                workspace_read_grants: Mutex::new(HashMap::new()),
                workspace_replace_approvals: Mutex::new(HashMap::new()),
                workspace_replace_grants: Mutex::new(HashMap::new()),
                recovery_pending: Mutex::new(HashMap::new()),
                recovery_scan_pending: Mutex::new(HashMap::new()),
                recovery_actions: Mutex::new(HashMap::new()),
                recovery_approvals: Mutex::new(HashMap::new()),
                recovery_grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                turn_authority: Mutex::new(HostTurnAuthority::Idle),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                recovery_result: Mutex::new(None),
                #[cfg(feature = "d32-a-host-canary")]
                canary_control: None,
                test_outbound: Mutex::new(Some(sender)),
            });
            (session, receiver)
        }

        fn install_test_pending(
            session: &Arc<HostSessionState>,
            pending_id: &str,
            request_id: &str,
            expires_at_unix_ms: u64,
        ) {
            let pending = PendingAction {
                pending_id: pending_id.to_string(),
                request_id: request_id.to_string(),
                host_turn_id: "turn".to_string(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                workspace_summary: "workspace".to_string(),
                expires_at_unix_ms,
                binding: test_binding(&session.session_id),
            };
            let ticket = ExpiryTicket::for_pending(&session.session_id, &pending);
            session
                .pending
                .lock()
                .expect("pending lock")
                .insert(pending_id.to_string(), pending);
            session.expiry.schedule(ticket);
        }

        #[test]
        fn host_turn_authority_cancel_wins_before_credential_decision() {
            let (session, _receiver) = test_session();
            let provider = test_provider();
            let turn_id = "turn-authority-race".to_string();
            let binding =
                protocol::ProviderBinding::derive(&session.session_id, &turn_id, &provider)
                    .expect("test provider binding");
            session
                .begin_turn(turn_id.clone(), provider, binding.clone())
                .expect("active turn");

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let cancelled = {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    session.begin_cancellation().expect("cancel decision")
                })
            };
            barrier.wait();
            let cancelled_turn = cancelled
                .join()
                .expect("cancel race worker")
                .expect("cancellation won");
            assert_eq!(cancelled_turn, turn_id);
            assert!(!session.active_authority_matches(&turn_id, &binding));
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Cancelling(_))
            ));
            assert!(session
                .begin_turn(
                    "turn-blocked-while-cancelling".to_string(),
                    test_provider(),
                    protocol::ProviderBinding::derive(
                        &session.session_id,
                        "turn-blocked-while-cancelling",
                        &test_provider(),
                    )
                    .expect("blocked binding"),
                )
                .is_err());

            // A late credential request is denied by the same fence and
            // cannot be made current by the old projected active_turn_id.
            assert!(!session.active_authority_matches(&turn_id, &binding));
            assert!(session.accept_turn_state(&turn_id, protocol::TurnPhase::Cancelled));
            assert!(session
                .begin_turn(
                    "turn-after-cancel".to_string(),
                    test_provider(),
                    protocol::ProviderBinding::derive(
                        &session.session_id,
                        "turn-after-cancel",
                        &test_provider(),
                    )
                    .expect("new binding"),
                )
                .is_ok());
        }

        #[test]
        fn host_turn_authority_credential_decision_can_precede_cancel() {
            let (session, _receiver) = test_session();
            let provider = test_provider();
            let turn_id = "turn-credential-first".to_string();
            let binding =
                protocol::ProviderBinding::derive(&session.session_id, &turn_id, &provider)
                    .expect("test provider binding");
            session
                .begin_turn(turn_id.clone(), provider, binding.clone())
                .expect("active turn");

            let locked = Arc::new(std::sync::Barrier::new(3));
            let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            let credential = {
                let session = Arc::clone(&session);
                let locked = Arc::clone(&locked);
                let release = Arc::clone(&release);
                thread::spawn(move || {
                    let authority = session.turn_authority.lock().expect("authority lock");
                    assert!(matches!(*authority, HostTurnAuthority::Active(_)));
                    locked.wait();
                    let (released, wake) = &*release;
                    let mut released = released.lock().expect("release lock");
                    while !*released {
                        released = wake.wait(released).expect("release wait");
                    }
                    // Holding the authority mutex models the credential
                    // decision/reply write: cancellation cannot win before it
                    // is released.
                    true
                })
            };
            let cancel = {
                let session = Arc::clone(&session);
                let locked = Arc::clone(&locked);
                thread::spawn(move || {
                    locked.wait();
                    session.begin_cancellation().expect("cancel decision")
                })
            };
            locked.wait();
            {
                let (released, wake) = &*release;
                *released.lock().expect("release lock") = true;
                wake.notify_one();
            }
            assert!(credential.join().expect("credential worker"));
            assert_eq!(cancel.join().expect("cancel worker"), Some(turn_id));
        }

        #[test]
        fn late_confirmation_is_cancelled_after_host_turn_fence() {
            let (session, receiver) = test_session();
            let provider = test_provider();
            let host_turn_id = "turn-h8-late".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active turn");
            session
                .begin_cancellation()
                .expect("cancellation decision")
                .expect("turn was active");

            let request = ConfirmationRequired {
                request_id: "late-confirmation".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id,
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                workspace_summary: "workspace".to_string(),
                expires_at_unix_ms: unix_millis().saturating_add(5_000),
                binding: test_binding(&session.session_id),
            };
            handle_confirmation_required(&session, request).expect("late request is denied");
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("cancellation reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Cancel,
                    ..
                })
            ));
            session.retire();
        }

        #[test]
        fn binding_key_is_not_a_frontend_grant_or_revision() {
            let binding = ProcessBinding {
                session_id: "s".to_string(),
                life_id: "l".to_string(),
                task_id: "t".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                program_id: PROGRAM_ID.to_string(),
                executable_identity: "v1f1".to_string(),
                executable_sha256: "0".repeat(64),
                argv_hash: "1".repeat(64),
                argv_count: 1,
                working_directory_identity: "v1f2".to_string(),
                environment_policy_hash: "2".repeat(64),
                stdout_bound: 1,
                stderr_bound: 1,
                timeout_ms: 1,
                tool_call_id: "call".to_string(),
                turn_id: "turn".to_string(),
                workspace_root_identity: "v1f3".to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                git_metadata_fence_hash: "3".repeat(64),
            };
            assert_eq!(binding_key(&binding), "call:turn");
        }

        #[test]
        fn d32_cargo_binding_requires_the_fixed_non_git_marker() {
            let (session, _receiver) = test_session();
            let mut binding = test_binding(&session.session_id);
            binding.capability_id = PRODUCTION_CARGO_CHECK_CAPABILITY_ID.to_string();
            binding.program_id = CARGO_PROGRAM_ID.to_string();
            binding.profile_id = PRODUCTION_CARGO_CHECK_PROFILE_ID.to_string();
            binding.argv_hash = CARGO_ARGV_HASH.to_string();
            binding.argv_count = 2;
            binding.working_directory_identity = session.workspace_identity.clone();
            binding.workspace_root_identity = session.workspace_identity.clone();
            binding.stdout_bound = 65_536;
            binding.stderr_bound = 65_536;
            binding.timeout_ms = 120_000;
            binding.environment_policy_hash = CARGO_ENVIRONMENT_POLICY_HASH.to_string();
            binding.git_metadata_fence_hash = CARGO_NO_GIT_METADATA_FENCE.to_string();
            assert!(validate_binding(&session, &binding).is_ok());

            binding.git_metadata_fence_hash = "0".repeat(64);
            assert!(validate_binding(&session, &binding).is_err());
            binding.git_metadata_fence_hash = CARGO_NO_GIT_METADATA_FENCE.to_string();
            binding.argv_count = 1;
            assert!(validate_binding(&session, &binding).is_err());
            binding.argv_count = 2;
            binding.environment_policy_hash = "0".repeat(64);
            assert!(validate_binding(&session, &binding).is_err());
            binding.environment_policy_hash = CARGO_ENVIRONMENT_POLICY_HASH.to_string();
            binding.executable_identity = "tampered".to_string();
            assert!(validate_binding(&session, &binding).is_err());
            binding.executable_identity = "v1f1".to_string();
            binding.executable_sha256 = "f".repeat(64);
            assert!(validate_binding(&session, &binding).is_err());
            binding.executable_sha256 = "0".repeat(64);
            binding.working_directory_identity = "tampered".to_string();
            assert!(validate_binding(&session, &binding).is_err());
        }

        #[test]
        fn d32_revalidation_life_fence_is_read_after_an_external_life_switch() {
            let (session, _receiver) = test_session();
            let (_root, storage, _registry, _revision) = authority_fixture(&session);
            let storage = Arc::new(storage);
            let authority_scope = storage
                .capability_authorization_scope()
                .expect("D32 authority scope");
            assert!(require_current_session_life_in_scope(&authority_scope, &session).is_ok());

            // The Life transition must compete from outside the non-reentrant
            // authority scope.  Starting it while the scope is held proves
            // that the linearizer blocks the transition; releasing the scope
            // before joining the worker then proves that a fresh scope reads
            // the committed Life fence rather than deadlocking or reusing the
            // stale view.
            let switch_storage = Arc::clone(&storage);
            let switch_started = Arc::new(Barrier::new(2));
            let switch_start = Arc::clone(&switch_started);
            let switch_thread = thread::spawn(move || {
                switch_start.wait();
                switch_current_life_for_test_with_persona(&switch_storage, "d29h9-r3-persona");
            });
            switch_started.wait();
            drop(authority_scope);
            switch_thread.join().expect("D32 Life switch worker");

            let fresh_scope = storage
                .capability_authorization_scope()
                .expect("D32 fresh authority scope");
            assert_eq!(
                require_current_session_life_in_scope(&fresh_scope, &session).unwrap_err(),
                LIFE_RESTART_REQUIRED
            );
        }

        #[test]
        fn d32_production_provider_prerequisites_fail_closed() {
            assert!(require_production_provider(None)
                .expect_err("missing active provider must not be executable")
                .contains("D32_A_NOT_EXECUTABLE"));

            let base = protocol::ProviderConfiguration {
                profile_id: "profile".to_string(),
                purpose: "chat".to_string(),
                provider_kind: "openai_compatible".to_string(),
                base_url: "http://provider.invalid/v1".to_string(),
                model: "model".to_string(),
                credential_ref: "profile".to_string(),
                credential_destination: "http://provider.invalid/v1".to_string(),
            };
            assert!(require_production_provider(Some(base.clone()))
                .expect_err("non-HTTPS provider must not be executable")
                .contains("D32_A_NOT_EXECUTABLE"));

            let mut missing_model = base;
            missing_model.base_url = "https://provider.example/v1".to_string();
            missing_model.credential_destination = missing_model.base_url.clone();
            missing_model.model.clear();
            assert!(require_production_provider(Some(missing_model))
                .expect_err("missing model must not be executable")
                .contains("D32_A_NOT_EXECUTABLE"));
        }

        #[cfg(feature = "d32-a-host-canary")]
        #[test]
        fn d32_each_host_mode_has_uniform_missing_provider_preflight() {
            for mode in [
                "positive",
                "grant-replay",
                "revoke",
                "life",
                "cancel",
                "migration",
                "executable-identity-tamper",
                "environment-profile-tamper",
            ] {
                assert!(
                    D32HostCanaryMode::parse(mode).is_ok(),
                    "mode parser rejected {mode}"
                );
                let error = require_production_provider(None)
                    .expect_err("missing provider must fail closed for every mode");
                assert!(
                    error.starts_with("D32_A_NOT_EXECUTABLE:"),
                    "mode {mode} returned non-structured preflight error: {error}"
                );
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn d32_contract_trace(
            mode: D32HostCanaryMode,
        ) -> (
            D32HostCanaryTraceSnapshot,
            protocol::TurnPhase,
            Option<&'static str>,
        ) {
            let mut trace = D32HostCanaryTraceSnapshot {
                authority_evaluate: 1,
                confirmation_required: 1,
                issue_grant: 1,
                revalidate_grant: if mode == D32HostCanaryMode::GrantReplay {
                    2
                } else {
                    1
                },
                replay_wire_responses: 1,
                exact_capability: true,
                exact_tool: true,
                exact_profile: true,
                exact_cargo_check: true,
                binding_fields_validated: true,
                ..Default::default()
            };
            if mode == D32HostCanaryMode::Positive {
                trace.grant_revalidated_allowed = 1;
                trace.turn_completed = 1;
                return (trace, protocol::TurnPhase::Completed, None);
            }

            trace.grant_denial_code = Some("D32_TEST_DENIED".to_string());
            trace.revoke_applied = mode == D32HostCanaryMode::RevokeBeforeRevalidation;
            trace.life_switch_applied = mode == D32HostCanaryMode::LifeBeforeRevalidation;
            trace.isolated_migration_applied =
                mode == D32HostCanaryMode::MigrationBeforeRevalidation;
            trace.tamper_denied = matches!(
                mode,
                D32HostCanaryMode::ExecutableIdentityTamper
                    | D32HostCanaryMode::EnvironmentProfileTamper
            );
            if mode == D32HostCanaryMode::GrantReplay {
                trace.replay_checked = true;
                trace.replay_denied = true;
                trace.replay_exact_request_count = 2;
                trace.replay_exact_session_count = 2;
                trace.replay_first_allowed = 1;
                trace.replay_second_denied = 1;
                trace.grant_revalidated_denied = 1;
                // A provider may summarize after a canonical replay denial;
                // native denial remains the security evidence.
                trace.turn_completed = 1;
                (trace, protocol::TurnPhase::Completed, None)
            } else if mode == D32HostCanaryMode::CancelBeforeRevalidation {
                trace.grant_revalidated_denied = 1;
                trace.action_cancelled = 1;
                (trace, protocol::TurnPhase::Cancelled, None)
            } else {
                trace.grant_revalidated_denied = 1;
                trace.turn_failed = 1;
                (trace, protocol::TurnPhase::Failed, None)
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        fn d32_contract_native_record(mode: D32HostCanaryMode) -> D32NativeEvidenceRecord {
            let positive = mode == D32HostCanaryMode::Positive;
            D32NativeEvidenceRecord {
                version: D32_NATIVE_EVIDENCE_VERSION,
                run_id: "run".to_string(),
                session_id: "session".to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                turn_id: "turn".to_string(),
                tool_call_id: "call".to_string(),
                capability_id: PRODUCTION_CARGO_CHECK_CAPABILITY_ID.to_string(),
                program_id: CARGO_PROGRAM_ID.to_string(),
                profile_id: PRODUCTION_CARGO_CHECK_PROFILE_ID.to_string(),
                status: if positive {
                    "started_and_exited"
                } else {
                    "denied"
                }
                .to_string(),
                process_created: positive,
                process_created_count: u64::from(positive),
                thread_resumed: positive,
                thread_resumed_count: u64::from(positive),
                user_code_started: positive,
                user_code_started_count: u64::from(positive),
                process_exit: positive,
                process_exit_verified: positive,
                process_exit_count: u64::from(positive),
                exit_code: positive.then_some(0),
                process_tree_observed: positive,
                process_tree_observation_count: u64::from(positive),
                process_tree_remaining: 0,
                process_tree_observer_failed: false,
                job_termination_attempted: false,
                job_terminated: false,
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        #[test]
        fn d32_all_eight_modes_satisfy_the_pure_trace_contract() {
            for mode in [
                D32HostCanaryMode::Positive,
                D32HostCanaryMode::GrantReplay,
                D32HostCanaryMode::RevokeBeforeRevalidation,
                D32HostCanaryMode::LifeBeforeRevalidation,
                D32HostCanaryMode::CancelBeforeRevalidation,
                D32HostCanaryMode::MigrationBeforeRevalidation,
                D32HostCanaryMode::ExecutableIdentityTamper,
                D32HostCanaryMode::EnvironmentProfileTamper,
            ] {
                let (trace, phase, error) = d32_contract_trace(mode);
                d32_validate_trace(mode, &trace, Some(phase), error)
                    .unwrap_or_else(|failure| panic!("{mode:?} trace contract failed: {failure}"));
            }
        }

        #[cfg(feature = "d32-a-host-canary")]
        #[test]
        fn d32_native_evidence_requires_zero_exit_for_positive_and_none_for_denial() {
            let positive = d32_contract_native_record(D32HostCanaryMode::Positive);
            assert!(
                validate_d32_native_evidence_record(&positive, D32HostCanaryMode::Positive).is_ok()
            );

            let mut nonzero = positive.clone();
            nonzero.exit_code = Some(1);
            assert!(
                validate_d32_native_evidence_record(&nonzero, D32HostCanaryMode::Positive).is_err()
            );

            for mode in [
                D32HostCanaryMode::GrantReplay,
                D32HostCanaryMode::RevokeBeforeRevalidation,
                D32HostCanaryMode::LifeBeforeRevalidation,
                D32HostCanaryMode::CancelBeforeRevalidation,
                D32HostCanaryMode::MigrationBeforeRevalidation,
                D32HostCanaryMode::ExecutableIdentityTamper,
                D32HostCanaryMode::EnvironmentProfileTamper,
            ] {
                let denied = d32_contract_native_record(mode);
                assert!(!denied.process_created);
                assert!(!denied.thread_resumed);
                assert!(!denied.user_code_started);
                assert!(denied.exit_code.is_none());
                assert!(validate_d32_native_evidence_record(&denied, mode).is_ok());
                let mut false_positive = denied.clone();
                false_positive.exit_code = Some(0);
                assert!(validate_d32_native_evidence_record(&false_positive, mode).is_err());
            }
        }

        #[test]
        fn host_confirmation_ttl_is_an_upper_bound() {
            assert_eq!(effective_confirmation_expiry(1_000, 90_000), Some(90_000));
            assert_eq!(effective_confirmation_expiry(1_000, 20_000), Some(20_000));
            assert_eq!(effective_confirmation_expiry(1_000, 1_000), None);
        }

        #[test]
        fn sidecar_paths_drop_verbatim_prefix_but_reject_unc() {
            let normalized = normalize_sidecar_local_path(Path::new(r"\\?\E:\vita\workspace"))
                .expect("verbatim local path");
            assert_eq!(normalized, PathBuf::from(r"E:\vita\workspace"));
            assert!(normalize_sidecar_local_path(Path::new(r"\\server\share\workspace")).is_err());
        }

        #[test]
        fn startup_frames_are_tagged_and_ordered() {
            let handshake = protocol::Handshake {
                request_id: "handshake".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                runtime: RUNTIME_ID.to_string(),
                codex_commit: CODEX_UPSTREAM_COMMIT.to_string(),
                codex_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH.to_string(),
            };
            let frame = protocol::encode_frame(&VitaMessage::Handshake(handshake.clone()))
                .expect("handshake frame");
            let decoded = protocol::decode_frame::<VitaMessage>(&frame[4..]).expect("tagged frame");
            assert!(matches!(decoded, VitaMessage::Handshake(value) if value == handshake));

            let ready = protocol::Ready {
                request_id: "ready".to_string(),
                session_id: "session".to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                workspace_identity: "workspace".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                tool_name: PRODUCTION_GIT_STATUS_TOOL_NAME.to_string(),
            };
            let frame = protocol::encode_frame(&VitaMessage::Ready(ready)).expect("ready frame");
            let decoded = protocol::decode_frame::<VitaMessage>(&frame[4..]).expect("tagged frame");
            assert!(matches!(decoded, VitaMessage::Ready(_)));
        }

        #[test]
        fn d31_protocol_version_mismatch_is_rejected_before_session_start() {
            let mut handshake = protocol::Handshake {
                request_id: "d31-version".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                runtime: RUNTIME_ID.to_string(),
                codex_commit: CODEX_UPSTREAM_COMMIT.to_string(),
                codex_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH.to_string(),
            };
            assert!(validate_handshake(&handshake).is_ok());

            handshake.protocol_version = "d30-c.vita-sidecar.v2".to_string();
            assert_eq!(
                validate_handshake(&handshake),
                Err("Vita sidecar handshake identity was not pinned".to_string())
            );
        }

        #[test]
        fn bundle_resource_mapping_matches_runtime_name() {
            let config: serde_json::Value =
                serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri config");
            let resources = config["bundle"]["resources"]
                .as_object()
                .expect("explicit resource mapping");
            assert_eq!(
                resources
                    .get("../vita-agent/target/release/vita-agent.exe")
                    .and_then(serde_json::Value::as_str),
                Some(SIDECAR_RESOURCE_NAME)
            );
        }

        #[test]
        fn vita_settings_command_surfaces_are_synchronized() {
            let settings = include_str!("../permissions/settings-commands.toml");
            let manifest = include_str!("../build.rs");
            let invoke_handler = include_str!("lib.rs");
            let chat = include_str!("../permissions/chat-commands.toml");
            for command in [
                "start_vita_sidecar",
                "get_vita_sidecar_status",
                "start_vita_turn",
                "cancel_vita_turn",
                "confirm_vita_sidecar",
                "recover_vita_sidecar",
                "deny_vita_sidecar",
                "stop_vita_sidecar",
            ] {
                assert!(settings.contains(&format!("\"{command}\"")));
                assert!(manifest.contains(&format!("\"{command}\"")));
                assert!(invoke_handler.contains(&format!("vita_sidecar::{command}")));
                assert!(!chat.contains(&format!("\"{command}\"")));
            }
        }

        #[test]
        fn active_confirmation_expiry_denies_without_polling_and_releases_slot() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-old",
                "request-old",
                unix_millis().saturating_add(40),
            );

            let message = receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("automatic expiry denial");
            assert!(matches!(
                message,
                HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id,
                    decision: ConfirmationDecision::Deny,
                    ..
                }) if request_id == "request-old"
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());

            install_test_pending(
                &session,
                "pending-new",
                "request-new",
                unix_millis().saturating_add(5_000),
            );
            assert_eq!(session.pending.lock().expect("pending lock").len(), 1);
            session.retire();
            assert!(session.pending.lock().expect("pending lock").is_empty());
        }

        #[test]
        fn host_turn_generation_retires_and_rejects_late_evidence() {
            let (session, receiver) = test_session();
            let provider = test_provider();
            let (_data_root, storage, registry, authorization_revision) =
                authority_fixture(&session);
            let turn_a = "turn-generation-a".to_string();
            let provider_binding_a =
                protocol::ProviderBinding::derive(&session.session_id, &turn_a, &provider)
                    .expect("provider binding A");
            session
                .begin_turn(turn_a.clone(), provider.clone(), provider_binding_a)
                .expect("turn A active");

            let codex_turn_a = "codex-turn-generation-a".to_string();
            let binding_a = test_binding_for(&session.session_id, &codex_turn_a, "call-a");
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "authority-a".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_a.clone(),
                    binding: binding_a.clone(),
                },
            )
            .expect("turn A authority is evaluated");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("turn A authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == authorization_revision
            ));
            let mut grant_a = test_grant(&session.session_id, "grant-a", binding_a.clone());
            grant_a.authorization_revision = authorization_revision;
            session.approvals.lock().expect("approval lock").insert(
                approval_key(&turn_a, &binding_a),
                ApprovedAction {
                    host_turn_id: turn_a.clone(),
                    binding: binding_a.clone(),
                    authorization_revision,
                    confirmation_id: "confirmation-a".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(60_000),
                },
            );
            session.grants.lock().expect("grant lock").insert(
                grant_a.grant_id.clone(),
                HostStoredGrant {
                    host_turn_id: turn_a.clone(),
                    grant: grant_a.clone(),
                },
            );

            assert_eq!(
                session.begin_cancellation().expect("cancel A"),
                Some(turn_a.clone())
            );
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert!(session.accept_turn_state(&turn_a, protocol::TurnPhase::Cancelled));

            let turn_b = "turn-generation-b".to_string();
            let provider_binding_b =
                protocol::ProviderBinding::derive(&session.session_id, &turn_b, &provider)
                    .expect("provider binding B");
            session
                .begin_turn(turn_b.clone(), provider, provider_binding_b)
                .expect("turn B active");

            let codex_turn_b = "codex-turn-generation-b".to_string();
            let binding_b = test_binding_for(&session.session_id, &codex_turn_b, "call-b");

            handle_issue_grant(
                &session,
                &storage,
                &registry,
                IssueGrant {
                    request_id: "old-approval-a-on-b".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_b.clone(),
                    binding: binding_a.clone(),
                    authorization_revision,
                },
            )
            .expect("old approval replay is answered");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("old approval replay reply"),
                HostMessage::GrantIssued(GrantIssued {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));

            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "old-grant-a-on-b".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_b.clone(),
                    binding: binding_a.clone(),
                    grant: grant_a.clone(),
                },
            )
            .expect("old grant replay is answered");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("old grant replay reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));

            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "authority-b".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_b.clone(),
                    binding: binding_b.clone(),
                },
            )
            .expect("turn B authority is evaluated");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("turn B authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == authorization_revision
            ));

            handle_issue_grant(
                &session,
                &storage,
                &registry,
                IssueGrant {
                    request_id: "late-issue-a".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_a.clone(),
                    binding: binding_a.clone(),
                    authorization_revision,
                },
            )
            .expect("late issue is answered");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("late issue reply"),
                HostMessage::GrantIssued(GrantIssued {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));

            let mut stale_grants = HashMap::from([(
                grant_a.grant_id.clone(),
                HostStoredGrant {
                    host_turn_id: turn_a.clone(),
                    grant: grant_a.clone(),
                },
            )]);
            assert!(consume_active_grant(
                &mut stale_grants,
                &turn_b,
                &grant_a,
                &binding_a,
                authorization_revision,
            )
            .is_err());
            assert_eq!(stale_grants.len(), 1);

            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "cross-confirmation-a-on-b".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_b.clone(),
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding_a.clone(),
                },
            )
            .expect("cross-generation confirmation is answered");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("cross-generation confirmation reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Cancel,
                    ..
                })
            ));

            let late_confirmation = ConfirmationRequired {
                request_id: "late-confirmation-a".to_string(),
                session_id: session.session_id.clone(),
                host_turn_id: turn_a.clone(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                workspace_summary: "workspace".to_string(),
                expires_at_unix_ms: unix_millis().saturating_add(5_000),
                binding: binding_a.clone(),
            };
            handle_confirmation_required(&session, late_confirmation)
                .expect("late confirmation is answered");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("late confirmation reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Cancel,
                    ..
                })
            ));

            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "late-authority-a".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_a.clone(),
                    binding: binding_a.clone(),
                },
            )
            .expect("late authority is answered");
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)).expect("late authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));

            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "late-revalidate-a".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: turn_a,
                    binding: binding_a,
                    grant: grant_a,
                },
            )
            .expect("late revalidation is answered");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("late revalidation reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert!(session.active_authority_matches(
                &turn_b,
                &protocol::ProviderBinding::derive(
                    &session.session_id,
                    "turn-generation-b",
                    &test_provider(),
                )
                .expect("provider binding B replay check")
            ));

            session.approvals.lock().expect("approval lock").insert(
                approval_key(&turn_b, &binding_b),
                ApprovedAction {
                    host_turn_id: turn_b.clone(),
                    binding: binding_b,
                    authorization_revision: authorization_revision,
                    confirmation_id: "confirmation-b".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(60_000),
                },
            );
            assert!(session.accept_turn_state("turn-generation-b", protocol::TurnPhase::Completed));
            assert!(session.approvals.lock().expect("approval lock").is_empty());
        }

        #[test]
        fn authority_binds_distinct_host_and_codex_turns_for_full_h7_chain() {
            let (session, receiver) = test_session();
            let provider = test_provider();
            let (_data_root, storage, registry, authorization_revision) =
                authority_fixture(&session);
            let host_turn_id = "host-turn-A".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let codex_turn_id = "0199-codex-turn-A".to_string();
            let binding = test_binding_for(&session.session_id, &codex_turn_id, "call-distinct");

            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "distinct-authority-1".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("distinct authority evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("distinct authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == authorization_revision
            ));
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Active(active))
                    if active.turn_id == host_turn_id
                        && active.h7_codex_turn_id.as_deref() == Some(codex_turn_id.as_str())
            ));

            // Re-evaluation with the same Codex/H7 turn is idempotently
            // accepted and does not create a second mapping.
            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "distinct-authority-2".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                },
            )
            .expect("same Codex turn authority re-evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("same Codex turn authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == authorization_revision
            ));

            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "distinct-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding.clone(),
                },
            )
            .expect("distinct confirmation admission");
            let pending_id = session
                .pending_summary()
                .expect("distinct pending confirmation")
                .pending_id;
            let pending = take_pending(&session, &pending_id).expect("pending action");
            send_confirmation_decision(
                &session,
                &pending,
                ConfirmationDecision::Confirm,
                Some(authorization_revision),
            )
            .expect("user confirmation reply");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("user confirmation response"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Confirm,
                    authorization_revision: Some(revision),
                    ..
                }) if revision == authorization_revision
            ));
            session.approvals.lock().expect("approval lock").insert(
                approval_key(&host_turn_id, &binding),
                ApprovedAction {
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                    authorization_revision,
                    confirmation_id: "distinct-confirmation-id".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                },
            );

            handle_issue_grant(
                &session,
                &storage,
                &registry,
                IssueGrant {
                    request_id: "distinct-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                    authorization_revision,
                },
            )
            .expect("distinct grant issue");
            let grant = match receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("distinct grant issue reply")
            {
                HostMessage::GrantIssued(GrantIssued {
                    allowed: true,
                    grant: Some(grant),
                    error_code: None,
                    ..
                }) => grant,
                other => panic!("unexpected distinct grant issue reply: {other:?}"),
            };
            assert_eq!(grant.binding, binding);

            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "distinct-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding.clone(),
                    grant,
                },
            )
            .expect("distinct grant revalidation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("distinct grant revalidation reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: true,
                    grant: Some(_),
                    error_code: None,
                    ..
                })
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert!(session.accept_turn_state(&host_turn_id, protocol::TurnPhase::Completed));
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Idle)
            ));
        }

        #[test]
        fn authority_rejects_same_host_turn_with_wrong_codex_turn_everywhere() {
            let (session, receiver) = test_session();
            let provider = test_provider();
            let (_data_root, storage, registry, authorization_revision) =
                authority_fixture(&session);
            let host_turn_id = "host-turn-wrong-codex".to_string();
            let provider_binding =
                protocol::ProviderBinding::derive(&session.session_id, &host_turn_id, &provider)
                    .expect("provider binding");
            session
                .begin_turn(host_turn_id.clone(), provider, provider_binding)
                .expect("active Host turn");
            let codex_turn_one = "0199-codex-turn-one".to_string();
            let codex_turn_two = "0199-codex-turn-two".to_string();
            let binding_one = test_binding_for(&session.session_id, &codex_turn_one, "call-one");
            let binding_two = test_binding_for(&session.session_id, &codex_turn_two, "call-two");

            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "wrong-codex-bind-one".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding_one.clone(),
                },
            )
            .expect("initial Codex turn authority evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("initial authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: true,
                    authorization_revision: Some(revision),
                    error_code: None,
                    ..
                }) if revision == authorization_revision
            ));

            handle_authority_evaluate(
                &session,
                &storage,
                &registry,
                AuthorityEvaluate {
                    request_id: "wrong-codex-bind-two".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding_two.clone(),
                },
            )
            .expect("wrong Codex turn authority evaluation");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("wrong authority reply"),
                HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some(code),
                    ..
                }) if code == "CODEX_TURN_MISMATCH"
            ));

            handle_confirmation_required(
                &session,
                ConfirmationRequired {
                    request_id: "wrong-codex-confirmation".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    life_id: session.life_id.clone(),
                    task_id: session.task_id.clone(),
                    capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: "workspace".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    binding: binding_two.clone(),
                },
            )
            .expect("wrong Codex confirmation is denied");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("wrong confirmation reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Cancel,
                    authorization_revision: None,
                    ..
                })
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());

            handle_issue_grant(
                &session,
                &storage,
                &registry,
                IssueGrant {
                    request_id: "wrong-codex-issue".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding_two.clone(),
                    authorization_revision,
                },
            )
            .expect("wrong Codex grant issue is denied");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("wrong grant issue reply"),
                HostMessage::GrantIssued(GrantIssued {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));

            let wrong_grant = test_grant(
                &session.session_id,
                "wrong-codex-grant",
                binding_two.clone(),
            );
            handle_revalidate_grant(
                &session,
                &storage,
                &registry,
                RevalidateGrant {
                    request_id: "wrong-codex-revalidate".to_string(),
                    session_id: session.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
                    binding: binding_two,
                    grant: wrong_grant,
                },
            )
            .expect("wrong Codex grant revalidation is denied");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("wrong grant revalidation reply"),
                HostMessage::GrantRevalidated(GrantRevalidated {
                    allowed: false,
                    error_code: Some(code),
                    ..
                }) if code == "TURN_NOT_ACTIVE"
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert!(matches!(
                session.authority_snapshot(),
                Some(HostTurnAuthority::Active(active))
                    if active.h7_codex_turn_id.as_deref() == Some(codex_turn_one.as_str())
            ));
        }

        #[test]
        fn confirmation_race_has_exactly_one_terminal_winner() {
            let (session, receiver) = test_session();
            install_test_pending(
                &session,
                "pending-race",
                "request-race",
                unix_millis().saturating_add(5_000),
            );
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let first = {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    take_pending(&session, "pending-race")
                })
            };
            let second = {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    take_pending(&session, "pending-race")
                })
            };
            barrier.wait();
            let first = first.join().expect("first race worker");
            let second = second.join().expect("second race worker");
            assert!(first.is_some() ^ second.is_some());
            let winner = first.or(second).expect("one terminal winner");
            send_confirmation_decision(&session, &winner, ConfirmationDecision::Confirm, Some(0))
                .expect("winner reply");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("one reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Confirm,
                    ..
                })
            ));
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            session.retire();
        }

        #[test]
        fn deny_and_cancel_races_also_have_one_terminal_winner() {
            for decision in [ConfirmationDecision::Deny, ConfirmationDecision::Cancel] {
                let (session, receiver) = test_session();
                install_test_pending(
                    &session,
                    "pending-terminal-race",
                    "request-terminal-race",
                    unix_millis().saturating_add(5_000),
                );
                let barrier = Arc::new(std::sync::Barrier::new(3));
                let first = {
                    let session = Arc::clone(&session);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        take_pending(&session, "pending-terminal-race")
                    })
                };
                let second = {
                    let session = Arc::clone(&session);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        take_pending(&session, "pending-terminal-race")
                    })
                };
                barrier.wait();
                let winner = first
                    .join()
                    .expect("first terminal worker")
                    .or(second.join().expect("second terminal worker"))
                    .expect("one terminal winner");
                send_confirmation_decision(&session, &winner, decision, None)
                    .expect("terminal reply");
                assert!(matches!(
                    receiver
                        .recv_timeout(Duration::from_secs(1))
                        .expect("one terminal reply"),
                    HostMessage::ConfirmationReply(ConfirmationReply {
                        decision: actual,
                        ..
                    }) if actual == decision
                ));
                assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
                session.retire();
            }
        }

        #[test]
        fn late_confirmation_after_expiry_is_rejected() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-late",
                "request-late",
                unix_millis().saturating_add(30),
            );
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("expiry reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
            assert!(take_pending(&session, "pending-late").is_none());
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            session.retire();
        }

        #[test]
        fn stopped_expiry_owner_cannot_touch_a_fresh_session() {
            let (old_session, old_receiver) = test_session();
            old_session
                .expiry
                .start(Arc::downgrade(&old_session))
                .expect("old expiry worker");
            install_test_pending(
                &old_session,
                "pending-old-session",
                "request-old-session",
                unix_millis().saturating_add(40),
            );
            old_session.retire();
            assert!(matches!(
                old_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("shutdown denial"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
            assert!(old_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err());

            let (new_session, new_receiver) = test_session();
            new_session
                .expiry
                .start(Arc::downgrade(&new_session))
                .expect("new expiry worker");
            install_test_pending(
                &new_session,
                "pending-new-session",
                "request-new-session",
                unix_millis().saturating_add(5_000),
            );
            assert_eq!(new_session.pending.lock().expect("pending lock").len(), 1);
            assert!(new_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err());
            new_session.retire();
        }

        #[test]
        fn session_retire_clears_all_authority_state_and_joins_expiry_owner() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-cleanup",
                "request-cleanup",
                unix_millis().saturating_add(5_000),
            );
            let binding = test_binding(&session.session_id);
            session.approvals.lock().expect("approval lock").insert(
                approval_key("turn", &binding),
                ApprovedAction {
                    host_turn_id: "turn".to_string(),
                    binding: binding.clone(),
                    authorization_revision: 7,
                    confirmation_id: "confirmation-cleanup".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                },
            );
            session.grants.lock().expect("grant lock").insert(
                "grant-cleanup".to_string(),
                HostStoredGrant {
                    host_turn_id: "turn".to_string(),
                    grant: ProcessGrant {
                        session_id: session.session_id.clone(),
                        grant_id: "grant-cleanup".to_string(),
                        confirmation_id: "confirmation-cleanup".to_string(),
                        binding,
                        authorization_revision: 7,
                        issued_at_unix_ms: unix_millis(),
                        expires_at_unix_ms: unix_millis().saturating_add(5_000),
                        single_use: true,
                        used: false,
                    },
                },
            );
            session
                .replay
                .lock()
                .expect("replay lock")
                .accept("request-cleanup");

            session.retire();
            assert!(session.closed.load(Ordering::Acquire));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert_eq!(session.replay.lock().expect("replay lock").len(), 0);
            assert!(session
                .expiry
                .worker
                .lock()
                .expect("expiry worker lock")
                .is_none());
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("cleanup denial"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
        }

        #[test]
        fn long_session_replay_window_and_grant_ledger_stay_bounded() {
            let mut replay = RequestReplayWindow::default();
            for index in 0..300 {
                assert!(replay.accept(&format!("request-{index}")));
            }
            assert_eq!(replay.len(), REQUEST_REPLAY_WINDOW);
            assert!(!replay.accept("request-299"));
            assert!(replay.accept("request-0"));

            let binding = test_binding("session-ledger");
            let mut grants = HashMap::new();
            grants.insert(
                "expired".to_string(),
                HostStoredGrant {
                    host_turn_id: "session-ledger-turn".to_string(),
                    grant: ProcessGrant {
                        session_id: "session-ledger".to_string(),
                        grant_id: "expired".to_string(),
                        confirmation_id: "expired-confirmation".to_string(),
                        binding: binding.clone(),
                        authorization_revision: 7,
                        issued_at_unix_ms: unix_millis().saturating_sub(10_000),
                        expires_at_unix_ms: unix_millis().saturating_sub(1),
                        single_use: true,
                        used: false,
                    },
                },
            );
            reap_expired_grants(&mut grants);
            assert!(grants.is_empty());
            for index in 0..160 {
                let grant = ProcessGrant {
                    session_id: "session-ledger".to_string(),
                    grant_id: format!("grant-{index}"),
                    confirmation_id: format!("confirmation-{index}"),
                    binding: binding.clone(),
                    authorization_revision: 7,
                    issued_at_unix_ms: unix_millis(),
                    expires_at_unix_ms: unix_millis().saturating_add(60_000),
                    single_use: true,
                    used: false,
                };
                grants.insert(
                    grant.grant_id.clone(),
                    HostStoredGrant {
                        host_turn_id: "session-ledger-turn".to_string(),
                        grant: grant.clone(),
                    },
                );
                assert!(grants.len() <= MAX_GRANTS);
                let consumed =
                    consume_active_grant(&mut grants, "session-ledger-turn", &grant, &binding, 7)
                        .expect("single-use grant consumption");
                assert!(consumed.used);
                assert!(grants.is_empty());
                assert!(consume_active_grant(
                    &mut grants,
                    "session-ledger-turn",
                    &grant,
                    &binding,
                    7,
                )
                .is_err());
            }
        }

        #[cfg(windows)]
        #[test]
        fn production_shaped_sidecar_startup_canary_uses_tagged_frames() {
            let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../vita-agent/target/release/vita-agent.exe");
            if !executable.is_file() {
                eprintln!(
                    "skipping production-shaped sidecar canary; release image is absent: {}",
                    executable.display()
                );
                return;
            }
            let git_path = match resolve_git_path() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("skipping production-shaped sidecar canary: {error}");
                    return;
                }
            };
            let app_data = tempfile::tempdir().expect("sidecar app-data root");
            fs::create_dir(app_data.path().join("agent")).expect("Vita app-data root");
            fs::write(
                app_data.path().join("agent/.vita-agent-runtime"),
                b"runtime_id=vita-agent\nlayout=v1\n",
            )
            .expect("Vita ownership marker");
            let process_root = tempfile::tempdir().expect("sidecar process root");
            let workspace = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."))
                .expect("repository workspace");
            let workspace_for_sidecar =
                normalize_sidecar_local_path(&workspace).expect("sidecar workspace path");
            let app_data_for_sidecar =
                normalize_sidecar_local_path(app_data.path()).expect("sidecar app-data path");
            let git_for_sidecar =
                normalize_sidecar_local_path(&git_path).expect("sidecar Git path");
            let canary_resource = tempfile::tempdir().expect("sidecar canary resource root");
            let canary_executable = canary_resource.path().join(SIDECAR_RESOURCE_NAME);
            fs::copy(&executable, &canary_executable).expect("copy canary sidecar image");
            let sidecar_binding =
                VitaSidecarProcess::prepare_image(&canary_executable, canary_resource.path())
                    .expect("prepared release sidecar image");
            let mut process = VitaSidecarProcess::spawn_prepared(
                sidecar_binding,
                &[OsString::from("--serve-ipc")],
                process_root.path(),
            )
            .expect("production-shaped sidecar process");
            let stdout = process.take_stdout().expect("sidecar stdout");
            let stdin = process.take_stdin().expect("sidecar stdin");
            let mut stderr = process.take_stderr().expect("sidecar stderr");

            let (message, reader) = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "canary handshake",
            )
            .expect("tagged handshake");
            let handshake = match message {
                VitaMessage::Handshake(value) => value,
                other => panic!("unexpected canary first frame: {other:?}"),
            };
            validate_handshake(&handshake).expect("pinned canary handshake");

            let session_id = "session-canary".to_string();
            let request = VitaSidecarStartRequest {
                life_id: "life-canary".to_string(),
                task_id: "task-canary".to_string(),
                workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
            };
            let mut writer = BufWriter::new(stdin);
            protocol::write_frame(
                &mut writer,
                &HostMessage::Initialize(InitializeSession {
                    request_id: "initialize-canary".to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    session_id: session_id.clone(),
                    life_id: request.life_id.clone(),
                    task_id: request.task_id.clone(),
                    app_data_root: app_data_for_sidecar.to_string_lossy().into_owned(),
                    workspace_path: request.workspace_path.clone(),
                    git_path: git_for_sidecar.to_string_lossy().into_owned(),
                    provider: None,
                }),
            )
            .expect("canary initialize");
            let ready_result =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "canary ready");
            let (message, reader) = match ready_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    panic!("tagged ready: {error}; sidecar stderr: {diagnostics}");
                }
            };
            let ready = match message {
                VitaMessage::Ready(value) => value,
                other => panic!("unexpected canary post-initialize frame: {other:?}"),
            };
            validate_ready(&ready, &session_id, &request, &request.life_id)
                .expect("exact canary ready identity");

            protocol::write_frame(
                &mut writer,
                &HostMessage::Shutdown(protocol::Shutdown {
                    request_id: "shutdown-canary".to_string(),
                    session_id: session_id.clone(),
                }),
            )
            .expect("canary shutdown");
            let (message, _reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "canary shutdown ack")
                    .expect("tagged shutdown ack");
            assert!(matches!(
                message,
                VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id: ack_session, .. })
                    if ack_session == session_id
            ));
            drop(writer);
            process.shutdown().expect("canary process shutdown");
        }

        #[test]
        fn d31_c_real_process_workspace_replace_canary() {
            run_d31_c_real_process_workspace_replace_canary(
                D31WorkspaceCanaryMode::Replace,
                false,
                d31_c_require_real_canary(),
            );
        }

        #[test]
        fn d31_c_real_process_workspace_replace_revocation_canary() {
            if !d31_c_require_real_canary() {
                eprintln!(
                    "skipping D31-C negative process canary; set D31_C_REQUIRE_REAL_CANARY=1 for the freeze gate"
                );
                return;
            }
            run_d31_c_real_process_workspace_replace_canary(
                D31WorkspaceCanaryMode::Replace,
                true,
                true,
            );
        }

        #[test]
        fn d31_d_real_process_workspace_patch_canary() {
            run_d31_c_real_process_workspace_replace_canary(
                D31WorkspaceCanaryMode::Patch,
                false,
                d31_d_require_real_canary(),
            );
        }

        #[test]
        fn d31_d_real_process_workspace_patch_conflict_canary() {
            run_d31_c_real_process_workspace_replace_canary(
                D31WorkspaceCanaryMode::PatchConflict,
                false,
                d31_d_require_real_canary(),
            );
        }

        #[test]
        fn d31_d_real_process_workspace_patch_revocation_canary() {
            if !d31_d_require_real_canary() {
                eprintln!(
                    "skipping D31-D patch revocation canary; set D31_D_REQUIRE_REAL_CANARY=1 for the freeze gate"
                );
                return;
            }
            run_d31_c_real_process_workspace_replace_canary(
                D31WorkspaceCanaryMode::Patch,
                true,
                true,
            );
        }

        fn d31_c_require_real_canary() -> bool {
            std::env::var("D31_C_REQUIRE_REAL_CANARY").as_deref() == Ok("1")
        }

        fn d31_d_require_real_canary() -> bool {
            std::env::var("D31_D_REQUIRE_REAL_CANARY").as_deref() == Ok("1")
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum D31WorkspaceCanaryMode {
            Replace,
            Patch,
            PatchConflict,
        }

        fn run_d31_c_real_process_workspace_replace_canary(
            mode: D31WorkspaceCanaryMode,
            revoke_before_revalidation: bool,
            require_real_canary: bool,
        ) {
            let is_patch = matches!(
                mode,
                D31WorkspaceCanaryMode::Patch | D31WorkspaceCanaryMode::PatchConflict
            );
            let is_patch_conflict = matches!(mode, D31WorkspaceCanaryMode::PatchConflict);
            let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../vita-agent/target/release/vita-agent.exe");
            if !executable.is_file() {
                if require_real_canary {
                    panic!(
                        "D31-C process freeze canary requires the release image: {}",
                        executable.display()
                    );
                }
                eprintln!(
                    "skipping D31-C process canary; release image is absent: {}",
                    executable.display()
                );
                return;
            }
            let git_path = match resolve_git_path() {
                Ok(path) => path,
                Err(error) => {
                    if require_real_canary {
                        panic!("D31-C process freeze canary requires trusted Git: {error}");
                    }
                    eprintln!("skipping D31-C process canary: {error}");
                    return;
                }
            };
            let workspace = tempfile::tempdir().expect("D31-C canary workspace");
            let git_metadata = workspace.path().join(".git");
            fs::create_dir(&git_metadata).expect("D31-C canary Git metadata directory");
            fs::write(
                git_metadata.join("config"),
                b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
            )
            .expect("D31-C canary Git config");
            let canary_file = workspace.path().join("canary.txt");
            let unrelated_file = workspace.path().join("unrelated.txt");
            let canary_content = b"D31-C original canary content\n";
            let replacement_content = b"D31-C replacement canary content\n";
            fs::write(&canary_file, canary_content).expect("D31-C canary file");
            fs::write(&unrelated_file, b"unrelated fixture\n").expect("D31-C unrelated file");
            let unrelated_before = fs::read(&unrelated_file).expect("D31-C unrelated before");
            let app_data = tempfile::tempdir().expect("D31-C canary app-data");
            fs::create_dir(app_data.path().join("agent")).expect("D31-C Vita app-data root");
            fs::write(
                app_data.path().join("agent/.vita-agent-runtime"),
                b"runtime_id=vita-agent\nlayout=v1\n",
            )
            .expect("D31-C Vita ownership marker");
            let process_root = tempfile::tempdir().expect("D31-C canary process root");
            let canary_resource = tempfile::tempdir().expect("D31-C canary resource root");
            let canary_executable = canary_resource.path().join(SIDECAR_RESOURCE_NAME);
            fs::copy(&executable, &canary_executable).expect("copy D31-C canary sidecar image");
            let image =
                VitaSidecarProcess::prepare_image(&canary_executable, canary_resource.path())
                    .expect("prepared D31-C sidecar image");
            let mut process = VitaSidecarProcess::spawn_prepared(
                image,
                &[OsString::from("--serve-ipc-test-canary")],
                process_root.path(),
            )
            .expect("D31-C process-isolated sidecar");
            let stdout = process.take_stdout().expect("D31-C sidecar stdout");
            let stdin = process.take_stdin().expect("D31-C sidecar stdin");
            let mut stderr = process.take_stderr().expect("D31-C sidecar stderr");

            let handshake_result = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "D31-C canary handshake",
            );
            let (message, reader) = match handshake_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    if require_real_canary {
                        panic!(
                            "D31-C process freeze canary handshake failed: {error}; sidecar stderr: {diagnostics}"
                        );
                    }
                    eprintln!(
                        "skipping D31-C process canary; release image lacks the test helper: {error}; sidecar stderr: {diagnostics}"
                    );
                    return;
                }
            };
            let handshake = match message {
                VitaMessage::Handshake(value) => value,
                other => panic!("unexpected D31-C canary first frame: {other:?}"),
            };
            validate_handshake(&handshake).expect("D31-C canary pinned handshake");

            let session_id = "d31-c-process-session".to_string();
            let life_id = "d31-c-process-life".to_string();
            let task_id = "d31-c-process-task".to_string();
            let host_turn_id = "d31-c-process-host-turn".to_string();
            let provider = protocol::ProviderConfiguration {
                profile_id: "d31-c-canary-profile".to_string(),
                purpose: "chat".to_string(),
                provider_kind: "openai_compatible".to_string(),
                base_url: "http://127.0.0.1:9/v1".to_string(),
                model: if is_patch {
                    if is_patch_conflict {
                        "d31-d-conflict-canary-model".to_string()
                    } else if revoke_before_revalidation {
                        "d31-d-negative-canary-model".to_string()
                    } else {
                        "d31-d-canary-model".to_string()
                    }
                } else if revoke_before_revalidation {
                    "d31-c-negative-canary-model".to_string()
                } else {
                    "d31-c-canary-model".to_string()
                },
                credential_ref: "d31-c-canary-credential".to_string(),
                credential_destination: "http://127.0.0.1:9/v1".to_string(),
            };
            let workspace_for_sidecar =
                normalize_sidecar_local_path(workspace.path()).expect("D31-C workspace path");
            let app_data_for_sidecar =
                normalize_sidecar_local_path(app_data.path()).expect("D31-C app-data path");
            let git_for_sidecar = normalize_sidecar_local_path(&git_path).expect("D31-C Git path");
            let mut writer = BufWriter::new(stdin);
            protocol::write_frame(
                &mut writer,
                &HostMessage::Initialize(InitializeSession {
                    request_id: "d31-c-canary-initialize".to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    session_id: session_id.clone(),
                    life_id: life_id.clone(),
                    task_id: task_id.clone(),
                    app_data_root: app_data_for_sidecar.to_string_lossy().into_owned(),
                    workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
                    git_path: git_for_sidecar.to_string_lossy().into_owned(),
                    provider: Some(provider.clone()),
                }),
            )
            .expect("D31-C canary initialize");
            let ready_result =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "D31-C canary ready");
            let (message, mut reader) = match ready_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    if require_real_canary {
                        panic!(
                            "D31-C process freeze canary ready failed: {error}; sidecar stderr: {diagnostics}"
                        );
                    }
                    eprintln!(
                        "skipping D31-C process canary; sidecar image has no test helper: {error}; sidecar stderr: {diagnostics}"
                    );
                    return;
                }
            };
            let ready = match message {
                VitaMessage::Ready(value) => value,
                other => panic!("unexpected D31-C canary ready frame: {other:?}"),
            };
            let request = VitaSidecarStartRequest {
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
            };
            validate_ready(&ready, &session_id, &request, &life_id)
                .expect("D31-C canary ready identity");

            let authority_root = tempfile::tempdir().expect("D31-C authority root");
            let storage = Arc::new(
                StorageService::initialize_with_roots(authority_root.path().to_path_buf(), None)
                    .expect("D31-C authority storage"),
            );
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-c-canary-persona".to_string(),
                    name: "D31-C canary persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("D31-C canary persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: life_id.clone(),
                    name: "D31-C canary life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-c-canary-body".to_string(),
                    persona_id: "d31-c-canary-persona".to_string(),
                    persona_version: 1,
                })
                .expect("D31-C canary life");
            let registry = CapabilityRegistry::production().expect("D31-C production registry");
            let replace_capability =
                CapabilityId::try_from(PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID)
                    .expect("D31-C replace capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: life_id.clone(),
                        capability_id: replace_capability,
                    })
                    .expect("D31-C canary replace root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let enabled_revision = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
                true,
                1,
                &life_id,
            )
            .expect("D31-C canary enable replace root");
            assert_eq!(enabled_revision.revision, 2);

            let provider_binding =
                protocol::ProviderBinding::derive(&session_id, &host_turn_id, &provider)
                    .expect("D31-C provider binding");
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_identity: ready.workspace_identity,
                cargo_profile: None,
                app_data_root_retained: None,
                provider: Some(provider.clone()),
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                workspace_read_pending: Mutex::new(HashMap::new()),
                workspace_replace_pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                workspace_read_approvals: Mutex::new(HashMap::new()),
                workspace_read_grants: Mutex::new(HashMap::new()),
                workspace_replace_approvals: Mutex::new(HashMap::new()),
                workspace_replace_grants: Mutex::new(HashMap::new()),
                recovery_pending: Mutex::new(HashMap::new()),
                recovery_scan_pending: Mutex::new(HashMap::new()),
                recovery_actions: Mutex::new(HashMap::new()),
                recovery_approvals: Mutex::new(HashMap::new()),
                recovery_grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                turn_authority: Mutex::new(HostTurnAuthority::Idle),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                recovery_result: Mutex::new(None),
                #[cfg(feature = "d32-a-host-canary")]
                canary_control: None,
                test_outbound: Mutex::new(None),
            });
            session
                .begin_turn(
                    host_turn_id.clone(),
                    provider.clone(),
                    provider_binding.clone(),
                )
                .expect("D31-C canary Host turn");
            let coordinator = VitaSidecarCoordinator::new(Arc::clone(&storage), registry.clone());
            coordinator.install_test_session(Arc::clone(&session));
            session
                .send(&HostMessage::StartTurn(protocol::StartTurn {
                    request_id: "d31-c-canary-start-turn".to_string(),
                    session_id: session_id.clone(),
                    turn_id: host_turn_id.clone(),
                    prompt: if is_patch {
                        "Patch canary.txt through the bounded exact-literal patch tool."
                    } else {
                        "Replace canary.txt through the governed workspace-replace tool."
                    }
                    .to_string(),
                    binding: provider_binding,
                }))
                .expect("D31-C canary start turn");

            let mut completed = false;
            let mut authority_evaluate_seen = false;
            let mut confirmation_seen = false;
            let mut grant_issue_seen = false;
            let mut revalidation_seen = false;
            for _ in 0..32 {
                let (message, next_reader) = receive_vita_message_with_timeout(
                    reader,
                    READY_TIMEOUT,
                    "D31-C canary turn frame",
                )
                .expect("D31-C canary turn frame");
                reader = next_reader;
                match message {
                    VitaMessage::TurnState(state) => {
                        handle_turn_state(&session, state).expect("D31-C canary turn state");
                    }
                    VitaMessage::CredentialRequired(request) => {
                        request.validate().expect("D31-C credential request");
                        assert_eq!(request.session_id, session_id);
                        assert_eq!(request.turn_id, host_turn_id);
                        let credential = protocol::SensitiveCredential::new(
                            "h9-canary-fake-credential".to_string(),
                        )
                        .expect("D31-C canary credential");
                        session
                            .send(&HostMessage::SensitiveCredentialReply(
                                protocol::SensitiveCredentialReply {
                                    request_id: request.request_id,
                                    session_id: session_id.clone(),
                                    turn_id: request.turn_id,
                                    binding_hash: request.binding.binding_hash,
                                    credential_ref: request.binding.credential_ref,
                                    credential: Some(credential),
                                    error_code: None,
                                },
                            ))
                            .expect("D31-C credential reply");
                    }
                    VitaMessage::WorkspaceReplaceAuthorityEvaluate(request) => {
                        authority_evaluate_seen = true;
                        handle_workspace_replace_authority_evaluate(
                            &session, &storage, &registry, request,
                        )
                        .expect("D31-C authority evaluation");
                    }
                    VitaMessage::WorkspaceReplaceConfirmationRequired(request) => {
                        confirmation_seen = true;
                        handle_workspace_replace_confirmation_required(&session, request)
                            .expect("D31-C confirmation request");
                        let pending_id = session
                            .pending_summary()
                            .expect("D31-C pending confirmation")
                            .pending_id;
                        coordinator
                            .confirm(pending_id)
                            .expect("D31-C explicit confirmation");
                    }
                    VitaMessage::WorkspaceReplaceIssueGrant(request) => {
                        grant_issue_seen = true;
                        handle_workspace_replace_issue_grant(
                            &session, &storage, &registry, request,
                        )
                        .expect("D31-C grant issue");
                    }
                    VitaMessage::WorkspaceReplaceRevalidateGrant(request) => {
                        revalidation_seen = true;
                        if revoke_before_revalidation {
                            let revoked = apply_transition_for_test(
                                &storage,
                                &registry,
                                PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID,
                                false,
                                2,
                                &life_id,
                            )
                            .expect("D31-C negative canary revocation");
                            assert_eq!(revoked.revision, 3);
                        }
                        handle_workspace_replace_revalidate_grant(
                            &session, &storage, &registry, request,
                        )
                        .expect("D31-C revalidation");
                    }
                    VitaMessage::TurnCompleted(message) => {
                        assert_eq!(message.session_id, session_id);
                        assert_eq!(message.turn_id, host_turn_id);
                        assert!(!message.assistant_text.is_empty());
                        completed = true;
                        break;
                    }
                    VitaMessage::TurnFailed(message) => {
                        let _ = process.shutdown();
                        let mut diagnostics = String::new();
                        let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                        panic!(
                            "D31-C canary turn failed: {} ({}) in {:?}; sidecar stderr: {}",
                            message.error_code, message.message, message.phase, diagnostics
                        );
                    }
                    other => panic!("unexpected D31-C canary turn frame: {other:?}"),
                }
            }
            assert!(completed, "D31-C canary did not complete a real turn");
            if is_patch_conflict {
                assert!(
                    !authority_evaluate_seen,
                    "D31-D conflict must not reach authority"
                );
                assert!(
                    !confirmation_seen,
                    "D31-D conflict must not request confirmation"
                );
                assert!(!grant_issue_seen, "D31-D conflict must not issue a grant");
                assert!(
                    !revalidation_seen,
                    "D31-D conflict must not revalidate a grant"
                );
            } else {
                assert!(
                    authority_evaluate_seen,
                    "D31 canary missed authority evaluation"
                );
                assert!(confirmation_seen, "D31 canary missed explicit confirmation");
                assert!(grant_issue_seen, "D31 canary missed Host grant issue");
                assert!(revalidation_seen, "D31 canary missed Host revalidation");
            }
            let final_content = fs::read(&canary_file).expect("D31-C canary final file");
            if revoke_before_revalidation || is_patch_conflict {
                assert_eq!(final_content, canary_content);
            } else {
                assert_eq!(final_content, replacement_content);
            }
            assert_eq!(
                fs::read(&unrelated_file).expect("D31-C unrelated final"),
                unrelated_before
            );
            session
                .send(&HostMessage::Shutdown(protocol::Shutdown {
                    request_id: "d31-c-canary-shutdown".to_string(),
                    session_id: session_id.clone(),
                }))
                .expect("D31-C canary shutdown");
            let (message, _reader) = receive_vita_message_with_timeout(
                reader,
                READY_TIMEOUT,
                "D31-C canary shutdown ack",
            )
            .expect("D31-C canary shutdown ack");
            assert!(matches!(
                message,
                VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id: ack_session, .. })
                    if ack_session == session_id
            ));
            session.retire();
            process.shutdown().expect("D31-C canary process shutdown");
        }

        #[test]
        fn d31_c_real_process_recovery_canary() {
            run_d31_c_real_process_recovery_canary(false, d31_c_require_real_canary());
        }

        #[test]
        fn d31_c_real_process_recovery_revocation_canary() {
            if !d31_c_require_real_canary() {
                eprintln!(
                    "skipping D31-C recovery revocation canary; set D31_C_REQUIRE_REAL_CANARY=1 for the freeze gate"
                );
                return;
            }
            run_d31_c_real_process_recovery_canary(true, true);
        }

        fn run_d31_c_real_process_recovery_canary(
            revoke_before_revalidation: bool,
            require_real_canary: bool,
        ) {
            const RECOVERY_ORIGINAL: &[u8] = b"D31-C recovery original content\n";
            const RECOVERY_REPLACEMENT: &[u8] = b"D31-C recovery replacement content\n";
            let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../vita-agent/target/release/vita-agent.exe");
            if !executable.is_file() {
                if require_real_canary {
                    panic!(
                        "D31-C recovery process freeze canary requires the release image: {}",
                        executable.display()
                    );
                }
                eprintln!(
                    "skipping D31-C recovery process canary; release image is absent: {}",
                    executable.display()
                );
                return;
            }
            let git_path = match resolve_git_path() {
                Ok(path) => path,
                Err(error) => {
                    if require_real_canary {
                        panic!("D31-C recovery canary requires trusted Git: {error}");
                    }
                    eprintln!("skipping D31-C recovery canary: {error}");
                    return;
                }
            };
            let workspace = tempfile::tempdir().expect("D31-C recovery canary workspace");
            let git_metadata = workspace.path().join(".git");
            fs::create_dir(&git_metadata).expect("D31-C recovery Git metadata directory");
            fs::write(
                git_metadata.join("config"),
                b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
            )
            .expect("D31-C recovery Git config");
            let target = workspace.path().join("recovery-canary.txt");
            fs::write(&target, RECOVERY_ORIGINAL).expect("D31-C recovery target");
            let app_data = tempfile::tempdir().expect("D31-C recovery app-data");
            let session_id = "d31-c-recovery-process-session".to_string();
            let life_id = "d31-c-recovery-process-life".to_string();
            let task_id = "d31-c-recovery-process-task".to_string();
            let seed = Command::new(&executable)
                .args([
                    "--seed-recovery-fixture",
                    app_data.path().to_str().expect("recovery app-data path"),
                    workspace.path().to_str().expect("recovery workspace path"),
                    &life_id,
                    &task_id,
                ])
                .output()
                .expect("spawn recovery fixture seeder");
            if !seed.status.success() {
                panic!(
                    "D31-C recovery fixture seeder failed: status={:?}, stderr={}",
                    seed.status,
                    String::from_utf8_lossy(&seed.stderr)
                );
            }
            let transaction_id = String::from_utf8(seed.stdout)
                .expect("recovery fixture transaction id utf8")
                .trim()
                .to_string();
            assert!(
                !transaction_id.is_empty(),
                "recovery fixture transaction id"
            );

            let process_root = tempfile::tempdir().expect("D31-C recovery process root");
            let canary_resource = tempfile::tempdir().expect("D31-C recovery resource root");
            let canary_executable = canary_resource.path().join(SIDECAR_RESOURCE_NAME);
            fs::copy(&executable, &canary_executable).expect("copy D31-C recovery sidecar image");
            let image =
                VitaSidecarProcess::prepare_image(&canary_executable, canary_resource.path())
                    .expect("prepared D31-C recovery sidecar image");
            let mut process = VitaSidecarProcess::spawn_prepared(
                image,
                &[OsString::from("--serve-ipc")],
                process_root.path(),
            )
            .expect("D31-C recovery production sidecar process");
            let stdout = process
                .take_stdout()
                .expect("D31-C recovery sidecar stdout");
            let stdin = process.take_stdin().expect("D31-C recovery sidecar stdin");
            let mut stderr = process
                .take_stderr()
                .expect("D31-C recovery sidecar stderr");
            let (message, reader) = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "D31-C recovery handshake",
            )
            .expect("D31-C recovery handshake");
            let handshake = match message {
                VitaMessage::Handshake(value) => value,
                other => panic!("unexpected D31-C recovery first frame: {other:?}"),
            };
            validate_handshake(&handshake).expect("D31-C recovery pinned handshake");
            let workspace_for_sidecar =
                normalize_sidecar_local_path(workspace.path()).expect("recovery workspace path");
            let app_data_for_sidecar =
                normalize_sidecar_local_path(app_data.path()).expect("recovery app-data path");
            let git_for_sidecar =
                normalize_sidecar_local_path(&git_path).expect("recovery Git path");
            let mut writer = BufWriter::new(stdin);
            protocol::write_frame(
                &mut writer,
                &HostMessage::Initialize(InitializeSession {
                    request_id: "d31-c-recovery-initialize".to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    session_id: session_id.clone(),
                    life_id: life_id.clone(),
                    task_id: task_id.clone(),
                    app_data_root: app_data_for_sidecar.to_string_lossy().into_owned(),
                    workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
                    git_path: git_for_sidecar.to_string_lossy().into_owned(),
                    provider: None,
                }),
            )
            .expect("D31-C recovery initialize");
            let (message, mut reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "D31-C recovery ready")
                    .unwrap_or_else(|error| {
                        let _ = process.shutdown();
                        let mut diagnostics = String::new();
                        let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                        panic!(
                            "D31-C recovery ready failed: {error}; sidecar stderr: {diagnostics}"
                        );
                    });
            let ready = match message {
                VitaMessage::Ready(value) => value,
                other => panic!("unexpected D31-C recovery ready frame: {other:?}"),
            };
            let start_request = VitaSidecarStartRequest {
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
            };
            validate_ready(&ready, &session_id, &start_request, &life_id)
                .expect("D31-C recovery ready identity");
            let (message, next_reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "D31-C recovery pending")
                    .expect("D31-C production RecoveryPending");
            reader = next_reader;
            let recovery_pending = match message {
                VitaMessage::RecoveryPending(value) => value,
                other => panic!("unexpected D31-C recovery pending frame: {other:?}"),
            };
            recovery_pending
                .validate()
                .expect("D31-C production RecoveryPending validation");
            assert_eq!(recovery_pending.session_id, session_id);
            assert_eq!(recovery_pending.life_id, life_id);
            assert_eq!(recovery_pending.task_id, task_id);
            assert_eq!(recovery_pending.transaction_id, transaction_id);
            assert_eq!(recovery_pending.relative_path, "recovery-canary.txt");
            assert_eq!(
                recovery_pending.current_sha256,
                format!("{:x}", Sha256::digest(RECOVERY_REPLACEMENT))
            );
            assert_eq!(
                recovery_pending.restore_sha256,
                format!("{:x}", Sha256::digest(RECOVERY_ORIGINAL))
            );

            let authority_root = tempfile::tempdir().expect("D31-C recovery authority root");
            let storage = Arc::new(
                StorageService::initialize_with_roots(authority_root.path().to_path_buf(), None)
                    .expect("D31-C recovery authority storage"),
            );
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-c-recovery-process-persona".to_string(),
                    name: "D31-C recovery process persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("D31-C recovery process persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: life_id.clone(),
                    name: "D31-C recovery process life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-c-recovery-process-body".to_string(),
                    persona_id: "d31-c-recovery-process-persona".to_string(),
                    persona_version: 1,
                })
                .expect("D31-C recovery process life");
            let registry = CapabilityRegistry::production().expect("D31-C recovery registry");
            let capability_id = CapabilityId::try_from(PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID)
                .expect("D31-C recovery capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: life_id.clone(),
                        capability_id,
                    })
                    .expect("D31-C recovery authorization root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let enabled_revision = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
                true,
                1,
                &life_id,
            )
            .expect("D31-C recovery capability enable");
            assert_eq!(enabled_revision.revision, 2);
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_identity: ready.workspace_identity,
                cargo_profile: None,
                app_data_root_retained: None,
                provider: None,
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                workspace_read_pending: Mutex::new(HashMap::new()),
                workspace_replace_pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                workspace_read_approvals: Mutex::new(HashMap::new()),
                workspace_read_grants: Mutex::new(HashMap::new()),
                workspace_replace_approvals: Mutex::new(HashMap::new()),
                workspace_replace_grants: Mutex::new(HashMap::new()),
                recovery_pending: Mutex::new(HashMap::new()),
                recovery_scan_pending: Mutex::new(HashMap::new()),
                recovery_actions: Mutex::new(HashMap::new()),
                recovery_approvals: Mutex::new(HashMap::new()),
                recovery_grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                turn_authority: Mutex::new(HostTurnAuthority::Idle),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                recovery_result: Mutex::new(None),
                #[cfg(feature = "d32-a-host-canary")]
                canary_control: None,
                test_outbound: Mutex::new(None),
            });
            handle_recovery_pending(&session, recovery_pending.clone())
                .expect("Host stores production RecoveryPending");
            assert_eq!(
                session.recovery_scan_summary().len(),
                1,
                "Host must retain the restart recovery summary"
            );
            let coordinator = VitaSidecarCoordinator::new(Arc::clone(&storage), registry.clone());
            coordinator.install_test_session(Arc::clone(&session));
            coordinator
                .recover(transaction_id.clone())
                .expect("Host sends typed ExecuteRecovery");

            let mut authority_seen = false;
            let mut confirmation_seen = false;
            let mut grant_issue_seen = false;
            let mut revalidation_seen = false;
            let mut result_seen = false;
            let mut recovery_result = None;
            for _ in 0..16 {
                let (message, next_reader) = receive_vita_message_with_timeout(
                    reader,
                    READY_TIMEOUT,
                    "D31-C recovery protocol frame",
                )
                .unwrap_or_else(|error| {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    panic!("D31-C recovery frame failed: {error}; sidecar stderr: {diagnostics}");
                });
                reader = next_reader;
                match message {
                    VitaMessage::RecoveryAuthorityEvaluate(request) => {
                        authority_seen = true;
                        handle_recovery_authority_evaluate(&session, &storage, &registry, request)
                            .expect("D31-C recovery authority evaluation");
                    }
                    VitaMessage::RecoveryConfirmationRequired(request) => {
                        confirmation_seen = true;
                        handle_recovery_confirmation_required(&session, request)
                            .expect("D31-C recovery confirmation request");
                        let pending_id = session
                            .pending_summary()
                            .expect("D31-C recovery pending confirmation")
                            .pending_id;
                        coordinator
                            .confirm(pending_id)
                            .expect("D31-C explicit recovery confirmation");
                    }
                    VitaMessage::RecoveryIssueGrant(request) => {
                        grant_issue_seen = true;
                        handle_recovery_issue_grant(&session, &storage, &registry, request)
                            .expect("D31-C recovery Host grant issue");
                    }
                    VitaMessage::RecoveryRevalidateGrant(request) => {
                        revalidation_seen = true;
                        if revoke_before_revalidation {
                            let revoked = apply_transition_for_test(
                                &storage,
                                &registry,
                                PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID,
                                false,
                                enabled_revision.revision,
                                &life_id,
                            )
                            .expect("D31-C recovery negative revocation");
                            assert_eq!(revoked.revision, 3);
                        }
                        handle_recovery_revalidate_grant(&session, &storage, &registry, request)
                            .expect("D31-C recovery Host revalidation reply");
                    }
                    VitaMessage::RecoveryResult(result) => {
                        result_seen = true;
                        recovery_result = Some(result.clone());
                        handle_recovery_result(&session, result).expect("Host recovery result");
                        break;
                    }
                    other => panic!("unexpected D31-C recovery protocol frame: {other:?}"),
                }
            }
            assert!(authority_seen, "D31-C recovery missed authority evaluation");
            assert!(
                confirmation_seen,
                "D31-C recovery missed explicit confirmation"
            );
            assert!(grant_issue_seen, "D31-C recovery missed Host grant issue");
            assert!(revalidation_seen, "D31-C recovery missed Host revalidation");
            assert!(result_seen, "D31-C recovery missed terminal RecoveryResult");
            let result = recovery_result.expect("D31-C recovery result");
            result.validate().expect("D31-C recovery result validation");
            assert_eq!(result.transaction_id, transaction_id);
            if revoke_before_revalidation {
                assert_eq!(result.outcome, protocol::RecoveryOutcome::Denied);
                assert_eq!(result.mutation_count, 0);
                assert!(!result.marker_persisted);
                assert_eq!(
                    fs::read(&target).expect("D31-C recovery negative target"),
                    RECOVERY_REPLACEMENT
                );
                assert_eq!(session.recovery_scan_summary().len(), 1);
            } else {
                assert_eq!(result.outcome, protocol::RecoveryOutcome::Recovered);
                assert_eq!(result.mutation_count, 1);
                assert!(result.marker_persisted);
                assert_eq!(
                    fs::read(&target).expect("D31-C recovery restored target"),
                    RECOVERY_ORIGINAL
                );
                assert!(session.recovery_scan_summary().is_empty());
            }
            session
                .send(&HostMessage::Shutdown(protocol::Shutdown {
                    request_id: "d31-c-recovery-shutdown".to_string(),
                    session_id: session_id.clone(),
                }))
                .expect("D31-C recovery shutdown");
            let (message, _reader) = receive_vita_message_with_timeout(
                reader,
                READY_TIMEOUT,
                "D31-C recovery shutdown ack",
            )
            .expect("D31-C recovery shutdown ack");
            assert!(matches!(
                message,
                VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id: ack_session, .. })
                    if ack_session == session_id
            ));
            session.retire();
            process.shutdown().expect("D31-C recovery process shutdown");
        }

        #[test]
        fn d31_b_real_process_workspace_read_canary() {
            run_d31_b_real_process_workspace_read_canary(false, d31_b_require_real_canary());
        }

        #[test]
        fn d31_b_real_process_workspace_read_revocation_canary() {
            if !d31_b_require_real_canary() {
                eprintln!(
                    "skipping D31-B negative process canary; set D31_B_REQUIRE_REAL_CANARY=1 for the freeze gate"
                );
                return;
            }
            run_d31_b_real_process_workspace_read_canary(true, true);
        }

        fn d31_b_require_real_canary() -> bool {
            std::env::var("D31_B_REQUIRE_REAL_CANARY").as_deref() == Ok("1")
        }

        fn run_d31_b_real_process_workspace_read_canary(
            revoke_before_revalidation: bool,
            require_real_canary: bool,
        ) {
            let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../vita-agent/target/release/vita-agent.exe");
            if !executable.is_file() {
                if require_real_canary {
                    panic!(
                        "D31-B process freeze canary requires the release image: {}",
                        executable.display()
                    );
                }
                eprintln!(
                    "skipping D31-B process canary; release image is absent: {}",
                    executable.display()
                );
                return;
            }
            let git_path = match resolve_git_path() {
                Ok(path) => path,
                Err(error) => {
                    if require_real_canary {
                        panic!("D31-B process freeze canary requires trusted Git: {error}");
                    }
                    eprintln!("skipping D31-B process canary: {error}");
                    return;
                }
            };
            let workspace = tempfile::tempdir().expect("D31-B canary workspace");
            let git_metadata = workspace.path().join(".git");
            fs::create_dir(&git_metadata).expect("D31-B canary Git metadata directory");
            fs::write(
                git_metadata.join("config"),
                b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
            )
            .expect("D31-B canary Git config");
            let canary_file = workspace.path().join("canary.txt");
            let canary_content = b"D31-B bounded canary content\n";
            fs::write(&canary_file, canary_content).expect("D31-B canary file");
            let app_data = tempfile::tempdir().expect("D31-B canary app-data");
            fs::create_dir(app_data.path().join("agent")).expect("D31-B Vita app-data root");
            fs::write(
                app_data.path().join("agent/.vita-agent-runtime"),
                b"runtime_id=vita-agent\nlayout=v1\n",
            )
            .expect("D31-B Vita ownership marker");
            let process_root = tempfile::tempdir().expect("D31-B canary process root");
            let canary_resource = tempfile::tempdir().expect("D31-B canary resource root");
            let canary_executable = canary_resource.path().join(SIDECAR_RESOURCE_NAME);
            fs::copy(&executable, &canary_executable).expect("copy D31-B canary sidecar image");
            let image =
                VitaSidecarProcess::prepare_image(&canary_executable, canary_resource.path())
                    .expect("prepared D31-B sidecar image");
            let mut process = VitaSidecarProcess::spawn_prepared(
                image,
                &[OsString::from("--serve-ipc-test-canary")],
                process_root.path(),
            )
            .expect("D31-B process-isolated sidecar");
            let stdout = process.take_stdout().expect("D31-B sidecar stdout");
            let stdin = process.take_stdin().expect("D31-B sidecar stdin");
            let mut stderr = process.take_stderr().expect("D31-B sidecar stderr");

            let handshake_result = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "D31-B canary handshake",
            );
            let (message, reader) = match handshake_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    if require_real_canary {
                        panic!(
                            "D31-B process freeze canary handshake failed: {error}; sidecar stderr: {diagnostics}"
                        );
                    }
                    eprintln!(
                        "skipping D31-B process canary; release image lacks the test helper: {error}; sidecar stderr: {diagnostics}"
                    );
                    return;
                }
            };
            let handshake = match message {
                VitaMessage::Handshake(value) => value,
                other => panic!("unexpected D31-B canary first frame: {other:?}"),
            };
            validate_handshake(&handshake).expect("D31-B canary pinned handshake");

            let session_id = "d31-b-process-session".to_string();
            let life_id = "d31-b-process-life".to_string();
            let task_id = "d31-b-process-task".to_string();
            let host_turn_id = "d31-b-process-host-turn".to_string();
            let provider = protocol::ProviderConfiguration {
                profile_id: "d31-b-canary-profile".to_string(),
                purpose: "chat".to_string(),
                provider_kind: "openai_compatible".to_string(),
                base_url: "http://127.0.0.1:9/v1".to_string(),
                model: if revoke_before_revalidation {
                    "d31-b-negative-canary-model".to_string()
                } else {
                    "d31-b-canary-model".to_string()
                },
                credential_ref: "d31-b-canary-credential".to_string(),
                credential_destination: "http://127.0.0.1:9/v1".to_string(),
            };
            let workspace_for_sidecar =
                normalize_sidecar_local_path(workspace.path()).expect("D31-B workspace path");
            let app_data_for_sidecar =
                normalize_sidecar_local_path(app_data.path()).expect("D31-B app-data path");
            let git_for_sidecar = normalize_sidecar_local_path(&git_path).expect("D31-B Git path");
            let mut writer = BufWriter::new(stdin);
            protocol::write_frame(
                &mut writer,
                &HostMessage::Initialize(InitializeSession {
                    request_id: "d31-b-canary-initialize".to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    session_id: session_id.clone(),
                    life_id: life_id.clone(),
                    task_id: task_id.clone(),
                    app_data_root: app_data_for_sidecar.to_string_lossy().into_owned(),
                    workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
                    git_path: git_for_sidecar.to_string_lossy().into_owned(),
                    provider: Some(provider.clone()),
                }),
            )
            .expect("D31-B canary initialize");
            let ready_result =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "D31-B canary ready");
            let (message, mut reader) = match ready_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    if require_real_canary {
                        panic!(
                            "D31-B process freeze canary ready failed: {error}; sidecar stderr: {diagnostics}"
                        );
                    }
                    eprintln!(
                        "skipping D31-B process canary; sidecar image has no test helper: {error}; sidecar stderr: {diagnostics}"
                    );
                    return;
                }
            };
            let ready = match message {
                VitaMessage::Ready(value) => value,
                other => panic!("unexpected D31-B canary ready frame: {other:?}"),
            };
            let request = VitaSidecarStartRequest {
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
            };
            validate_ready(&ready, &session_id, &request, &life_id)
                .expect("D31-B canary ready identity");

            let authority_root = tempfile::tempdir().expect("D31-B authority root");
            let storage = Arc::new(
                StorageService::initialize_with_roots(authority_root.path().to_path_buf(), None)
                    .expect("D31-B authority storage"),
            );
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d31-b-canary-persona".to_string(),
                    name: "D31-B canary persona".to_string(),
                    version: 1,
                    persona_json: "{}".to_string(),
                })
                .expect("D31-B canary persona");
            storage
                .save_life(LifeIdentityRecord {
                    id: life_id.clone(),
                    name: "D31-B canary life".to_string(),
                    created_at: "2026-09-14T00:00:00.000Z".to_string(),
                    version: 1,
                    body_id: "d31-b-canary-body".to_string(),
                    persona_id: "d31-b-canary-persona".to_string(),
                    persona_version: 1,
                })
                .expect("D31-B canary life");
            let registry = CapabilityRegistry::production().expect("D31-B production registry");
            let read_capability = CapabilityId::try_from(PRODUCTION_WORKSPACE_READ_CAPABILITY_ID)
                .expect("D31-B read capability");
            assert!(matches!(
                storage
                    .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                        life_id: life_id.clone(),
                        capability_id: read_capability,
                    })
                    .expect("D31-B canary read root"),
                CapabilityAuthorizationCreateOutcome::Applied(_)
            ));
            let enabled_revision = apply_transition_for_test(
                &storage,
                &registry,
                PRODUCTION_WORKSPACE_READ_CAPABILITY_ID,
                true,
                1,
                &life_id,
            )
            .expect("D31-B canary enable read root");
            assert_eq!(enabled_revision.revision, 2);

            let provider_binding =
                protocol::ProviderBinding::derive(&session_id, &host_turn_id, &provider)
                    .expect("D31-B provider binding");
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: life_id.clone(),
                task_id: task_id.clone(),
                workspace_identity: ready.workspace_identity,
                cargo_profile: None,
                app_data_root_retained: None,
                provider: Some(provider.clone()),
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                workspace_read_pending: Mutex::new(HashMap::new()),
                workspace_replace_pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                workspace_read_approvals: Mutex::new(HashMap::new()),
                workspace_read_grants: Mutex::new(HashMap::new()),
                workspace_replace_approvals: Mutex::new(HashMap::new()),
                workspace_replace_grants: Mutex::new(HashMap::new()),
                recovery_pending: Mutex::new(HashMap::new()),
                recovery_scan_pending: Mutex::new(HashMap::new()),
                recovery_actions: Mutex::new(HashMap::new()),
                recovery_approvals: Mutex::new(HashMap::new()),
                recovery_grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                turn_authority: Mutex::new(HostTurnAuthority::Idle),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                recovery_result: Mutex::new(None),
                #[cfg(feature = "d32-a-host-canary")]
                canary_control: None,
                test_outbound: Mutex::new(None),
            });
            session
                .begin_turn(
                    host_turn_id.clone(),
                    provider.clone(),
                    provider_binding.clone(),
                )
                .expect("D31-B canary Host turn");
            let coordinator = VitaSidecarCoordinator::new(Arc::clone(&storage), registry.clone());
            coordinator.install_test_session(Arc::clone(&session));
            session
                .send(&HostMessage::StartTurn(protocol::StartTurn {
                    request_id: "d31-b-canary-start-turn".to_string(),
                    session_id: session_id.clone(),
                    turn_id: host_turn_id.clone(),
                    prompt: "Read canary.txt through the governed workspace-read tool.".to_string(),
                    binding: provider_binding,
                }))
                .expect("D31-B canary start turn");

            let mut completed = false;
            let mut authority_evaluate_seen = false;
            let mut confirmation_seen = false;
            let mut grant_issue_seen = false;
            let mut revalidation_seen = false;
            let mut release_seen = false;
            let mut release_bytes = 0_u64;
            for _ in 0..32 {
                let (message, next_reader) = receive_vita_message_with_timeout(
                    reader,
                    READY_TIMEOUT,
                    "D31-B canary turn frame",
                )
                .expect("D31-B canary turn frame");
                reader = next_reader;
                match message {
                    VitaMessage::TurnState(state) => {
                        handle_turn_state(&session, state).expect("D31-B canary turn state");
                    }
                    VitaMessage::CredentialRequired(request) => {
                        request.validate().expect("D31-B credential request");
                        assert_eq!(request.session_id, session_id);
                        assert_eq!(request.turn_id, host_turn_id);
                        assert_eq!(request.binding.purpose, "chat");
                        let credential = protocol::SensitiveCredential::new(
                            "h9-canary-fake-credential".to_string(),
                        )
                        .expect("D31-B canary credential");
                        session
                            .send(&HostMessage::SensitiveCredentialReply(
                                protocol::SensitiveCredentialReply {
                                    request_id: request.request_id,
                                    session_id: session_id.clone(),
                                    turn_id: request.turn_id,
                                    binding_hash: request.binding.binding_hash,
                                    credential_ref: request.binding.credential_ref,
                                    credential: Some(credential),
                                    error_code: None,
                                },
                            ))
                            .expect("D31-B credential reply");
                    }
                    VitaMessage::WorkspaceReadAuthorityEvaluate(request) => {
                        authority_evaluate_seen = true;
                        handle_workspace_read_authority_evaluate(
                            &session, &storage, &registry, request,
                        )
                        .expect("D31-B authority evaluation");
                    }
                    VitaMessage::WorkspaceReadConfirmationRequired(request) => {
                        confirmation_seen = true;
                        handle_workspace_read_confirmation_required(&session, request)
                            .expect("D31-B confirmation request");
                        let pending_id = session
                            .pending_summary()
                            .expect("D31-B pending confirmation")
                            .pending_id;
                        coordinator
                            .confirm(pending_id)
                            .expect("D31-B explicit confirmation");
                    }
                    VitaMessage::WorkspaceReadIssueGrant(request) => {
                        grant_issue_seen = true;
                        handle_workspace_read_issue_grant(&session, &storage, &registry, request)
                            .expect("D31-B grant issue");
                    }
                    VitaMessage::WorkspaceReadRevalidateGrant(request) => {
                        revalidation_seen = true;
                        if revoke_before_revalidation {
                            let revoked = apply_transition_for_test(
                                &storage,
                                &registry,
                                PRODUCTION_WORKSPACE_READ_CAPABILITY_ID,
                                false,
                                2,
                                &life_id,
                            )
                            .expect("D31-B negative canary revocation");
                            assert_eq!(revoked.revision, 3);
                            handle_workspace_read_revalidate_grant(
                                &session, &storage, &registry, request,
                            )
                            .expect("D31-B negative canary revalidation denial reply");
                        } else {
                            handle_workspace_read_revalidate_grant(
                                &session, &storage, &registry, request,
                            )
                            .expect("D31-B pre-read revalidation");
                        }
                    }
                    VitaMessage::WorkspaceReadReleaseCheck(request) => {
                        release_seen = true;
                        release_bytes = request.bytes_read;
                        assert!(
                            !revoke_before_revalidation,
                            "D31-B negative canary must not reach release"
                        );
                        assert!(request.bytes_read <= 64);
                        handle_workspace_read_release_check(&session, &storage, &registry, request)
                            .expect("D31-B disclosure release");
                    }
                    VitaMessage::TurnCompleted(message) => {
                        assert_eq!(message.session_id, session_id);
                        assert_eq!(message.turn_id, host_turn_id);
                        assert!(!message.assistant_text.is_empty());
                        completed = true;
                        break;
                    }
                    VitaMessage::TurnFailed(message) => {
                        let _ = process.shutdown();
                        let mut diagnostics = String::new();
                        let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                        panic!(
                            "D31-B canary turn failed: {} ({}) in {:?}; sidecar stderr: {}",
                            message.error_code, message.message, message.phase, diagnostics
                        );
                    }
                    other => panic!("unexpected D31-B canary turn frame: {other:?}"),
                }
            }
            assert!(completed, "D31-B canary did not complete a real turn");
            assert!(
                authority_evaluate_seen,
                "D31-B canary missed authority evaluation"
            );
            assert!(
                confirmation_seen,
                "D31-B canary missed explicit confirmation"
            );
            assert!(grant_issue_seen, "D31-B canary missed Host grant issue");
            assert!(revalidation_seen, "D31-B canary missed Host revalidation");
            if revoke_before_revalidation {
                assert!(!release_seen, "D31-B negative canary reached release");
                assert_eq!(release_bytes, 0);
            } else {
                assert!(release_seen, "D31-B canary missed disclosure release");
                assert!(release_bytes > 0, "D31-B canary read no fixture bytes");
            }
            assert_eq!(
                fs::read(&canary_file).expect("D31-B canary file remains readable"),
                canary_content
            );
            session
                .send(&HostMessage::Shutdown(protocol::Shutdown {
                    request_id: "d31-b-canary-shutdown".to_string(),
                    session_id: session_id.clone(),
                }))
                .expect("D31-B canary shutdown");
            let (message, _reader) = receive_vita_message_with_timeout(
                reader,
                READY_TIMEOUT,
                "D31-B canary shutdown ack",
            )
            .expect("D31-B canary shutdown ack");
            assert!(matches!(
                message,
                VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id: ack_session, .. })
                    if ack_session == session_id
            ));
            session.retire();
            process.shutdown().expect("D31-B canary process shutdown");
        }
    }
}

#[cfg(windows)]
use windows::StateType as WindowsCoordinatorState;

#[cfg(not(windows))]
mod non_windows {
    use super::*;
    use tauri::State;

    pub(super) fn start_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _request: VitaSidecarStartRequest,
    ) -> Result<VitaSidecarStartResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn get_vita_sidecar_status(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarStatusResponse, String> {
        Ok(VitaSidecarStatusResponse {
            running: false,
            provider_readiness: VitaProviderReadiness::SidecarNotRunning,
            capability_readiness: VitaCapabilityReadiness::AuthorizationUnavailable,
            capability_states: Vec::new(),
            session_life_id: None,
            current_life_id: None,
            session_id: None,
            pending: None,
            recovery_pending: Vec::new(),
            recovery_result: None,
            active_turn_id: None,
            turn_phase: None,
            assistant_text: None,
            turn_error: None,
        })
    }

    pub(super) fn confirm_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn recover_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _transaction_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn deny_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn cancel_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn start_vita_turn(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _request: VitaTurnStartRequest,
    ) -> Result<VitaTurnStartResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn cancel_vita_turn(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn stop_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Ok(VitaSidecarActionResponse { accepted: true })
    }
}

#[tauri::command]
pub(crate) fn start_vita_sidecar(
    app: AppHandle,
    coordinator: State<'_, VitaSidecarCoordinator>,
    request: VitaSidecarStartRequest,
) -> Result<VitaSidecarStartResponse, String> {
    #[cfg(windows)]
    {
        windows::start_vita_sidecar(app, coordinator, request)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        non_windows::start_vita_sidecar(coordinator, request)
    }
}

#[tauri::command]
pub(crate) fn get_vita_sidecar_status(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarStatusResponse, String> {
    #[cfg(windows)]
    {
        windows::get_vita_sidecar_status(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::get_vita_sidecar_status(coordinator)
    }
}

#[tauri::command]
pub(crate) fn start_vita_turn(
    coordinator: State<'_, VitaSidecarCoordinator>,
    request: VitaTurnStartRequest,
) -> Result<VitaTurnStartResponse, String> {
    #[cfg(windows)]
    {
        windows::start_vita_turn(coordinator, request)
    }
    #[cfg(not(windows))]
    {
        non_windows::start_vita_turn(coordinator, request)
    }
}

#[tauri::command]
pub(crate) fn cancel_vita_turn(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::cancel_vita_turn(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::cancel_vita_turn(coordinator)
    }
}

#[tauri::command]
pub(crate) fn confirm_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
    pending_id: String,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::confirm_vita_sidecar(coordinator, pending_id)
    }
    #[cfg(not(windows))]
    {
        non_windows::confirm_vita_sidecar(coordinator, pending_id)
    }
}

#[tauri::command]
pub(crate) fn recover_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
    transaction_id: String,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::recover_vita_sidecar(coordinator, transaction_id)
    }
    #[cfg(not(windows))]
    {
        non_windows::recover_vita_sidecar(coordinator, transaction_id)
    }
}

#[tauri::command]
pub(crate) fn deny_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
    pending_id: String,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::deny_vita_sidecar(coordinator, pending_id)
    }
    #[cfg(not(windows))]
    {
        non_windows::deny_vita_sidecar(coordinator, pending_id)
    }
}

#[tauri::command]
pub(crate) fn cancel_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::cancel_vita_sidecar(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::cancel_vita_sidecar(coordinator)
    }
}

#[tauri::command]
pub(crate) fn stop_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::stop_vita_sidecar(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::stop_vita_sidecar(coordinator)
    }
}
