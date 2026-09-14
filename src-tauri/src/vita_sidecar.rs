//! D29-H8-R1 Host boundary for the process-isolated Vita sidecar.
//!
//! The Host owns the lifecycle, the D28 SQLite read, confirmation state, and
//! the short-lived grant ledger.  Vita receives only the bounded protocol
//! DTOs; no provider credential, SQLite handle, or Codex crate crosses this
//! module boundary.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
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

pub struct VitaSidecarCoordinator {
    authority_storage: Arc<StorageService>,
    registry: CapabilityRegistry,
    #[cfg(windows)]
    credential_store: WindowsCredentialSecretStore,
    #[cfg(all(windows, test))]
    test_provider_override: Mutex<Option<protocol::ProviderConfiguration>>,
    #[cfg(windows)]
    inner: Mutex<WindowsCoordinatorState>,
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
            #[cfg(not(windows))]
            inner: Mutex::new(()),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::capability::authorization::{
        evaluate_capability_authorization, evaluate_capability_authorization_in_scope,
        CapabilityAuthorizationDecisionKind, CapabilityAuthorizationErrorCode,
        CapabilityAuthorizationRepository, CapabilityEvaluationErrorCode, RequestedCapabilityScope,
    };
    use crate::capability::descriptor::{
        CapabilityId, ScopeRequirement, PRODUCTION_GIT_STATUS_CAPABILITY_ID,
        PRODUCTION_GIT_STATUS_PROFILE_ID, PRODUCTION_GIT_STATUS_TOOL_NAME,
        PRODUCTION_WORKSPACE_READ_CAPABILITY_ID, PRODUCTION_WORKSPACE_READ_TOOL_NAME,
        PRODUCTION_WORKSPACE_RECOVER_CAPABILITY_ID, PRODUCTION_WORKSPACE_RECOVER_PROFILE_ID,
        PRODUCTION_WORKSPACE_REPLACE_CAPABILITY_ID, PRODUCTION_WORKSPACE_REPLACE_PROFILE_ID,
        PRODUCTION_WORKSPACE_REPLACE_TOOL_NAME,
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
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Condvar, Weak};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tauri::{AppHandle, Manager, State};
    use vita_agent_protocol as protocol;

    // H7-C's fixed Git-status program identity is the profile identity.  The
    // generic H7 fixture program id is deliberately not accepted on this
    // production capability lane.
    const PROGRAM_ID: &str = PRODUCTION_GIT_STATUS_PROFILE_ID;
    const GRANT_LIFETIME_MS: u64 = 30_000;
    const HOST_CONFIRMATION_TTL_MS: u64 = 30_000;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_PENDING: usize = 1;
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
        #[cfg(test)]
        fn install_test_session(&self, session: Arc<HostSessionState>) {
            if let Ok(mut guard) = self.inner.lock() {
                guard.test_session = Some(session);
            }
        }

        fn start(
            &self,
            app: &AppHandle,
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

        fn start_inner(
            &self,
            app: &AppHandle,
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
            let app_data_root = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("Vita app data root unavailable: {error}"))?;
            fs::create_dir_all(&app_data_root)
                .map_err(|_| "Vita app data root could not be created".to_string())?;
            let app_data_root = fs::canonicalize(&app_data_root)
                .map_err(|_| "Vita app data root could not be canonicalized".to_string())?;
            validate_private_app_data_root(&app_data_root)?;
            let sidecar_app_data_root = normalize_sidecar_local_path(&app_data_root)?;

            let sidecar_binding = app_owned_sidecar_path(app)?;
            let sidecar = sidecar_binding.path.clone();
            // The image authority retains the resource directory and image
            // handles through the final pre-CreateProcessW fence.  The path
            // below is only the app-owned resource lookup, not the authority.
            let image = VitaSidecarProcess::prepare_image(&sidecar, &sidecar_binding.resource_dir)
                .map_err(map_process_error)?;
            let process_root = app_data_root.join("vita-sidecar-process");
            fs::create_dir_all(&process_root)
                .map_err(|_| "Vita sidecar process root could not be created".to_string())?;
            let process_root = fs::canonicalize(&process_root)
                .map_err(|_| "Vita sidecar process root could not be canonicalized".to_string())?;
            let git_path = resolve_git_path()?;
            let sidecar_git_path = normalize_sidecar_local_path(&git_path)?;

            let mut process = VitaSidecarProcess::spawn_prepared(
                image,
                &[OsString::from("--serve-ipc")],
                &process_root,
            )
            .map_err(map_process_error)?;
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
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: life.id.clone(),
                task_id: request.task_id.clone(),
                workspace_identity: ready.workspace_identity,
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
            let result = match message {
                VitaMessage::AuthorityEvaluate(request) => {
                    handle_authority_evaluate(&session, &storage, &registry, request)
                }
                VitaMessage::ConfirmationRequired(request) => {
                    handle_confirmation_required(&session, request)
                }
                VitaMessage::IssueGrant(request) => {
                    handle_issue_grant(&session, &storage, &registry, request)
                }
                VitaMessage::RevalidateGrant(request) => {
                    handle_revalidate_grant(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReadAuthorityEvaluate(request) => {
                    handle_workspace_read_authority_evaluate(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReadConfirmationRequired(request) => {
                    handle_workspace_read_confirmation_required(&session, request)
                }
                VitaMessage::WorkspaceReadIssueGrant(request) => {
                    handle_workspace_read_issue_grant(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReadRevalidateGrant(request) => {
                    handle_workspace_read_revalidate_grant(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReadReleaseCheck(request) => {
                    handle_workspace_read_release_check(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReplaceAuthorityEvaluate(request) => {
                    handle_workspace_replace_authority_evaluate(
                        &session, &storage, &registry, request,
                    )
                }
                VitaMessage::WorkspaceReplaceConfirmationRequired(request) => {
                    handle_workspace_replace_confirmation_required(&session, request)
                }
                VitaMessage::WorkspaceReplaceIssueGrant(request) => {
                    handle_workspace_replace_issue_grant(&session, &storage, &registry, request)
                }
                VitaMessage::WorkspaceReplaceRevalidateGrant(request) => {
                    handle_workspace_replace_revalidate_grant(
                        &session, &storage, &registry, request,
                    )
                }
                VitaMessage::RecoveryAuthorityEvaluate(request) => {
                    handle_recovery_authority_evaluate(&session, &storage, &registry, request)
                }
                VitaMessage::RecoveryConfirmationRequired(request) => {
                    handle_recovery_confirmation_required(&session, request)
                }
                VitaMessage::RecoveryIssueGrant(request) => {
                    handle_recovery_issue_grant(&session, &storage, &registry, request)
                }
                VitaMessage::RecoveryRevalidateGrant(request) => {
                    handle_recovery_revalidate_grant(&session, &storage, &registry, request)
                }
                VitaMessage::RecoveryPending(request) => handle_recovery_pending(&session, request),
                VitaMessage::RecoveryResult(result) => handle_recovery_result(&session, result),
                VitaMessage::CredentialRequired(request) => {
                    handle_credential_required(&session, &storage, &secrets, request)
                }
                VitaMessage::TurnState(message) => handle_turn_state(&session, message),
                VitaMessage::TurnCompleted(message) => handle_turn_completed(&session, message),
                VitaMessage::TurnFailed(message) => handle_turn_failed(&session, message),
                VitaMessage::ActionCancelled(message)
                    if message.session_id == session.session_id =>
                {
                    Ok(())
                }
                VitaMessage::ShutdownAck(message) if message.session_id == session.session_id => {
                    Ok(())
                }
                VitaMessage::Fatal(_) | VitaMessage::Handshake(_) | VitaMessage::Ready(_) => {
                    Err("Vita sidecar emitted an invalid Host-phase message".to_string())
                }
                VitaMessage::ActionCancelled(_) | VitaMessage::ShutdownAck(_) => {
                    Err("Vita sidecar lifecycle response session was not exact".to_string())
                }
            };
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
        let mut authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        let active = match &mut *authority {
            HostTurnAuthority::Active(active) if active.turn_id == request.host_turn_id => active,
            _ => {
                return session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    authorization_revision: None,
                    error_code: Some("TURN_NOT_ACTIVE".to_string()),
                }));
            }
        };
        if active
            .h7_codex_turn_id
            .as_deref()
            .is_some_and(|codex_turn_id| codex_turn_id != request.binding.turn_id)
        {
            return session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                authorization_revision: None,
                error_code: Some("CODEX_TURN_MISMATCH".to_string()),
            }));
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
            || request.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || request.binding.validate().is_err()
        {
            return Err("Vita confirmation binding was not exact".to_string());
        }
        validate_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                decision: ConfirmationDecision::Deny,
                authorization_revision: None,
            }))?;
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
            session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                decision: ConfirmationDecision::Cancel,
                authorization_revision: None,
            }))?;
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
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket = ExpiryTicket::for_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(pending);
        drop(authority);
        session.expiry.schedule(ticket);
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
        let authority = session
            .turn_authority
            .lock()
            .map_err(|_| "Vita turn authority lock was poisoned".to_string())?;
        if !matches!(
            &*authority,
            HostTurnAuthority::Active(active)
                if active_h7_binding_matches(active, &request.host_turn_id, &request.binding)
        ) {
            return session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some("TURN_NOT_ACTIVE".to_string()),
            }));
        }
        expire_pending(session);
        let authority_scope = match storage.capability_authorization_scope() {
            Ok(scope) => scope,
            Err(error) => {
                return session.send(&HostMessage::GrantIssued(GrantIssued {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error.code),
                }));
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
        drop(authority);
        result
    }

    fn handle_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RevalidateGrant,
    ) -> Result<(), String> {
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
            return session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some("TURN_NOT_ACTIVE".to_string()),
            }));
        }
        let authority_scope = match storage.capability_authorization_scope() {
            Ok(scope) => scope,
            Err(error) => {
                return session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                    request_id: request.request_id,
                    session_id: session.session_id.clone(),
                    allowed: false,
                    grant: None,
                    error_code: Some(error.code),
                }));
            }
        };
        let result = validate_binding(session, &request.binding).and_then(|_| {
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
            Ok(grant) => session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            })),
            Err(error) => session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            })),
        };
        drop(authority);
        result
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
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || binding.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || binding.program_id != PROGRAM_ID
            || binding.profile_id != PRODUCTION_GIT_STATUS_PROFILE_ID
            || binding.workspace_root_identity != session.workspace_identity
            || binding.git_metadata_fence_hash.len() != 64
            || !binding
                .git_metadata_fence_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
        session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
            request_id: pending.request_id.clone(),
            session_id: session.session_id.clone(),
            decision,
            authorization_revision,
        }))
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

    fn app_owned_sidecar_path(app: &AppHandle) -> Result<SidecarPathBinding, String> {
        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|error| format!("Vita resource directory unavailable: {error}"))?;
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
        fn host_confirmation_ttl_is_an_upper_bound() {
            assert_eq!(effective_confirmation_expiry(1_000, 90_000), Some(31_000));
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
            run_d31_c_real_process_workspace_replace_canary(false, d31_c_require_real_canary());
        }

        #[test]
        fn d31_c_real_process_workspace_replace_revocation_canary() {
            if !d31_c_require_real_canary() {
                eprintln!(
                    "skipping D31-C negative process canary; set D31_C_REQUIRE_REAL_CANARY=1 for the freeze gate"
                );
                return;
            }
            run_d31_c_real_process_workspace_replace_canary(true, true);
        }

        fn d31_c_require_real_canary() -> bool {
            std::env::var("D31_C_REQUIRE_REAL_CANARY").as_deref() == Ok("1")
        }

        fn run_d31_c_real_process_workspace_replace_canary(
            revoke_before_revalidation: bool,
            require_real_canary: bool,
        ) {
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
                model: if revoke_before_revalidation {
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
                    prompt: "Replace canary.txt through the governed workspace-replace tool."
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
            assert!(
                authority_evaluate_seen,
                "D31-C canary missed authority evaluation"
            );
            assert!(
                confirmation_seen,
                "D31-C canary missed explicit confirmation"
            );
            assert!(grant_issue_seen, "D31-C canary missed Host grant issue");
            assert!(revalidation_seen, "D31-C canary missed Host revalidation");
            let final_content = fs::read(&canary_file).expect("D31-C canary final file");
            if revoke_before_revalidation {
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
