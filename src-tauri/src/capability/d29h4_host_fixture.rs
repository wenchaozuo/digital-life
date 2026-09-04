//! Process-isolated D29-H4-A Host authority fixture.
//!
//! This module is compiled only for the H4-A integration fixture.  It owns the
//! canonical D28 SQLite row, the Host workspace scope, the explicit action
//! confirmation store, and the issued replace grants.  It never opens or
//! mutates the requested workspace target; the actual mutation primitive is a
//! later H4-B concern.

use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::authorization::{
    evaluate_capability_authorization, CapabilityAuthorizationCreateOutcome,
    CapabilityAuthorizationDecisionCode, CapabilityAuthorizationDecisionKind,
    CapabilityAuthorizationError, CapabilityAuthorizationRepository,
    CapabilityAuthorizationUpdateOutcome, LifeCapabilityAuthorization,
    LifeCapabilityAuthorizationCreateRequest, LifeCapabilityAuthorizationEvent,
    LifeCapabilityAuthorizationUpdateRequest, RequestedCapabilityScope,
};
use super::descriptor::{
    ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, RiskClass,
    ScopeRequirement,
};
use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_ID_CHARS: usize = 128;
const MAX_PATH_CHARS: usize = 256;
const MAX_IDENTITY_CHARS: usize = 512;
const MAX_GRANTS: usize = 256;
const GRANT_LIFETIME_MS: u64 = 30_000;
const H4_CAPABILITY_ID: &str = "vita.workspace.replace_file";
const H4_TARGET_KIND: &str = "existing_file";
const H4_OPERATION: &str = "replace_existing_utf8_file";

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum HostRequest {
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

#[derive(Clone, Debug, Serialize)]
struct HostResponse {
    operation: &'static str,
    status: &'static str,
    canonical: Option<CanonicalWire>,
    confirmation: Option<ConfirmationWire>,
    action_grant: Option<ReplaceGrantWire>,
    confirmation_consumed: bool,
    denial: Option<&'static str>,
    authorization_revision: Option<i64>,
    error_code: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct CanonicalWire {
    canonical_evaluations: usize,
    production_registry_size: usize,
    test_registry_size: usize,
    authorization_row_reads: usize,
    host_scope_authority_present: bool,
    requested_root_matched_authorized_root: bool,
    life_id: String,
    capability_id: String,
    outcome: &'static str,
    decision_code: &'static str,
    risk_class: &'static str,
    scope_requirement: &'static str,
    approval_floor: &'static str,
    authorization_revision: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConfirmationWire {
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplaceGrantWire {
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

/// Host-owned scope; the request's root string is only an operation fact.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostOwnedWorkspaceScope {
    life_id: String,
    task_id: String,
    capability_id: CapabilityId,
    allowed_workspace_root_identity: String,
}

impl HostOwnedWorkspaceScope {
    fn provision(
        life_id: String,
        task_id: String,
        capability_id: CapabilityId,
        allowed_workspace_root_identity: String,
    ) -> Result<Self, String> {
        if !valid_identity(&allowed_workspace_root_identity) {
            return Err("D29-H4 Host workspace scope identity was invalid".to_string());
        }
        Ok(Self {
            life_id,
            task_id,
            capability_id,
            allowed_workspace_root_identity,
        })
    }

    fn matches_request(
        &self,
        life_id: &str,
        task_id: &str,
        capability_id: &str,
        workspace_root_identity: &str,
    ) -> bool {
        self.life_id == life_id
            && self.task_id == task_id
            && self.capability_id.as_str() == capability_id
            && self.allowed_workspace_root_identity == workspace_root_identity
    }
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "digital-life-d29h4-authority-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir(&path).map_err(|_| {
            "D29-H4 Host fixture could not create its private temp root".to_string()
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct HostSession {
    _root: FixtureRoot,
    storage: Arc<StorageService>,
    production_registry: CapabilityRegistry,
    test_registry: CapabilityRegistry,
    life_id: String,
    task_id: String,
    capability_id: CapabilityId,
    workspace_scope_authority: HostOwnedWorkspaceScope,
    confirmations: HashMap<String, ConfirmationWire>,
    grants: HashMap<String, ReplaceGrantWire>,
    issued_tool_calls: HashSet<String>,
    next_grant_id: u64,
}

impl HostSession {
    fn initialize(
        protocol_version: u8,
        life_id: String,
        task_id: String,
        capability_id: String,
        allowed_workspace_root_identity: String,
    ) -> Result<(Self, HostResponse), String> {
        if protocol_version != PROTOCOL_VERSION
            || !valid_identity(&life_id)
            || !valid_identity(&task_id)
            || capability_id != H4_CAPABILITY_ID
        {
            return Err("D29-H4 Host initialize request was invalid".to_string());
        }
        let capability_id = CapabilityId::try_from(capability_id)
            .map_err(|_| "D29-H4 Host capability ID was invalid".to_string())?;
        let workspace_scope_authority = HostOwnedWorkspaceScope::provision(
            life_id.clone(),
            task_id.clone(),
            capability_id.clone(),
            allowed_workspace_root_identity,
        )?;
        let root = FixtureRoot::create()?;
        let storage = Arc::new(
            StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .map_err(|_| "D29-H4 Host could not initialize its one SQLite state".to_string())?,
        );
        storage
            .save_persona(PersonaTemplateRecord {
                id: "d29h4-persona".to_string(),
                name: "D29-H4-A fixture persona".to_string(),
                version: 1,
                persona_json: "{}".to_string(),
            })
            .map_err(|_| "D29-H4 Host could not create its fixture persona".to_string())?;
        storage
            .save_life(LifeIdentityRecord {
                id: life_id.clone(),
                name: "D29-H4-A fixture life".to_string(),
                created_at: "2026-09-04T00:00:00.000Z".to_string(),
                version: 1,
                body_id: "d29h4-body".to_string(),
                persona_id: "d29h4-persona".to_string(),
                persona_version: 1,
            })
            .map_err(|_| "D29-H4 Host could not create its fixture life".to_string())?;

        let descriptor = CapabilityDescriptor::synthetic(
            capability_id.clone(),
            "D29-H4-A governed existing-file replace",
            RiskClass::Medium,
            ApprovalFloor::ExplicitPerAction,
            ScopeRequirement::WorkspaceRequired,
        )
        .map_err(|_| "D29-H4 Host could not construct its test descriptor".to_string())?;
        let test_registry = CapabilityRegistry::synthetic([descriptor])
            .map_err(|_| "D29-H4 Host could not construct its test registry".to_string())?;
        let production_registry = CapabilityRegistry::production()
            .map_err(|_| "D29-H4 Host could not build the production registry".to_string())?;

        match storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: life_id.clone(),
                capability_id: capability_id.clone(),
            })
            .map_err(|_| "D29-H4 Host could not create the authorization root".to_string())?
        {
            CapabilityAuthorizationCreateOutcome::Applied(_) => {}
            CapabilityAuthorizationCreateOutcome::Replayed(_) => {
                return Err("D29-H4 Host authorization root unexpectedly replayed".to_string())
            }
        }
        match storage
            .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest::for_test(
                "d29h4-fixture-enable",
                &life_id,
                capability_id.clone(),
                true,
                1,
            ))
            .map_err(|_| "D29-H4 Host could not enable the authorization root".to_string())?
        {
            CapabilityAuthorizationUpdateOutcome::Applied { .. } => {}
            CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
                return Err("D29-H4 Host authorization enable unexpectedly replayed".to_string())
            }
        }

        let session = Self {
            _root: root,
            storage,
            production_registry,
            test_registry,
            life_id,
            task_id,
            capability_id,
            workspace_scope_authority,
            confirmations: HashMap::new(),
            grants: HashMap::new(),
            issued_tool_calls: HashSet::new(),
            next_grant_id: 0,
        };
        Ok((session, HostResponse::control("initialize", Some(2), None)))
    }

    fn handle(&mut self, request: HostRequest) -> Result<HostResponse, String> {
        match request {
            HostRequest::ProvisionReplaceConfirmation {
                confirmation_id,
                life_id,
                task_id,
                capability_id,
                authorization_revision,
                workspace_root_identity,
                relative_path,
                target_identity,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                tool_call_id,
                turn_id,
                issued_at_unix_ms,
                expires_at_unix_ms,
            } => self.provision_confirmation(ConfirmationWire {
                confirmation_id,
                life_id,
                task_id,
                capability_id,
                authorization_revision,
                workspace_root_identity,
                relative_path,
                target_identity,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                tool_call_id,
                turn_id,
                issued_at_unix_ms,
                expires_at_unix_ms,
            }),
            HostRequest::IssueReplaceGrant {
                life_id,
                task_id,
                capability_id,
                tool_call_id,
                turn_id,
                relative_path,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                workspace_root_identity,
                target_identity,
                target_kind,
            } => self.issue(
                life_id,
                task_id,
                capability_id,
                tool_call_id,
                turn_id,
                relative_path,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                workspace_root_identity,
                target_identity,
                target_kind,
            ),
            HostRequest::RevalidateReplaceGrant {
                grant_id,
                life_id,
                task_id,
                capability_id,
                tool_call_id,
                turn_id,
                relative_path,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                workspace_root_identity,
                target_identity,
                target_kind,
                authorization_revision,
            } => self.revalidate(
                grant_id,
                life_id,
                task_id,
                capability_id,
                tool_call_id,
                turn_id,
                relative_path,
                expected_sha256,
                replacement_sha256,
                replacement_bytes,
                workspace_root_identity,
                target_identity,
                target_kind,
                authorization_revision,
            ),
            HostRequest::DisableAuthorizationForTest {
                life_id,
                capability_id,
                expected_revision,
            } => self.disable_authorization(life_id, capability_id, expected_revision),
            HostRequest::Shutdown {} => Ok(HostResponse::control("shutdown", None, None)),
            HostRequest::Initialize { .. } => {
                Err("D29-H4 Host received a duplicate initialize operation".to_string())
            }
        }
    }

    fn provision_confirmation(
        &mut self,
        confirmation: ConfirmationWire,
    ) -> Result<HostResponse, String> {
        if !valid_confirmation_wire(&confirmation)
            || confirmation.capability_id != H4_CAPABILITY_ID
            || confirmation.life_id != self.life_id
            || confirmation.task_id != self.task_id
            || confirmation.authorization_revision < 1
        {
            return Err("D29-H4 Host confirmation provisioning was invalid".to_string());
        }
        self.confirmations
            .insert(confirmation.confirmation_id.clone(), confirmation);
        Ok(HostResponse::control(
            "provision_replace_confirmation",
            None,
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &mut self,
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
    ) -> Result<HostResponse, String> {
        self.validate_binding(
            &life_id,
            &task_id,
            &capability_id,
            &tool_call_id,
            &turn_id,
            &relative_path,
            &expected_sha256,
            &replacement_sha256,
            replacement_bytes,
            &workspace_root_identity,
            &target_identity,
            &target_kind,
        )?;
        let root_matches = self.workspace_scope_authority.matches_request(
            &life_id,
            &task_id,
            &capability_id,
            &workspace_root_identity,
        );
        let canonical = self.canonical_decision(&life_id, &capability_id, root_matches)?;
        if canonical.decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired {
            return Ok(canonical.response("issue_replace_grant", None, false, None));
        }
        self.ensure_scope_floor(&canonical.decision)?;
        if !root_matches {
            return Ok(canonical.response(
                "issue_replace_grant",
                None,
                false,
                Some("workspace_scope_denied"),
            ));
        }
        if self.issued_tool_calls.contains(&tool_call_id) {
            return Ok(canonical.response(
                "issue_replace_grant",
                None,
                false,
                Some("confirmation_replay"),
            ));
        }
        if self.grants.len() >= MAX_GRANTS {
            return Ok(canonical.response(
                "issue_replace_grant",
                None,
                false,
                Some("grant_capacity_exhausted"),
            ));
        }

        let revision = canonical
            .decision
            .authorization_revision()
            .ok_or_else(|| "D29-H4 Host canonical revision was absent".to_string())?;
        let now = unix_millis();
        let mut matching = None;
        let mut action_candidate = false;
        let mut expired_candidate = false;
        for (id, confirmation) in &self.confirmations {
            let same_action = confirmation.life_id == life_id
                && confirmation.task_id == task_id
                && confirmation.capability_id == capability_id
                && confirmation.workspace_root_identity == workspace_root_identity
                && confirmation.relative_path == relative_path
                && confirmation.target_identity == target_identity
                && confirmation.tool_call_id == tool_call_id
                && confirmation.turn_id == turn_id;
            if !same_action {
                continue;
            }
            action_candidate = true;
            if confirmation.expires_at_unix_ms <= now {
                expired_candidate = true;
            }
            if confirmation.authorization_revision == revision
                && confirmation.expected_sha256 == expected_sha256
                && confirmation.replacement_sha256 == replacement_sha256
                && confirmation.replacement_bytes == replacement_bytes
                && confirmation.expires_at_unix_ms > now
            {
                matching = Some(id.clone());
                break;
            }
        }
        let Some(confirmation_id) = matching else {
            let denial = if expired_candidate {
                "confirmation_expired"
            } else if action_candidate {
                "confirmation_mismatch"
            } else {
                "confirmation_missing"
            };
            return Ok(canonical.response("issue_replace_grant", None, false, Some(denial)));
        };

        // Consume at grant issuance, before returning the executable evidence.
        let confirmation = self
            .confirmations
            .remove(&confirmation_id)
            .expect("matching H4 confirmation remains available");
        self.next_grant_id = self.next_grant_id.saturating_add(1);
        let grant = ReplaceGrantWire {
            grant_id: format!("d29h4-host-grant-{}", self.next_grant_id),
            life_id,
            task_id,
            capability_id,
            authorization_revision: revision,
            scope: "workspace".to_string(),
            workspace_root_identity,
            relative_path,
            target_identity,
            target_kind,
            operation: H4_OPERATION.to_string(),
            expected_sha256,
            replacement_sha256,
            replacement_bytes,
            tool_call_id: tool_call_id.clone(),
            turn_id,
            confirmation_id: confirmation.confirmation_id.clone(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(GRANT_LIFETIME_MS),
            single_use: true,
        };
        self.issued_tool_calls.insert(tool_call_id);
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(canonical.response_with_confirmation(
            "issue_replace_grant",
            Some(confirmation),
            Some(grant),
            true,
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn revalidate(
        &self,
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
    ) -> Result<HostResponse, String> {
        self.validate_binding(
            &life_id,
            &task_id,
            &capability_id,
            &tool_call_id,
            &turn_id,
            &relative_path,
            &expected_sha256,
            &replacement_sha256,
            replacement_bytes,
            &workspace_root_identity,
            &target_identity,
            &target_kind,
        )?;
        if !valid_identity(&grant_id) || authorization_revision < 1 {
            return Err("D29-H4 Host revalidation binding was invalid".to_string());
        }
        let root_matches = self.workspace_scope_authority.matches_request(
            &life_id,
            &task_id,
            &capability_id,
            &workspace_root_identity,
        );
        let canonical = self.canonical_decision(&life_id, &capability_id, root_matches)?;
        if canonical.decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired {
            return Ok(canonical.response("revalidate_replace_grant", None, root_matches, None));
        }
        self.ensure_scope_floor(&canonical.decision)?;
        if !root_matches {
            return Ok(canonical.response(
                "revalidate_replace_grant",
                None,
                false,
                Some("workspace_scope_denied"),
            ));
        }
        let Some(grant) = self.grants.get(&grant_id).cloned() else {
            return Ok(canonical.response(
                "revalidate_replace_grant",
                None,
                true,
                Some("replace_grant_revalidation_denied"),
            ));
        };
        let matches = grant.life_id == life_id
            && grant.task_id == task_id
            && grant.capability_id == capability_id
            && grant.authorization_revision == authorization_revision
            && grant.scope == "workspace"
            && grant.workspace_root_identity == workspace_root_identity
            && grant.relative_path == relative_path
            && grant.target_identity == target_identity
            && grant.target_kind == target_kind
            && grant.operation == H4_OPERATION
            && grant.expected_sha256 == expected_sha256
            && grant.replacement_sha256 == replacement_sha256
            && grant.replacement_bytes == replacement_bytes
            && grant.tool_call_id == tool_call_id
            && grant.turn_id == turn_id
            && grant.expires_at_unix_ms > unix_millis();
        if !matches {
            return Ok(canonical.response(
                "revalidate_replace_grant",
                None,
                true,
                Some("replace_grant_revalidation_denied"),
            ));
        }
        Ok(canonical.response("revalidate_replace_grant", Some(grant), true, None))
    }

    fn disable_authorization(
        &self,
        life_id: String,
        capability_id: String,
        expected_revision: i64,
    ) -> Result<HostResponse, String> {
        if life_id != self.life_id || capability_id != self.capability_id.as_str() {
            return Err("D29-H4 Host disable binding was invalid".to_string());
        }
        let outcome = self
            .storage
            .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest::for_test(
                "d29h4-fixture-disable",
                &life_id,
                self.capability_id.clone(),
                false,
                expected_revision,
            ))
            .map_err(|_| "D29-H4 Host could not update the canonical authorization".to_string())?;
        let revision = match outcome {
            CapabilityAuthorizationUpdateOutcome::Applied { authorization, .. }
            | CapabilityAuthorizationUpdateOutcome::Replayed {
                current: authorization,
                ..
            } => authorization.revision,
        };
        Ok(HostResponse::control(
            "disable_authorization_for_test",
            Some(revision),
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_binding(
        &self,
        life_id: &str,
        task_id: &str,
        capability_id: &str,
        tool_call_id: &str,
        turn_id: &str,
        relative_path: &str,
        expected_sha256: &str,
        replacement_sha256: &str,
        replacement_bytes: u64,
        workspace_root_identity: &str,
        target_identity: &str,
        target_kind: &str,
    ) -> Result<(), String> {
        if life_id != self.life_id
            || task_id != self.task_id
            || capability_id != self.capability_id.as_str()
            || !valid_identity(tool_call_id)
            || !valid_identity(turn_id)
            || !valid_identity(workspace_root_identity)
            || !valid_identity(target_identity)
            || target_kind != H4_TARGET_KIND
            || !valid_relative_resource(relative_path)
            || !is_sha256_hex(expected_sha256)
            || !is_sha256_hex(replacement_sha256)
            || replacement_bytes as usize > 64 * 1024
        {
            return Err("D29-H4 Host trusted replace binding was invalid".to_string());
        }
        Ok(())
    }

    fn ensure_scope_floor(
        &self,
        decision: &super::authorization::CapabilityAuthorizationDecision,
    ) -> Result<(), String> {
        if decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired
            || decision.decision_code() != CapabilityAuthorizationDecisionCode::ScopeNotAvailable
            || decision.scope_requirement() != ScopeRequirement::WorkspaceRequired
            || decision.approval_floor() != ApprovalFloor::ExplicitPerAction
            || decision.authorization_revision().is_none()
        {
            return Err("D29-H4 Host received an unexpected frozen D28 decision".to_string());
        }
        Ok(())
    }

    fn canonical_decision(
        &self,
        life_id: &str,
        capability_id: &str,
        root_matches: bool,
    ) -> Result<CanonicalEvaluation, String> {
        let capability_id = CapabilityId::try_from(capability_id.to_string())
            .map_err(|_| "D29-H4 Host capability ID was invalid".to_string())?;
        let row_reads = Arc::new(AtomicUsize::new(0));
        let repository = CountingAuthorizationRepository {
            storage: Arc::clone(&self.storage),
            row_reads: Arc::clone(&row_reads),
        };
        let decision = evaluate_capability_authorization(
            &repository,
            &self.test_registry,
            life_id,
            &capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|_| "D29-H4 Host canonical D28 evaluation failed".to_string())?;
        Ok(CanonicalEvaluation {
            decision,
            row_reads: row_reads.load(Ordering::Acquire),
            production_registry_size: self.production_registry.len(),
            test_registry_size: self.test_registry.len(),
            root_matches,
        })
    }
}

struct CanonicalEvaluation {
    decision: super::authorization::CapabilityAuthorizationDecision,
    row_reads: usize,
    production_registry_size: usize,
    test_registry_size: usize,
    root_matches: bool,
}

impl CanonicalEvaluation {
    fn response(
        &self,
        operation: &'static str,
        action_grant: Option<ReplaceGrantWire>,
        root_matches: bool,
        denial: Option<&'static str>,
    ) -> HostResponse {
        self.response_with_confirmation(operation, None, action_grant, false, denial)
            .with_root_matches(root_matches)
    }

    fn response_with_confirmation(
        &self,
        operation: &'static str,
        confirmation: Option<ConfirmationWire>,
        action_grant: Option<ReplaceGrantWire>,
        confirmation_consumed: bool,
        denial: Option<&'static str>,
    ) -> HostResponse {
        HostResponse {
            operation,
            status: if denial.is_some() { "denied" } else { "ok" },
            canonical: Some(CanonicalWire {
                canonical_evaluations: 1,
                production_registry_size: self.production_registry_size,
                test_registry_size: self.test_registry_size,
                authorization_row_reads: self.row_reads,
                host_scope_authority_present: true,
                requested_root_matched_authorized_root: self.root_matches,
                life_id: self.decision.life_id().to_string(),
                capability_id: self.decision.capability_id().as_str().to_string(),
                outcome: decision_outcome_name(self.decision.outcome()),
                decision_code: self.decision.decision_code().as_str(),
                risk_class: H4_DESCRIPTOR_RISK_CLASS,
                scope_requirement: scope_requirement_name(self.decision.scope_requirement()),
                approval_floor: approval_floor_name(self.decision.approval_floor()),
                authorization_revision: self.decision.authorization_revision(),
            }),
            confirmation,
            action_grant,
            confirmation_consumed,
            denial,
            authorization_revision: self.decision.authorization_revision(),
            error_code: None,
        }
    }
}

trait HostResponseRootMatch {
    fn with_root_matches(self, _root_matches: bool) -> Self;
}

impl HostResponseRootMatch for HostResponse {
    fn with_root_matches(self, _root_matches: bool) -> Self {
        self
    }
}

impl HostResponse {
    fn control(
        operation: &'static str,
        authorization_revision: Option<i64>,
        error_code: Option<&'static str>,
    ) -> Self {
        Self {
            operation,
            status: if error_code.is_some() { "denied" } else { "ok" },
            canonical: None,
            confirmation: None,
            action_grant: None,
            confirmation_consumed: false,
            denial: None,
            authorization_revision,
            error_code,
        }
    }
}

const H4_DESCRIPTOR_RISK_CLASS: &str = "Medium";

fn decision_outcome_name(outcome: CapabilityAuthorizationDecisionKind) -> &'static str {
    match outcome {
        CapabilityAuthorizationDecisionKind::Denied => "Denied",
        CapabilityAuthorizationDecisionKind::RootDisabled => "RootDisabled",
        CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired => {
            "ExplicitConfirmationRequired"
        }
        CapabilityAuthorizationDecisionKind::ScopeRequired => "ScopeRequired",
        CapabilityAuthorizationDecisionKind::Forbidden => "Forbidden",
        CapabilityAuthorizationDecisionKind::Eligible => "Eligible",
    }
}

fn scope_requirement_name(requirement: ScopeRequirement) -> &'static str {
    match requirement {
        ScopeRequirement::None => "None",
        ScopeRequirement::WorkspaceRequired => "WorkspaceRequired",
        ScopeRequirement::NetworkDestinationRequired => "NetworkDestinationRequired",
        ScopeRequirement::ExternalResourceRequired => "ExternalResourceRequired",
    }
}

fn approval_floor_name(floor: ApprovalFloor) -> &'static str {
    match floor {
        ApprovalFloor::RootEnabled => "RootEnabled",
        ApprovalFloor::ExplicitPerAction => "ExplicitPerAction",
        ApprovalFloor::Forbidden => "Forbidden",
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_IDENTITY_CHARS
        && value
            .chars()
            .all(|character| !character.is_whitespace() && !character.is_control())
}

fn valid_relative_resource(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_PATH_CHARS
        && !value.starts_with(['/', '\\'])
        && !value.contains(':')
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("\\\\")
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_confirmation_wire(confirmation: &ConfirmationWire) -> bool {
    valid_identity(&confirmation.confirmation_id)
        && valid_identity(&confirmation.life_id)
        && valid_identity(&confirmation.task_id)
        && valid_identity(&confirmation.workspace_root_identity)
        && valid_identity(&confirmation.target_identity)
        && valid_identity(&confirmation.tool_call_id)
        && valid_identity(&confirmation.turn_id)
        && valid_relative_resource(&confirmation.relative_path)
        && is_sha256_hex(&confirmation.expected_sha256)
        && is_sha256_hex(&confirmation.replacement_sha256)
        && confirmation.replacement_bytes as usize <= 64 * 1024
        && confirmation.expires_at_unix_ms > confirmation.issued_at_unix_ms
        && confirmation
            .expires_at_unix_ms
            .saturating_sub(confirmation.issued_at_unix_ms)
            <= GRANT_LIFETIME_MS
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err("D29-H4 Host frame length read failed".to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("D29-H4 Host frame exceeded its bounded size".to_string());
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|_| "D29-H4 Host frame body read failed".to_string())?;
    Ok(Some(frame))
}

fn write_frame(writer: &mut impl Write, response: &HostResponse) -> Result<(), String> {
    let body = serde_json::to_vec(response)
        .map_err(|_| "D29-H4 Host response serialization failed".to_string())?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err("D29-H4 Host response exceeded its bounded size".to_string());
    }
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&body))
        .and_then(|_| writer.flush())
        .map_err(|_| "D29-H4 Host response write failed".to_string())
}

pub(crate) fn run_from_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let first = read_frame(&mut reader)?
        .ok_or_else(|| "D29-H4 Host exited before initialize".to_string())?;
    let first: HostRequest = serde_json::from_slice(&first)
        .map_err(|_| "D29-H4 Host initialize frame was malformed".to_string())?;
    let HostRequest::Initialize {
        protocol_version,
        life_id,
        task_id,
        capability_id,
        allowed_workspace_root_identity,
    } = first
    else {
        return Err("D29-H4 Host first operation was not initialize".to_string());
    };
    let (mut session, response) = HostSession::initialize(
        protocol_version,
        life_id,
        task_id,
        capability_id,
        allowed_workspace_root_identity,
    )?;
    write_frame(&mut writer, &response)?;

    loop {
        let Some(frame) = read_frame(&mut reader)? else {
            return Err("D29-H4 Host IPC ended before shutdown".to_string());
        };
        let request: HostRequest = serde_json::from_slice(&frame)
            .map_err(|_| "D29-H4 Host operation frame was malformed".to_string())?;
        let shutdown = matches!(request, HostRequest::Shutdown {});
        let response = session.handle(request)?;
        write_frame(&mut writer, &response)?;
        if shutdown {
            return Ok(());
        }
    }
}

struct CountingAuthorizationRepository {
    storage: Arc<StorageService>,
    row_reads: Arc<AtomicUsize>,
}

impl CapabilityAuthorizationRepository for CountingAuthorizationRepository {
    fn create_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationCreateRequest,
    ) -> Result<CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError> {
        <StorageService as CapabilityAuthorizationRepository>::create_capability_authorization(
            &self.storage,
            request,
        )
    }

    fn find_capability_authorization(
        &self,
        life_id: &str,
        capability_id: &CapabilityId,
    ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
        self.row_reads.fetch_add(1, Ordering::AcqRel);
        <StorageService as CapabilityAuthorizationRepository>::find_capability_authorization(
            &self.storage,
            life_id,
            capability_id,
        )
    }

    fn update_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationUpdateRequest,
    ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
        <StorageService as CapabilityAuthorizationRepository>::update_capability_authorization(
            &self.storage,
            request,
        )
    }

    fn find_capability_authorization_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError> {
        <StorageService as CapabilityAuthorizationRepository>::find_capability_authorization_event(
            &self.storage,
            life_id,
            event_id,
        )
    }
}
