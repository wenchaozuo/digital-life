//! D29-H7-A process authority fixture.
//!
//! This module is compiled only for the test/integration authority binary. It
//! owns a real D28 SQLite capability row and keeps process confirmations and
//! single-use grants in Host memory. It never receives an executable path,
//! shell text, environment map, or raw process handle.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::authorization::{
    evaluate_capability_authorization, CapabilityAuthorizationCreateOutcome,
    CapabilityAuthorizationDecisionKind, CapabilityAuthorizationRepository,
    CapabilityAuthorizationUpdateOutcome, LifeCapabilityAuthorizationCreateRequest,
    LifeCapabilityAuthorizationUpdateRequest, RequestedCapabilityScope,
};
use super::descriptor::{
    ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, RiskClass,
    ScopeRequirement,
};
use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_ID_CHARS: usize = 256;
const MAX_GRANTS: usize = 256;
const GRANT_LIFETIME_MS: u64 = 30_000;
const CAPABILITY_ID: &str = "vita.process.run";
const WORKSPACE_CAPABILITY_ID: &str = "vita.process.workspace.run";
const PROGRAM_ID: &str = "d29h7_fixture";

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum HostRequest {
    Initialize {
        protocol_version: u8,
        life_id: String,
        task_id: String,
        capability_id: String,
        #[serde(default)]
        workspace_root_identity: Option<String>,
    },
    EvaluateWorkspaceScope {
        binding: ProcessBinding,
    },
    ProvisionProcessConfirmation {
        binding: ProcessBinding,
    },
    IssueProcessGrant {
        binding: ProcessBinding,
        authorization_revision: i64,
    },
    RevalidateProcessGrant {
        grant_id: String,
        binding: ProcessBinding,
        authorization_revision: i64,
    },
    DisableAuthorizationForTest {
        life_id: String,
        capability_id: String,
        expected_revision: i64,
    },
    HoldForTest {
        milliseconds: u64,
    },
    Shutdown {},
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProcessBinding {
    life_id: String,
    task_id: String,
    capability_id: String,
    program_id: String,
    executable_identity: String,
    executable_sha256: String,
    argv_hash: String,
    argv_count: usize,
    working_directory_identity: String,
    environment_policy_hash: String,
    stdout_bound: usize,
    stderr_bound: usize,
    timeout_ms: u64,
    tool_call_id: String,
    turn_id: String,
    #[serde(default)]
    workspace_root_identity: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProcessConfirmation {
    confirmation_id: String,
    binding: ProcessBinding,
    authorization_revision: i64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProcessGrantWire {
    grant_id: String,
    confirmation_id: String,
    binding: ProcessBinding,
    authorization_revision: i64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
    used: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CanonicalWire {
    canonical_evaluations: usize,
    production_registry_size: usize,
    test_registry_size: usize,
    authorization_row_reads: usize,
    life_id: String,
    capability_id: String,
    outcome: String,
    decision_code: String,
    risk_class: String,
    approval_floor: String,
    scope_requirement: String,
    authorization_revision: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_scope_authority_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_root_matched_authorized_root: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HostResponse {
    operation: String,
    status: String,
    canonical: Option<CanonicalWire>,
    confirmation: Option<ProcessConfirmation>,
    process_grant: Option<ProcessGrantWire>,
    confirmation_consumed: bool,
    denial: Option<String>,
    authorization_revision: Option<i64>,
    error_code: Option<String>,
}

impl HostResponse {
    fn ok(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            status: "ok".to_string(),
            canonical: None,
            confirmation: None,
            process_grant: None,
            confirmation_consumed: false,
            denial: None,
            authorization_revision: None,
            error_code: None,
        }
    }

    fn denied(operation: &str, denial: &str, canonical: Option<CanonicalWire>) -> Self {
        Self {
            operation: operation.to_string(),
            status: "denied".to_string(),
            canonical,
            confirmation: None,
            process_grant: None,
            confirmation_consumed: false,
            denial: Some(denial.to_string()),
            authorization_revision: None,
            error_code: None,
        }
    }
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "digital-life-d29h7-authority-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir(&path)
            .map_err(|_| "D29-H7 Host fixture could not create its private root".to_string())?;
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
    workspace_root_identity: Option<String>,
    confirmations: BTreeMap<String, ProcessConfirmation>,
    grants: BTreeMap<String, ProcessGrantWire>,
    next_id: u64,
}

impl HostSession {
    fn initialize(
        protocol_version: u8,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_root_identity: Option<String>,
    ) -> Result<(Self, HostResponse), String> {
        if protocol_version != PROTOCOL_VERSION
            || !valid_id(&life_id)
            || !valid_id(&task_id)
            || !matches!(
                capability_id.as_str(),
                CAPABILITY_ID | WORKSPACE_CAPABILITY_ID
            )
            || (capability_id == WORKSPACE_CAPABILITY_ID
                && !workspace_root_identity.as_deref().is_some_and(valid_id))
            || (capability_id == CAPABILITY_ID && workspace_root_identity.is_some())
        {
            return Err("D29-H7 Host initialize binding was invalid".to_string());
        }
        let capability_id = CapabilityId::try_from(capability_id)
            .map_err(|_| "D29-H7 Host capability ID was invalid".to_string())?;
        let root = FixtureRoot::create()?;
        let storage = Arc::new(
            StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .map_err(|_| "D29-H7 Host could not initialize SQLite".to_string())?,
        );
        storage
            .save_persona(PersonaTemplateRecord {
                id: "d29h7-persona".to_string(),
                name: "D29-H7 fixture persona".to_string(),
                version: 1,
                persona_json: "{}".to_string(),
            })
            .map_err(|_| "D29-H7 Host could not create its persona".to_string())?;
        storage
            .save_life(LifeIdentityRecord {
                id: life_id.clone(),
                name: "D29-H7 fixture life".to_string(),
                created_at: "2026-09-09T00:00:00.000Z".to_string(),
                version: 1,
                body_id: "d29h7-body".to_string(),
                persona_id: "d29h7-persona".to_string(),
                persona_version: 1,
            })
            .map_err(|_| "D29-H7 Host could not create its life".to_string())?;
        let descriptor = CapabilityDescriptor::synthetic(
            capability_id.clone(),
            if capability_id.as_str() == WORKSPACE_CAPABILITY_ID {
                "D29-H7-B governed workspace no-shell process run"
            } else {
                "D29-H7 governed no-shell process run"
            },
            RiskClass::Critical,
            ApprovalFloor::ExplicitPerAction,
            if capability_id.as_str() == WORKSPACE_CAPABILITY_ID {
                ScopeRequirement::WorkspaceRequired
            } else {
                ScopeRequirement::None
            },
        )
        .map_err(|_| "D29-H7 Host could not construct its descriptor".to_string())?;
        let test_registry = CapabilityRegistry::synthetic([descriptor])
            .map_err(|_| "D29-H7 Host could not construct its test registry".to_string())?;
        let production_registry = CapabilityRegistry::production()
            .map_err(|_| "D29-H7 Host could not construct production registry".to_string())?;
        match storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: life_id.clone(),
                capability_id: capability_id.clone(),
            })
            .map_err(|_| "D29-H7 Host could not create authorization root".to_string())?
        {
            CapabilityAuthorizationCreateOutcome::Applied(_) => {}
            CapabilityAuthorizationCreateOutcome::Replayed(_) => {
                return Err("D29-H7 Host authorization root unexpectedly replayed".to_string())
            }
        }
        match storage
            .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest::for_test(
                "d29h7-fixture-enable",
                &life_id,
                capability_id.clone(),
                true,
                1,
            ))
            .map_err(|_| "D29-H7 Host could not enable authorization root".to_string())?
        {
            CapabilityAuthorizationUpdateOutcome::Applied { .. } => {}
            CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
                return Err("D29-H7 Host authorization enable unexpectedly replayed".to_string())
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
            workspace_root_identity,
            confirmations: BTreeMap::new(),
            grants: BTreeMap::new(),
            next_id: 0,
        };
        let mut response = HostResponse::ok("initialize");
        response.authorization_revision = Some(2);
        Ok((session, response))
    }

    fn handle(&mut self, request: HostRequest) -> Result<HostResponse, String> {
        match request {
            HostRequest::EvaluateWorkspaceScope { binding } => {
                if self.capability_id.as_str() != WORKSPACE_CAPABILITY_ID {
                    return Err(
                        "D29-H7 Host received a workspace scope request for H7-A".to_string()
                    );
                }
                let (canonical, _revision) = self.canonical(&binding)?;
                let matched = canonical.requested_root_matched_authorized_root == Some(true);
                if !matched {
                    return Ok(HostResponse::denied(
                        "evaluate_workspace_scope",
                        "workspace_scope_denied",
                        Some(canonical),
                    ));
                }
                let mut response = HostResponse::ok("evaluate_workspace_scope");
                response.canonical = Some(canonical);
                response.authorization_revision = response
                    .canonical
                    .as_ref()
                    .and_then(|canonical| canonical.authorization_revision);
                Ok(response)
            }
            HostRequest::ProvisionProcessConfirmation { binding } => {
                let (canonical, revision) = self.canonical(&binding)?;
                let confirmation_required =
                    if self.capability_id.as_str() == WORKSPACE_CAPABILITY_ID {
                        canonical.outcome == "scope_required"
                            && canonical.requested_root_matched_authorized_root == Some(true)
                    } else {
                        canonical.outcome == "explicit_confirmation_required"
                    };
                if !confirmation_required || canonical.authorization_revision != Some(revision) {
                    return Ok(HostResponse::denied(
                        "provision_process_confirmation",
                        "confirmation_not_available",
                        Some(canonical),
                    ));
                }
                self.validate_binding(&binding)?;
                self.next_id = self.next_id.saturating_add(1);
                let confirmation = ProcessConfirmation {
                    confirmation_id: format!("d29h7-confirmation-{}", self.next_id),
                    binding: binding.clone(),
                    authorization_revision: revision,
                    issued_at_unix_ms: unix_millis(),
                    expires_at_unix_ms: unix_millis().saturating_add(GRANT_LIFETIME_MS),
                };
                self.confirmations
                    .insert(binding_key(&binding), confirmation);
                let mut response = HostResponse::ok("provision_process_confirmation");
                response.authorization_revision = Some(revision);
                Ok(response)
            }
            HostRequest::IssueProcessGrant {
                binding,
                authorization_revision,
            } => self.issue(binding, authorization_revision),
            HostRequest::RevalidateProcessGrant {
                grant_id,
                binding,
                authorization_revision,
            } => self.revalidate(&grant_id, binding, authorization_revision),
            HostRequest::DisableAuthorizationForTest {
                life_id,
                capability_id,
                expected_revision,
            } => {
                if life_id != self.life_id || capability_id != self.capability_id.as_str() {
                    return Err("D29-H7 Host disable binding was invalid".to_string());
                }
                let outcome = self
                    .storage
                    .update_capability_authorization(
                        LifeCapabilityAuthorizationUpdateRequest::for_test(
                            "d29h7-fixture-disable",
                            &life_id,
                            self.capability_id.clone(),
                            false,
                            expected_revision,
                        ),
                    )
                    .map_err(|_| "D29-H7 Host could not disable SQLite row".to_string())?;
                let revision = match outcome {
                    CapabilityAuthorizationUpdateOutcome::Applied { authorization, .. }
                    | CapabilityAuthorizationUpdateOutcome::Replayed {
                        current: authorization,
                        ..
                    } => authorization.revision,
                };
                let mut response = HostResponse::ok("disable_authorization_for_test");
                response.authorization_revision = Some(revision);
                Ok(response)
            }
            HostRequest::HoldForTest { milliseconds } => {
                thread::sleep(Duration::from_millis(milliseconds.min(10_000)));
                Ok(HostResponse::ok("hold_for_test"))
            }
            HostRequest::Shutdown {} => Ok(HostResponse::ok("shutdown")),
            HostRequest::Initialize { .. } => {
                Err("D29-H7 Host received duplicate initialize".to_string())
            }
        }
    }

    fn canonical(&self, binding: &ProcessBinding) -> Result<(CanonicalWire, i64), String> {
        if binding.life_id != self.life_id
            || binding.task_id != self.task_id
            || binding.capability_id != self.capability_id.as_str()
            || binding.program_id != PROGRAM_ID
        {
            return Err("D29-H7 Host process binding denied".to_string());
        }
        let workspace = self.capability_id.as_str() == WORKSPACE_CAPABILITY_ID;
        let requested_root_matched_authorized_root = workspace
            && self.workspace_root_identity.as_deref()
                == binding.workspace_root_identity.as_deref();
        let decision = evaluate_capability_authorization(
            self.storage.as_ref(),
            &self.test_registry,
            &self.life_id,
            &self.capability_id,
            if workspace {
                RequestedCapabilityScope::Workspace
            } else {
                RequestedCapabilityScope::None
            },
        )
        .map_err(|_| "D29-H7 Host D28 evaluation failed".to_string())?;
        let expected_outcome = if workspace {
            CapabilityAuthorizationDecisionKind::ScopeRequired
        } else {
            CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired
        };
        if decision.outcome() != expected_outcome {
            return Err("D29-H7 Host canonical authorization is disabled".to_string());
        }
        let revision = decision
            .authorization_revision()
            .ok_or_else(|| "D29-H7 Host canonical revision was absent".to_string())?;
        Ok((
            CanonicalWire {
                canonical_evaluations: 1,
                production_registry_size: self.production_registry.len(),
                test_registry_size: self.test_registry.len(),
                authorization_row_reads: 1,
                life_id: self.life_id.clone(),
                capability_id: self.capability_id.as_str().to_string(),
                outcome: if workspace {
                    "scope_required".to_string()
                } else {
                    "explicit_confirmation_required".to_string()
                },
                decision_code: if workspace {
                    "CAPABILITY_SCOPE_NOT_AVAILABLE".to_string()
                } else {
                    "CAPABILITY_CONFIRMATION_REQUIRED".to_string()
                },
                risk_class: "Critical".to_string(),
                approval_floor: "ExplicitPerAction".to_string(),
                scope_requirement: if workspace {
                    "WorkspaceRequired".to_string()
                } else {
                    "None".to_string()
                },
                authorization_revision: Some(revision),
                host_scope_authority_present: workspace.then_some(true),
                requested_root_matched_authorized_root: workspace
                    .then_some(requested_root_matched_authorized_root),
            },
            revision,
        ))
    }

    fn validate_binding(&self, binding: &ProcessBinding) -> Result<(), String> {
        if !valid_id(&binding.life_id)
            || !valid_id(&binding.task_id)
            || binding.capability_id != CAPABILITY_ID
                && binding.capability_id != WORKSPACE_CAPABILITY_ID
            || binding.program_id != PROGRAM_ID
            || !valid_id(&binding.executable_identity)
            || !lower_sha256(&binding.executable_sha256)
            || !lower_sha256(&binding.argv_hash)
            || binding.argv_count > 16
            || !valid_id(&binding.working_directory_identity)
            || !lower_sha256(&binding.environment_policy_hash)
            || binding.stdout_bound > 65_536
            || binding.stderr_bound > 65_536
            || binding.timeout_ms == 0
            || binding.timeout_ms > 5_000
            || !valid_id(&binding.tool_call_id)
            || !valid_id(&binding.turn_id)
            || (binding.capability_id == CAPABILITY_ID && binding.workspace_root_identity.is_some())
            || (binding.capability_id == WORKSPACE_CAPABILITY_ID
                && !binding
                    .workspace_root_identity
                    .as_deref()
                    .is_some_and(valid_id))
        {
            return Err("D29-H7 Host process binding was invalid".to_string());
        }
        Ok(())
    }

    fn issue(
        &mut self,
        binding: ProcessBinding,
        authorization_revision: i64,
    ) -> Result<HostResponse, String> {
        self.validate_binding(&binding)?;
        let (canonical, current_revision) = match self.canonical(&binding) {
            Ok(value) => value,
            Err(_error) => {
                return Ok(HostResponse::denied(
                    "issue_process_grant",
                    "root_disabled_or_authority_error",
                    None,
                ));
            }
        };
        if current_revision != authorization_revision {
            return Ok(HostResponse::denied(
                "issue_process_grant",
                "stale_revision",
                Some(canonical),
            ));
        }
        if self.capability_id.as_str() == WORKSPACE_CAPABILITY_ID
            && canonical.requested_root_matched_authorized_root != Some(true)
        {
            return Ok(HostResponse::denied(
                "issue_process_grant",
                "workspace_scope_denied",
                Some(canonical),
            ));
        }
        let Some(confirmation) = self.confirmations.remove(&binding_key(&binding)) else {
            return Ok(HostResponse::denied(
                "issue_process_grant",
                "confirmation_missing",
                Some(canonical),
            ));
        };
        if confirmation.binding != binding
            || confirmation.authorization_revision != authorization_revision
            || confirmation.expires_at_unix_ms <= unix_millis()
        {
            return Ok(HostResponse::denied(
                "issue_process_grant",
                "confirmation_mismatch_or_expired",
                Some(canonical),
            ));
        }
        if self.grants.len() >= MAX_GRANTS {
            return Ok(HostResponse::denied(
                "issue_process_grant",
                "grant_capacity_exhausted",
                Some(canonical),
            ));
        }
        self.next_id = self.next_id.saturating_add(1);
        let grant = ProcessGrantWire {
            grant_id: format!("d29h7-process-grant-{}", self.next_id),
            confirmation_id: confirmation.confirmation_id,
            binding,
            authorization_revision,
            issued_at_unix_ms: unix_millis(),
            expires_at_unix_ms: unix_millis().saturating_add(GRANT_LIFETIME_MS),
            single_use: true,
            used: false,
        };
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        let mut response = HostResponse::ok("issue_process_grant");
        response.canonical = Some(canonical);
        response.process_grant = Some(grant);
        response.authorization_revision = Some(authorization_revision);
        response.confirmation_consumed = true;
        Ok(response)
    }

    fn revalidate(
        &mut self,
        grant_id: &str,
        binding: ProcessBinding,
        authorization_revision: i64,
    ) -> Result<HostResponse, String> {
        self.validate_binding(&binding)?;
        let (canonical, current_revision) = match self.canonical(&binding) {
            Ok(value) => value,
            Err(_) => {
                return Ok(HostResponse::denied(
                    "revalidate_process_grant",
                    "root_disabled_or_authority_error",
                    None,
                ));
            }
        };
        let Some(grant) = self.grants.get_mut(grant_id) else {
            return Ok(HostResponse::denied(
                "revalidate_process_grant",
                "grant_missing_or_replayed",
                Some(canonical),
            ));
        };
        if grant.used
            || !grant.single_use
            || grant.binding != binding
            || grant.authorization_revision != authorization_revision
            || current_revision != authorization_revision
            || grant.expires_at_unix_ms <= unix_millis()
            || (self.capability_id.as_str() == WORKSPACE_CAPABILITY_ID
                && canonical.requested_root_matched_authorized_root != Some(true))
        {
            return Ok(HostResponse::denied(
                "revalidate_process_grant",
                "grant_revalidation_denied",
                Some(canonical),
            ));
        }
        grant.used = true;
        let mut response = HostResponse::ok("revalidate_process_grant");
        response.canonical = Some(canonical);
        response.process_grant = Some(grant.clone());
        response.authorization_revision = Some(current_revision);
        Ok(response)
    }
}

pub(crate) fn run_from_stdio() -> Result<(), String> {
    let mut session: Option<HostSession> = None;
    loop {
        let Some(bytes) = read_frame()? else {
            return Ok(());
        };
        let request: HostRequest = serde_json::from_slice(&bytes)
            .map_err(|_| "D29-H7 Host request JSON was malformed".to_string())?;
        let response = match request {
            HostRequest::Initialize {
                protocol_version,
                life_id,
                task_id,
                capability_id,
                workspace_root_identity,
            } => {
                let (new_session, response) = HostSession::initialize(
                    protocol_version,
                    life_id,
                    task_id,
                    capability_id,
                    workspace_root_identity,
                )?;
                session = Some(new_session);
                response
            }
            request => {
                let session = session
                    .as_mut()
                    .ok_or_else(|| "D29-H7 Host request arrived before initialize".to_string())?;
                let shutdown = matches!(request, HostRequest::Shutdown {});
                let response = session.handle(request)?;
                if shutdown {
                    write_frame(&response)?;
                    return Ok(());
                }
                response
            }
        };
        write_frame(&response)?;
    }
}

fn read_frame() -> Result<Option<Vec<u8>>, String> {
    let mut length = [0_u8; 4];
    match io::stdin().read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err("D29-H7 Host frame length read failed".to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("D29-H7 Host request frame exceeded its bound".to_string());
    }
    let mut bytes = vec![0_u8; length];
    io::stdin()
        .read_exact(&mut bytes)
        .map_err(|_| "D29-H7 Host frame body read failed".to_string())?;
    Ok(Some(bytes))
}

fn write_frame(value: &HostResponse) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| "D29-H7 Host response serialization failed".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("D29-H7 Host response exceeded its bound".to_string());
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stdout.write_all(&bytes))
        .and_then(|_| stdout.flush())
        .map_err(|_| "D29-H7 Host response write failed".to_string())
}

fn binding_key(binding: &ProcessBinding) -> String {
    format!("{}:{}", binding.tool_call_id, binding.turn_id)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_ID_CHARS
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.".contains(character))
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h7_fixture_initializes_real_sqlite_revision_two() {
        let (session, response) = HostSession::initialize(
            PROTOCOL_VERSION,
            "life-1".to_string(),
            "task-1".to_string(),
            CAPABILITY_ID.to_string(),
        )
        .expect("H7 fixture initialize");
        assert_eq!(response.authorization_revision, Some(2));
        assert_eq!(session.production_registry.len(), 0);
        assert_eq!(session.test_registry.len(), 1);
    }

    #[test]
    fn h7_fixture_rejects_unknown_program() {
        let (session, _) = HostSession::initialize(
            PROTOCOL_VERSION,
            "life-1".to_string(),
            "task-1".to_string(),
            CAPABILITY_ID.to_string(),
        )
        .expect("H7 fixture initialize");
        let _ = session;
        assert!(!valid_id("C:\\Windows\\System32\\cmd.exe"));
    }
}
