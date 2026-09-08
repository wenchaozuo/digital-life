//! Process-isolated D29-H5-B Host recovery-authority fixture.
//!
//! This fixture is test/integration-only.  It owns the canonical D28 SQLite
//! row and the independent recovery confirmation/grant stores.  It never
//! writes a workspace target and it never exposes a production descriptor.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

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
const MAX_ID_CHARS: usize = 512;
const MAX_GRANTS: usize = 256;
const GRANT_LIFETIME_MS: u64 = 30_000;
const CAPABILITY_ID: &str = "vita.workspace.recover_replace";

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
    ProvisionRecoveryConfirmation {
        confirmation_id: String,
        action_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        transaction_id: String,
        journal_integrity_hash: String,
        current_sha256: String,
        current_bytes: u64,
        restore_sha256: String,
        restore_bytes: u64,
        original_replacement_sha256: String,
    },
    IssueRecoveryGrant {
        action_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        transaction_id: String,
        journal_integrity_hash: String,
        current_sha256: String,
        current_bytes: u64,
        restore_sha256: String,
        restore_bytes: u64,
        original_replacement_sha256: String,
    },
    RevalidateRecoveryGrant {
        grant_id: String,
        action_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        transaction_id: String,
        journal_integrity_hash: String,
        current_sha256: String,
        current_bytes: u64,
        restore_sha256: String,
        restore_bytes: u64,
        original_replacement_sha256: String,
    },
    DisableAuthorizationForTest {
        life_id: String,
        capability_id: String,
        expected_revision: i64,
    },
    Shutdown {},
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RecoveryBinding {
    action_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    authorization_revision: i64,
    workspace_root_identity: String,
    relative_path: String,
    target_identity: String,
    transaction_id: String,
    journal_integrity_hash: String,
    current_sha256: String,
    current_bytes: u64,
    restore_sha256: String,
    restore_bytes: u64,
    original_replacement_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RecoveryConfirmation {
    confirmation_id: String,
    binding: RecoveryBinding,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RecoveryGrant {
    grant_id: String,
    confirmation_id: String,
    binding: RecoveryBinding,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
    used: bool,
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "digital-life-d29h5-authority-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir(&path)
            .map_err(|_| "D29-H5 Host fixture could not create its private root".to_string())?;
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
    allowed_workspace_root_identity: String,
    confirmations: HashMap<String, RecoveryConfirmation>,
    grants: HashMap<String, RecoveryGrant>,
    next_id: u64,
}

impl HostSession {
    fn initialize(
        protocol_version: u8,
        life_id: String,
        task_id: String,
        capability_id: String,
        allowed_workspace_root_identity: String,
    ) -> Result<(Self, serde_json::Value), String> {
        if protocol_version != PROTOCOL_VERSION
            || !valid_id(&life_id)
            || !valid_id(&task_id)
            || capability_id != CAPABILITY_ID
            || !valid_id(&allowed_workspace_root_identity)
        {
            return Err("D29-H5 Host initialize binding was invalid".to_string());
        }
        let capability_id = CapabilityId::try_from(capability_id)
            .map_err(|_| "D29-H5 Host capability ID was invalid".to_string())?;
        let root = FixtureRoot::create()?;
        let storage = Arc::new(
            StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .map_err(|_| "D29-H5 Host could not initialize SQLite".to_string())?,
        );
        storage
            .save_persona(PersonaTemplateRecord {
                id: "d29h5-persona".to_string(),
                name: "D29-H5-B fixture persona".to_string(),
                version: 1,
                persona_json: "{}".to_string(),
            })
            .map_err(|_| "D29-H5 Host could not create its persona".to_string())?;
        storage
            .save_life(LifeIdentityRecord {
                id: life_id.clone(),
                name: "D29-H5-B fixture life".to_string(),
                created_at: "2026-09-08T00:00:00.000Z".to_string(),
                version: 1,
                body_id: "d29h5-body".to_string(),
                persona_id: "d29h5-persona".to_string(),
                persona_version: 1,
            })
            .map_err(|_| "D29-H5 Host could not create its life".to_string())?;
        let descriptor = CapabilityDescriptor::synthetic(
            capability_id.clone(),
            "D29-H5-B governed recovery replace",
            RiskClass::High,
            ApprovalFloor::ExplicitPerAction,
            ScopeRequirement::WorkspaceRequired,
        )
        .map_err(|_| "D29-H5 Host could not construct its descriptor".to_string())?;
        let test_registry = CapabilityRegistry::synthetic([descriptor])
            .map_err(|_| "D29-H5 Host could not construct its test registry".to_string())?;
        let production_registry = CapabilityRegistry::production()
            .map_err(|_| "D29-H5 Host could not construct production registry".to_string())?;
        match storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: life_id.clone(),
                capability_id: capability_id.clone(),
            })
            .map_err(|_| "D29-H5 Host could not create authorization root".to_string())?
        {
            CapabilityAuthorizationCreateOutcome::Applied(_) => {}
            CapabilityAuthorizationCreateOutcome::Replayed(_) => {
                return Err("D29-H5 Host authorization root unexpectedly replayed".to_string())
            }
        }
        match storage
            .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest::for_test(
                "d29h5-fixture-enable",
                &life_id,
                capability_id.clone(),
                true,
                1,
            ))
            .map_err(|_| "D29-H5 Host could not enable authorization root".to_string())?
        {
            CapabilityAuthorizationUpdateOutcome::Applied { .. } => {}
            CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
                return Err("D29-H5 Host authorization enable unexpectedly replayed".to_string())
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
            allowed_workspace_root_identity,
            confirmations: HashMap::new(),
            grants: HashMap::new(),
            next_id: 0,
        };
        Ok((
            session,
            json!({
                "operation": "initialize",
                "status": "ok",
                "production_registry_size": 0,
                "test_registry_size": 1,
                "authorization_revision": 2,
                "same_sqlite_row": true,
            }),
        ))
    }

    fn handle(&mut self, request: HostRequest) -> Result<serde_json::Value, String> {
        match request {
            HostRequest::ProvisionRecoveryConfirmation {
                confirmation_id,
                action_id,
                life_id,
                task_id,
                capability_id,
                authorization_revision,
                workspace_root_identity,
                relative_path,
                target_identity,
                transaction_id,
                journal_integrity_hash,
                current_sha256,
                current_bytes,
                restore_sha256,
                restore_bytes,
                original_replacement_sha256,
            } => {
                let binding = RecoveryBinding {
                    action_id,
                    life_id,
                    task_id,
                    capability_id,
                    authorization_revision,
                    workspace_root_identity,
                    relative_path,
                    target_identity,
                    transaction_id,
                    journal_integrity_hash,
                    current_sha256,
                    current_bytes,
                    restore_sha256,
                    restore_bytes,
                    original_replacement_sha256,
                };
                self.validate_binding(&binding)?;
                self.confirmations.insert(
                    binding.action_id.clone(),
                    RecoveryConfirmation {
                        confirmation_id,
                        binding,
                        issued_at_unix_ms: unix_millis(),
                        expires_at_unix_ms: unix_millis().saturating_add(GRANT_LIFETIME_MS),
                    },
                );
                Ok(json!({
                    "operation": "provision_recovery_confirmation",
                    "status": "ok",
                    "trusted_confirmation": true,
                    "request_derived_confirmation": false,
                }))
            }
            HostRequest::IssueRecoveryGrant {
                action_id,
                life_id,
                task_id,
                capability_id,
                authorization_revision,
                workspace_root_identity,
                relative_path,
                target_identity,
                transaction_id,
                journal_integrity_hash,
                current_sha256,
                current_bytes,
                restore_sha256,
                restore_bytes,
                original_replacement_sha256,
            } => {
                let binding = RecoveryBinding {
                    action_id,
                    life_id,
                    task_id,
                    capability_id,
                    authorization_revision,
                    workspace_root_identity,
                    relative_path,
                    target_identity,
                    transaction_id,
                    journal_integrity_hash,
                    current_sha256,
                    current_bytes,
                    restore_sha256,
                    restore_bytes,
                    original_replacement_sha256,
                };
                self.issue(binding)
            }
            HostRequest::RevalidateRecoveryGrant {
                grant_id,
                action_id,
                life_id,
                task_id,
                capability_id,
                authorization_revision,
                workspace_root_identity,
                relative_path,
                target_identity,
                transaction_id,
                journal_integrity_hash,
                current_sha256,
                current_bytes,
                restore_sha256,
                restore_bytes,
                original_replacement_sha256,
            } => {
                let binding = RecoveryBinding {
                    action_id,
                    life_id,
                    task_id,
                    capability_id,
                    authorization_revision,
                    workspace_root_identity,
                    relative_path,
                    target_identity,
                    transaction_id,
                    journal_integrity_hash,
                    current_sha256,
                    current_bytes,
                    restore_sha256,
                    restore_bytes,
                    original_replacement_sha256,
                };
                self.revalidate(&grant_id, binding)
            }
            HostRequest::DisableAuthorizationForTest {
                life_id,
                capability_id,
                expected_revision,
            } => {
                if life_id != self.life_id || capability_id != self.capability_id.as_str() {
                    return Err("D29-H5 Host disable binding was invalid".to_string());
                }
                let outcome = self
                    .storage
                    .update_capability_authorization(
                        LifeCapabilityAuthorizationUpdateRequest::for_test(
                            "d29h5-fixture-disable",
                            &life_id,
                            self.capability_id.clone(),
                            false,
                            expected_revision,
                        ),
                    )
                    .map_err(|_| "D29-H5 Host could not disable SQLite row".to_string())?;
                let revision = match outcome {
                    CapabilityAuthorizationUpdateOutcome::Applied { authorization, .. }
                    | CapabilityAuthorizationUpdateOutcome::Replayed {
                        current: authorization,
                        ..
                    } => authorization.revision,
                };
                Ok(json!({
                    "operation": "disable_authorization_for_test",
                    "status": "ok",
                    "authorization_revision": revision,
                    "same_sqlite_row": true,
                }))
            }
            HostRequest::Shutdown {} => Ok(json!({
                "operation": "shutdown",
                "status": "ok",
            })),
            HostRequest::Initialize { .. } => {
                Err("D29-H5 Host received duplicate initialize".to_string())
            }
        }
    }

    fn canonical(&self, binding: &RecoveryBinding) -> Result<i64, String> {
        if binding.life_id != self.life_id
            || binding.task_id != self.task_id
            || binding.capability_id != self.capability_id.as_str()
            || binding.workspace_root_identity != self.allowed_workspace_root_identity
        {
            return Err("D29-H5 Host workspace scope binding denied".to_string());
        }
        let decision = evaluate_capability_authorization(
            self.storage.as_ref(),
            &self.test_registry,
            &self.life_id,
            &self.capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|_| "D29-H5 Host D28 evaluation failed".to_string())?;
        if decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired {
            return Err("D29-H5 Host canonical authorization is disabled".to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "D29-H5 Host canonical revision was absent".to_string())
    }

    fn validate_binding(&self, binding: &RecoveryBinding) -> Result<(), String> {
        if !valid_id(&binding.action_id)
            || !valid_id(&binding.life_id)
            || !valid_id(&binding.task_id)
            || binding.capability_id != CAPABILITY_ID
            || !valid_id(&binding.workspace_root_identity)
            || !valid_id(&binding.target_identity)
            || !valid_id(&binding.transaction_id)
            || !valid_id(&binding.journal_integrity_hash)
            || !valid_id(&binding.current_sha256)
            || !valid_id(&binding.restore_sha256)
            || !valid_id(&binding.original_replacement_sha256)
            || binding.relative_path.is_empty()
            || binding.current_bytes > 64 * 1024
            || binding.restore_bytes > 64 * 1024
        {
            return Err("D29-H5 Host recovery binding was invalid".to_string());
        }
        Ok(())
    }

    fn issue(&mut self, binding: RecoveryBinding) -> Result<serde_json::Value, String> {
        self.validate_binding(&binding)?;
        let revision = match self.canonical(&binding) {
            Ok(revision) => revision,
            Err(error) => {
                return Ok(json!({
                    "operation": "issue_recovery_grant",
                    "status": "denied",
                    "denial": "authorization_disabled_or_scope_denied",
                    "error": error,
                }))
            }
        };
        if revision != binding.authorization_revision {
            return Ok(json!({
                "operation": "issue_recovery_grant",
                "status": "denied",
                "denial": "stale_revision",
            }));
        }
        if self.grants.len() >= MAX_GRANTS {
            return Ok(json!({
                "operation": "issue_recovery_grant",
                "status": "denied",
                "denial": "grant_capacity_exhausted",
            }));
        }
        let confirmation = match self.confirmations.get(&binding.action_id).cloned() {
            Some(confirmation) if confirmation.binding == binding => confirmation,
            Some(_) => {
                return Ok(json!({
                    "operation": "issue_recovery_grant",
                    "status": "denied",
                    "denial": "confirmation_mismatch",
                }))
            }
            None => {
                return Ok(json!({
                    "operation": "issue_recovery_grant",
                    "status": "denied",
                    "denial": "confirmation_missing",
                }))
            }
        };
        if confirmation.expires_at_unix_ms <= unix_millis() {
            return Ok(json!({
                "operation": "issue_recovery_grant",
                "status": "denied",
                "denial": "confirmation_expired",
            }));
        }
        self.confirmations.remove(&binding.action_id);
        self.next_id = self.next_id.saturating_add(1);
        let now = unix_millis();
        let grant = RecoveryGrant {
            grant_id: format!("d29h5-host-grant-{}", self.next_id),
            confirmation_id: confirmation.confirmation_id.clone(),
            binding,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(GRANT_LIFETIME_MS),
            single_use: true,
            used: false,
        };
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(json!({
            "operation": "issue_recovery_grant",
            "status": "ok",
            "authorization_revision": revision,
            "confirmation": confirmation,
            "recovery_grant": grant,
            "confirmation_consumed": true,
            "production_registry_size": self.production_registry.len(),
            "test_registry_size": self.test_registry.len(),
        }))
    }

    fn revalidate(
        &mut self,
        grant_id: &str,
        binding: RecoveryBinding,
    ) -> Result<serde_json::Value, String> {
        self.validate_binding(&binding)?;
        let revision = match self.canonical(&binding) {
            Ok(revision) => revision,
            Err(_) => {
                return Ok(json!({
                    "operation": "revalidate_recovery_grant",
                    "status": "denied",
                    "denial": "root_disabled_or_scope_denied",
                    "modifying_syscalls": 0,
                }))
            }
        };
        let Some(grant) = self.grants.get_mut(grant_id) else {
            return Ok(json!({
                "operation": "revalidate_recovery_grant",
                "status": "denied",
                "denial": "recovery_grant_replay_or_missing",
            }));
        };
        if grant.used
            || !grant.single_use
            || grant.binding != binding
            || grant.binding.authorization_revision != revision
            || grant.expires_at_unix_ms <= unix_millis()
        {
            return Ok(json!({
                "operation": "revalidate_recovery_grant",
                "status": "denied",
                "denial": "recovery_grant_revalidation_denied",
            }));
        }
        grant.used = true;
        Ok(json!({
            "operation": "revalidate_recovery_grant",
            "status": "ok",
            "authorization_revision": revision,
            "recovery_grant": grant,
        }))
    }
}

/// Runs the bounded length-prefixed Host fixture protocol.
pub(crate) fn run_from_stdio() -> Result<(), String> {
    let mut session: Option<HostSession> = None;
    loop {
        let Some(bytes) = read_frame()? else {
            return Ok(());
        };
        let request: HostRequest = serde_json::from_slice(&bytes)
            .map_err(|_| "D29-H5 Host request JSON was malformed".to_string())?;
        let response = match request {
            HostRequest::Initialize {
                protocol_version,
                life_id,
                task_id,
                capability_id,
                allowed_workspace_root_identity,
            } => {
                let (new_session, response) = HostSession::initialize(
                    protocol_version,
                    life_id,
                    task_id,
                    capability_id,
                    allowed_workspace_root_identity,
                )?;
                session = Some(new_session);
                response
            }
            request => {
                let session = session
                    .as_mut()
                    .ok_or_else(|| "D29-H5 Host request arrived before initialize".to_string())?;
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
        Err(_) => return Err("D29-H5 Host frame length read failed".to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("D29-H5 Host request frame exceeded its bound".to_string());
    }
    let mut bytes = vec![0_u8; length];
    io::stdin()
        .read_exact(&mut bytes)
        .map_err(|_| "D29-H5 Host frame body read failed".to_string())?;
    Ok(Some(bytes))
}

fn write_frame(value: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| "D29-H5 Host response serialization failed".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("D29-H5 Host response exceeded its bound".to_string());
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stdout.write_all(&bytes))
        .and_then(|_| stdout.flush())
        .map_err(|_| "D29-H5 Host response write failed".to_string())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_ID_CHARS
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:\\".contains(character))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

#[cfg(all(test, feature = "d29-h5-host-fixture"))]
mod tests {
    use super::*;

    fn binding() -> RecoveryBinding {
        RecoveryBinding {
            action_id: "action-1".to_string(),
            life_id: "life-1".to_string(),
            task_id: "task-1".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            authorization_revision: 2,
            workspace_root_identity: "root-1".to_string(),
            relative_path: "notes.txt".to_string(),
            target_identity: "target-1".to_string(),
            transaction_id: "tx-1".to_string(),
            journal_integrity_hash: "journal-hash-1".to_string(),
            current_sha256: "current-hash-1".to_string(),
            current_bytes: 4,
            restore_sha256: "restore-hash-1".to_string(),
            restore_bytes: 5,
            original_replacement_sha256: "replacement-hash-1".to_string(),
        }
    }

    fn initialize() -> HostSession {
        let (session, response) = HostSession::initialize(
            PROTOCOL_VERSION,
            "life-1".to_string(),
            "task-1".to_string(),
            CAPABILITY_ID.to_string(),
            "root-1".to_string(),
        )
        .expect("fixture initialize");
        assert_eq!(response["same_sqlite_row"], true);
        assert_eq!(response["authorization_revision"], 2);
        session
    }

    #[test]
    fn same_sqlite_row_revision_revalidation_denies_without_mutation() {
        let mut session = initialize();
        let binding = binding();
        let confirmation_id = "confirmation-1".to_string();
        let provision = session
            .handle(HostRequest::ProvisionRecoveryConfirmation {
                confirmation_id,
                action_id: binding.action_id.clone(),
                life_id: binding.life_id.clone(),
                task_id: binding.task_id.clone(),
                capability_id: binding.capability_id.clone(),
                authorization_revision: binding.authorization_revision,
                workspace_root_identity: binding.workspace_root_identity.clone(),
                relative_path: binding.relative_path.clone(),
                target_identity: binding.target_identity.clone(),
                transaction_id: binding.transaction_id.clone(),
                journal_integrity_hash: binding.journal_integrity_hash.clone(),
                current_sha256: binding.current_sha256.clone(),
                current_bytes: binding.current_bytes,
                restore_sha256: binding.restore_sha256.clone(),
                restore_bytes: binding.restore_bytes,
                original_replacement_sha256: binding.original_replacement_sha256.clone(),
            })
            .expect("provision confirmation");
        assert_eq!(provision["trusted_confirmation"], true);

        let issued = session.issue(binding.clone()).expect("issue grant");
        assert_eq!(issued["status"], "ok");
        let grant_id = issued["recovery_grant"]["grant_id"]
            .as_str()
            .expect("grant id")
            .to_string();

        let disabled = session
            .handle(HostRequest::DisableAuthorizationForTest {
                life_id: binding.life_id.clone(),
                capability_id: binding.capability_id.clone(),
                expected_revision: 2,
            })
            .expect("disable canonical SQLite row");
        assert_eq!(disabled["same_sqlite_row"], true);
        assert_eq!(disabled["authorization_revision"], 3);

        let revalidated = session
            .revalidate(&grant_id, binding)
            .expect("revalidate after same-SQLite disable");
        assert_eq!(revalidated["status"], "denied");
        assert_eq!(revalidated["denial"], "root_disabled_or_scope_denied");
        assert_eq!(revalidated["modifying_syscalls"], 0);
    }
}
