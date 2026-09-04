//! Process-isolated D29-H3 canonical authority fixture.
//!
//! This executable is built only with the D29-H3 test feature.  It creates a
//! private fixture database, constructs a test-only trusted descriptor and an
//! explicit user authorization row, and then calls the unchanged D28
//! evaluator.  It is not a production descriptor, registry entry, Tauri
//! command, or grant issuer.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use super::authorization::{
    evaluate_capability_authorization, CapabilityAuthorizationCreateOutcome,
    CapabilityAuthorizationError, CapabilityAuthorizationRepository,
    CapabilityAuthorizationUpdateOutcome, CapabilityEvaluationErrorCode,
    LifeCapabilityAuthorization, LifeCapabilityAuthorizationCreateRequest,
    LifeCapabilityAuthorizationEvent, LifeCapabilityAuthorizationUpdateRequest,
    RequestedCapabilityScope,
};
use super::descriptor::{
    ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, RiskClass,
    ScopeRequirement,
};
use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_ID_CHARS: usize = 128;
const H3_CAPABILITY_ID: &str = "vita.workspace.read_file";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRequest {
    life_id: String,
    task_id: String,
    capability_id: String,
    d28_requested_scope: String,
    authorized_scope: String,
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "digital-life-d29h3-authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "D29-H3 host fixture clock is before the Unix epoch".to_string())?
                .as_nanos()
        ));
        std::fs::create_dir(&path).map_err(|_| {
            "D29-H3 host fixture could not create its private temp root".to_string()
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

/// Runs one bounded canonical D28 evaluation and writes one bounded response.
pub(crate) fn run_from_stdio() -> Result<(), String> {
    let request = read_request()?;
    validate_identity("life", &request.life_id)?;
    validate_identity("task", &request.task_id)?;
    if request.d28_requested_scope != "none" || request.authorized_scope != "workspace" {
        return write_response(json!({
            "canonical_evaluations": 1,
            "production_registry_size": 0,
            "test_registry_size": 0,
            "authorization_row_reads": 0,
            "result": "InvalidArgument",
            "decision_code": "CAPABILITY_AUTHORIZATION_DENIED",
            "authorization_revision": null,
            "life_id": request.life_id,
            "task_id": request.task_id,
            "capability_id": request.capability_id,
            "d28_requested_scope": request.d28_requested_scope,
            "authorized_scope": request.authorized_scope,
        }));
    }
    if request.capability_id != H3_CAPABILITY_ID {
        return Err("D29-H3 host fixture received a non-static capability id".to_string());
    }

    let capability_id = CapabilityId::try_from(request.capability_id.clone())
        .map_err(|_| "D29-H3 host fixture received an invalid capability id".to_string())?;
    let root = FixtureRoot::create()?;
    let storage = Arc::new(
        StorageService::initialize_with_roots(root.path().to_path_buf(), None).map_err(|_| {
            "D29-H3 host fixture could not initialize canonical storage".to_string()
        })?,
    );
    storage
        .save_persona(PersonaTemplateRecord {
            id: "d29h3-persona".to_string(),
            name: "D29-H3 fixture persona".to_string(),
            version: 1,
            persona_json: "{}".to_string(),
        })
        .map_err(|_| "D29-H3 host fixture could not create its fixture persona".to_string())?;
    storage
        .save_life(LifeIdentityRecord {
            id: request.life_id.clone(),
            name: "D29-H3 fixture life".to_string(),
            created_at: "2026-09-04T00:00:00.000Z".to_string(),
            version: 1,
            body_id: "d29h3-body".to_string(),
            persona_id: "d29h3-persona".to_string(),
            persona_version: 1,
        })
        .map_err(|_| "D29-H3 host fixture could not create its fixture life".to_string())?;

    // This descriptor and authorization are test-fixture inputs only.  The
    // production registry remains independently constructed and empty.
    let descriptor = CapabilityDescriptor::synthetic(
        capability_id.clone(),
        "D29-H3 test workspace read",
        RiskClass::Low,
        ApprovalFloor::RootEnabled,
        ScopeRequirement::None,
    )
    .map_err(|_| "D29-H3 host fixture could not construct its descriptor".to_string())?;
    let test_registry = CapabilityRegistry::synthetic([descriptor])
        .map_err(|_| "D29-H3 host fixture could not construct its test registry".to_string())?;
    let production_registry = CapabilityRegistry::production()
        .map_err(|_| "D29-H3 host fixture could not build the production registry".to_string())?;

    match storage
        .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
            life_id: request.life_id.clone(),
            capability_id: capability_id.clone(),
        })
        .map_err(|_| "D29-H3 host fixture could not create its authorization root".to_string())?
    {
        CapabilityAuthorizationCreateOutcome::Applied(_) => {}
        CapabilityAuthorizationCreateOutcome::Replayed(_) => {
            return Err("D29-H3 fixture authorization unexpectedly replayed".to_string())
        }
    }
    match storage
        .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest::for_test(
            "d29h3-fixture-enable",
            &request.life_id,
            capability_id.clone(),
            true,
            1,
        ))
        .map_err(|_| "D29-H3 host fixture could not enable its authorization root".to_string())?
    {
        CapabilityAuthorizationUpdateOutcome::Applied { .. } => {}
        CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
            return Err("D29-H3 fixture authorization update unexpectedly replayed".to_string())
        }
    }

    let row_reads = Arc::new(AtomicUsize::new(0));
    let repository = CountingAuthorizationRepository {
        storage,
        row_reads: Arc::clone(&row_reads),
    };
    let decision = evaluate_capability_authorization(
        &repository,
        &test_registry,
        &request.life_id,
        &capability_id,
        RequestedCapabilityScope::None,
    )
    .map_err(|_| "D29-H3 host fixture canonical evaluator failed".to_string())?;
    let result = decision.outcome();
    let response = json!({
        "canonical_evaluations": 1,
        "production_registry_size": production_registry.len(),
        "test_registry_size": test_registry.len(),
        "authorization_row_reads": row_reads.load(Ordering::Acquire),
        "result": if result == super::authorization::CapabilityAuthorizationDecisionKind::Eligible { "Eligible" } else { "Denied" },
        "decision_code": decision.decision_code().as_str(),
        "authorization_revision": decision.authorization_revision(),
        "life_id": request.life_id,
        "task_id": request.task_id,
        "capability_id": capability_id.as_str(),
        "d28_requested_scope": "none",
        "authorized_scope": "workspace",
    });
    write_response(response)
}

fn write_response(response: serde_json::Value) -> Result<(), String> {
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut stdout, &response)
        .map_err(|_| "D29-H3 host fixture could not serialize its response".to_string())?;
    stdout
        .write_all(b"\n")
        .map_err(|_| "D29-H3 host fixture could not write its response".to_string())?;
    stdout
        .flush()
        .map_err(|_| "D29-H3 host fixture could not flush its response".to_string())
}

fn read_request() -> Result<AuthorityRequest, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "D29-H3 host fixture could not read its request".to_string())?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("D29-H3 host fixture request exceeded its bounded size".to_string());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "D29-H3 host fixture received malformed bounded JSON".to_string())
}

fn validate_identity(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_ID_CHARS
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!(
            "D29-H3 host fixture received an invalid {field} identity"
        ));
    }
    Ok(())
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

#[allow(dead_code)]
fn _canonical_error_name(code: CapabilityEvaluationErrorCode) -> &'static str {
    match code {
        CapabilityEvaluationErrorCode::InvalidArgument => "InvalidArgument",
        CapabilityEvaluationErrorCode::UnknownCapability => "UnknownCapability",
        CapabilityEvaluationErrorCode::AuthorizationUnavailable => "AuthorizationUnavailable",
        CapabilityEvaluationErrorCode::NotEligible => "NotEligible",
    }
}
