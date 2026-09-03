//! Process-isolated D29-H1 host authority fixture.
//!
//! This is a test-only executable boundary.  It uses the normal Host graph
//! and the canonical D28 registry, repository, and evaluator, but it is not a
//! Tauri command or a production route.  The Vita-side canary starts it as a
//! bounded child process and exchanges one small JSON request/response over
//! stdin/stdout.

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
use super::descriptor::{CapabilityId, CapabilityRegistry};
use crate::storage::StorageService;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_ID_CHARS: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRequest {
    life_id: String,
    capability_id: String,
    requested_scope: String,
}

struct FixtureRoot(PathBuf);

impl FixtureRoot {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "digital-life-d29h1-authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "D29-H1 host fixture clock is before the Unix epoch".to_string())?
                .as_nanos()
        ));
        std::fs::create_dir(&path).map_err(|_| {
            "D29-H1 host fixture could not create its private temp root".to_string()
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

/// Runs one canonical authority lookup and writes one bounded response.
pub(crate) fn run_from_stdio() -> Result<(), String> {
    let request = read_request()?;
    validate_wire_identity(&request.life_id)?;
    let capability_id = CapabilityId::try_from(request.capability_id.clone())
        .map_err(|_| "D29-H1 host fixture received an invalid capability id".to_string())?;
    let requested_scope = parse_scope(&request.requested_scope)?;

    let root = FixtureRoot::create()?;
    let storage = Arc::new(
        StorageService::initialize_with_roots(root.path().to_path_buf(), None).map_err(|_| {
            "D29-H1 host fixture could not initialize canonical storage".to_string()
        })?,
    );
    let row_reads = Arc::new(AtomicUsize::new(0));
    let repository = CountingAuthorizationRepository {
        storage: Arc::clone(&storage),
        row_reads: Arc::clone(&row_reads),
    };
    let registry = CapabilityRegistry::production()
        .map_err(|_| "D29-H1 host fixture could not build the production registry".to_string())?;

    let evaluation = evaluate_capability_authorization(
        &repository,
        &registry,
        &request.life_id,
        &capability_id,
        requested_scope,
    );
    let result = match evaluation {
        Ok(_) => "Decision",
        Err(error) => canonical_error_name(error.code),
    };
    let response = json!({
        "canonical_evaluations": 1,
        "production_registry_size": registry.len(),
        "authorization_row_reads": row_reads.load(Ordering::Acquire),
        "result": result,
        "life_id": request.life_id,
        "capability_id": capability_id.as_str(),
        "requested_scope": scope_name(requested_scope),
    });

    let mut stdout = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut stdout, &response)
        .map_err(|_| "D29-H1 host fixture could not serialize its bounded response".to_string())?;
    stdout
        .write_all(b"\n")
        .map_err(|_| "D29-H1 host fixture could not write its bounded response".to_string())?;
    stdout
        .flush()
        .map_err(|_| "D29-H1 host fixture could not flush its bounded response".to_string())?;
    Ok(())
}

fn read_request() -> Result<AuthorityRequest, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "D29-H1 host fixture could not read its bounded request".to_string())?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("D29-H1 host fixture request exceeded its bounded size".to_string());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "D29-H1 host fixture received malformed bounded JSON".to_string())
}

fn validate_wire_identity(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_ID_CHARS
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("D29-H1 host fixture received an invalid life identity".to_string());
    }
    Ok(())
}

fn parse_scope(value: &str) -> Result<RequestedCapabilityScope, String> {
    match value {
        "none" => Ok(RequestedCapabilityScope::None),
        "workspace" => Ok(RequestedCapabilityScope::Workspace),
        "network_destination" => Ok(RequestedCapabilityScope::NetworkDestination),
        "external_resource" => Ok(RequestedCapabilityScope::ExternalResource),
        _ => Err("D29-H1 host fixture received an invalid requested scope".to_string()),
    }
}

fn scope_name(scope: RequestedCapabilityScope) -> &'static str {
    match scope {
        RequestedCapabilityScope::None => "none",
        RequestedCapabilityScope::Workspace => "workspace",
        RequestedCapabilityScope::NetworkDestination => "network_destination",
        RequestedCapabilityScope::ExternalResource => "external_resource",
    }
}

fn canonical_error_name(code: CapabilityEvaluationErrorCode) -> &'static str {
    match code {
        CapabilityEvaluationErrorCode::InvalidArgument => "InvalidArgument",
        CapabilityEvaluationErrorCode::UnknownCapability => "UnknownCapability",
        CapabilityEvaluationErrorCode::AuthorizationUnavailable => "AuthorizationUnavailable",
        CapabilityEvaluationErrorCode::NotEligible => "NotEligible",
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
