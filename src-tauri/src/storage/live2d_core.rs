//! D22-D1 SQLite-authoritative managed Cubism Core provisioning authority.
//!
//! Trust chain (fail closed at every hop):
//!
//! ```text
//! user-selected official Core file
//!   -> bounded read + SHA-256
//!   -> exact match against the compiled production allowlist
//!   -> staged copy + rehash verification
//!   -> promote into the managed active directory
//!   -> register the component row in Migration026 (single command)
//!   -> main-only `digital-life-core` protocol serving with serve-time
//!      integrity (DB row + managed path + file hash + allowlist presence)
//! ```
//!
//! The production allowlist intentionally contains ZERO approved hashes in
//! D22-D1: no proprietary Cubism Core file is committed, downloaded, or
//! copied into fixtures, and no SHA-256 is fabricated.  The import command
//! therefore fails closed (`LIVE2D_CORE_UNAPPROVED`) until D22-D2 adds an
//! independently verified official entry.  A test-only allowlist exists
//! exclusively under `#[cfg(test)]` and can never compile into production.
//!
//! The table stores no original user path, no remote URL, no script URL, and
//! no JavaScript source text.  The original source absolute path is transient
//! untrusted input and is never persisted.

use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    http::{header, Method, Request, Response, StatusCode},
    State,
};

use super::{unique_suffix, StorageError, StorageService};

pub(crate) const CORE_ASSET_PROTOCOL_SCHEME: &str = "digital-life-core";
pub(crate) const CORE_RENDERER_WEBVIEW_LABEL: &str = "main";
pub(crate) const CORE_COMPONENT_SLOT: &str = "active";
pub(crate) const CORE_RUNTIME_FAMILY: &str = "cubism4";
pub(crate) const CORE_FIXED_RESOURCE_NAME: &str = "live2dcubismcore.min.js";
pub(crate) const MANAGED_CORE_DIRECTORY: &str = "live2d";
pub(crate) const MANAGED_CORE_SUBDIRECTORY: &str = "core";
pub(crate) const MANAGED_CORE_STAGING_DIRECTORY: &str = "staging";
pub(crate) const MANAGED_CORE_ACTIVE_DIRECTORY: &str = "active";

/// Conservative bounded maximum for the official Cubism Core Web JavaScript.
/// Applied to real bytes read, never merely to filesystem metadata.
pub(crate) const MAX_CORE_BYTES: u64 = 2 * 1024 * 1024;

#[cfg(any(test, target_os = "windows", target_os = "android"))]
const WINDOWS_ANDROID_CORE_ORIGIN: &str = "http://digital-life-core.localhost/";
#[cfg(any(test, not(any(target_os = "windows", target_os = "android"))))]
const MAC_LINUX_CORE_ORIGIN: &str = "digital-life-core://localhost/";

pub(crate) const MIGRATION_026_TABLE_SQLS: &[&str] = &[include_str!(
    "migrations/026_live2d_core_component_authority.live2d_core_component.sql"
)];

pub(crate) const MIGRATION_026_TRIGGER_SQLS: &[&str] = &[include_str!(
    "migrations/026_live2d_core_component_authority.live2d_core_component_immutable_trigger.sql"
)];

/// One immutable production-approved Cubism Core identity.  Trust authority
/// is the exact lowercase SHA-256 of the real bytes; filename/size are never
/// trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApprovedCubismCore {
    pub(crate) runtime_family: &'static str,
    pub(crate) version_label: &'static str,
    pub(crate) sha256: &'static str,
}

/// D22-D1 production allowlist: intentionally EMPTY.  No production-approved
/// proprietary Core hash exists yet; D22-D2 adds entries only from
/// independently verified official provenance.  This array is private and
/// immutable; no frontend or IPC can supply or extend it.
const PRODUCTION_APPROVED_CORES: &[ApprovedCubismCore] = &[];

/// Test-only allowlist seam.  The fixture is an inert, harmless byte string
/// (never a Cubism Core implementation) whose hash proves the matching,
/// managed-copy, serving, and descriptor flows.  It can never compile into
/// the production allowlist; an explicit test below enforces that.
#[cfg(test)]
const TEST_FIXTURE_CORE_BYTES: &[u8] = b"/* d22-d1 inert test fixture, not Cubism Core */";

#[cfg(test)]
fn test_fixture_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(TEST_FIXTURE_CORE_BYTES);
    hex_digest(&hasher.finalize())
}

#[cfg(test)]
fn test_approved_cores() -> Vec<ApprovedCubismCore> {
    vec![ApprovedCubismCore {
        runtime_family: CORE_RUNTIME_FAMILY,
        version_label: "d22-d1-test-fixture",
        sha256: Box::leak(test_fixture_sha256().into_boxed_str()),
    }]
}

/// Looks up a lowercase canonical SHA-256 in an allowlist slice.
fn find_approved_by_hash<'a>(
    allowlist: &'a [ApprovedCubismCore],
    sha256: &str,
) -> Option<&'a ApprovedCubismCore> {
    allowlist.iter().find(|approved| approved.sha256 == sha256)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedCubismCoreStatus {
    NotConfigured,
    ReadyForStartup,
    CorruptUnavailable,
    RestartRequired,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedCubismCoreSnapshot {
    pub status: ManagedCubismCoreStatus,
    pub runtime_family: String,
    pub version_label: Option<String>,
    pub sha256: Option<String>,
    pub script_url: Option<String>,
    pub restart_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCubismCoreRequest {
    pub source_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RegisteredCoreComponent {
    runtime_family: String,
    version_label: String,
    sha256: String,
    installed_at: String,
}

fn core_error(code: &'static str, message: &'static str, recoverable: bool) -> StorageError {
    StorageError::new(code, message, recoverable)
}

fn database_unavailable() -> StorageError {
    core_error(
        "LIVE2D_CORE_DATABASE_UNAVAILABLE",
        "The managed Cubism Core authority could not be reached.",
        true,
    )
}

fn unapproved() -> StorageError {
    core_error(
        "LIVE2D_CORE_UNAPPROVED",
        "The selected Cubism Core file is not on the approved allowlist.",
        false,
    )
}

fn invalid_input() -> StorageError {
    core_error(
        "LIVE2D_CORE_INVALID_INPUT",
        "The Cubism Core import request is invalid.",
        false,
    )
}

fn core_too_large() -> StorageError {
    core_error(
        "LIVE2D_CORE_TOO_LARGE",
        "The selected Cubism Core file exceeds the bounded size limit.",
        false,
    )
}

fn core_missing() -> StorageError {
    core_error(
        "LIVE2D_CORE_FILE_MISSING",
        "The managed Cubism Core file is missing.",
        false,
    )
}

fn import_copy_failed() -> StorageError {
    core_error(
        "LIVE2D_CORE_IMPORT_COPY_FAILED",
        "The Cubism Core file could not be staged.",
        false,
    )
}

fn import_verify_failed() -> StorageError {
    core_error(
        "LIVE2D_CORE_IMPORT_VERIFY_FAILED",
        "The staged Cubism Core bytes failed rehash verification.",
        false,
    )
}

fn registration_failed() -> StorageError {
    core_error(
        "LIVE2D_CORE_REGISTRATION_FAILED",
        "The Cubism Core component could not be registered.",
        false,
    )
}

fn component_not_registered() -> StorageError {
    core_error(
        "LIVE2D_CORE_COMPONENT_NOT_REGISTERED",
        "No Cubism Core component is registered.",
        false,
    )
}

fn core_corrupt() -> StorageError {
    core_error(
        "LIVE2D_CORE_CORRUPT",
        "The managed Cubism Core component failed integrity verification.",
        false,
    )
}

fn unsafe_path() -> StorageError {
    core_error(
        "LIVE2D_CORE_UNSAFE_PATH",
        "The Cubism Core managed path is unsafe.",
        false,
    )
}

/// Bounded read of a source file into memory, refusing anything larger than
/// `limit` real bytes.
fn read_file_with_limit(path: &Path, limit: u64) -> Result<Vec<u8>, StorageError> {
    let file = File::open(path).map_err(|_| core_missing())?;
    let metadata = file.metadata().map_err(|_| core_missing())?;
    if !metadata.is_file() {
        return Err(core_missing());
    }
    if metadata.len() > limit {
        return Err(core_too_large());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| core_too_large())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| core_missing())?;
    if bytes.len() as u64 > limit {
        return Err(core_too_large());
    }
    Ok(bytes)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Ensures `<active-root>/live2d/core/{staging,active}` exist.
fn managed_core_roots(active_root: &Path) -> Result<(PathBuf, PathBuf), StorageError> {
    let core_root = active_root
        .join(MANAGED_CORE_DIRECTORY)
        .join(MANAGED_CORE_SUBDIRECTORY);
    let staging = core_root.join(MANAGED_CORE_STAGING_DIRECTORY);
    let active = core_root.join(MANAGED_CORE_ACTIVE_DIRECTORY);
    fs::create_dir_all(&staging).map_err(|_| import_copy_failed())?;
    fs::create_dir_all(&active).map_err(|_| import_copy_failed())?;
    Ok((staging, active))
}

fn managed_active_core_path(active_root: &Path) -> Result<PathBuf, StorageError> {
    let (_staging, active) = managed_core_roots(active_root)?;
    let candidate = active.join(CORE_FIXED_RESOURCE_NAME);
    if !candidate.starts_with(&active) {
        return Err(unsafe_path());
    }
    Ok(candidate)
}

fn read_registered_core(
    connection: &Connection,
) -> Result<Option<RegisteredCoreComponent>, StorageError> {
    connection
        .query_row(
            "SELECT runtime_family, version_label, sha256, installed_at
             FROM live2d_core_component WHERE slot = ?1",
            [CORE_COMPONENT_SLOT],
            |row| {
                Ok(RegisteredCoreComponent {
                    runtime_family: row.get(0)?,
                    version_label: row.get(1)?,
                    sha256: row.get(2)?,
                    installed_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| database_unavailable())
}

/// Serve-time integrity: the component row exists, the managed file is in
/// the trusted active root, its real bytes hash to the registered SHA-256,
/// and that hash remains present in the supplied allowlist authority.
fn core_component_available(
    active_root: &Path,
    component: &RegisteredCoreComponent,
    allowlist: &[ApprovedCubismCore],
) -> Result<Vec<u8>, StorageError> {
    if find_approved_by_hash(allowlist, &component.sha256).is_none() {
        return Err(unapproved());
    }
    let managed_path = managed_active_core_path(active_root)?;
    let bytes = read_file_with_limit(&managed_path, MAX_CORE_BYTES)?;
    if hash_bytes(&bytes) != component.sha256 {
        return Err(core_corrupt());
    }
    Ok(bytes)
}

fn snapshot_for_status(
    active_root: &Path,
    component: Option<&RegisteredCoreComponent>,
    restart_required: bool,
    allowlist: &[ApprovedCubismCore],
) -> ManagedCubismCoreSnapshot {
    let Some(component) = component else {
        return ManagedCubismCoreSnapshot {
            status: ManagedCubismCoreStatus::NotConfigured,
            runtime_family: CORE_RUNTIME_FAMILY.to_string(),
            version_label: None,
            sha256: None,
            script_url: None,
            restart_required,
        };
    };
    let verified = core_component_available(active_root, component, allowlist).is_ok();
    if !verified {
        return ManagedCubismCoreSnapshot {
            status: ManagedCubismCoreStatus::CorruptUnavailable,
            runtime_family: component.runtime_family.clone(),
            version_label: Some(component.version_label.clone()),
            sha256: Some(component.sha256.clone()),
            script_url: None,
            restart_required,
        };
    }
    ManagedCubismCoreSnapshot {
        status: ManagedCubismCoreStatus::ReadyForStartup,
        runtime_family: component.runtime_family.clone(),
        version_label: Some(component.version_label.clone()),
        sha256: Some(component.sha256.clone()),
        script_url: Some(managed_core_script_url()),
        restart_required,
    }
}

/// Backend-generated URL for the fixed managed Core resource.  The frontend
/// never constructs this URL; the production URL validator accepts only this
/// exact origin/path shape.
fn managed_core_script_url() -> String {
    format!("{}{}", core_asset_origin(), CORE_FIXED_RESOURCE_NAME)
}

#[cfg(any(target_os = "windows", target_os = "android"))]
fn core_asset_origin() -> &'static str {
    WINDOWS_ANDROID_CORE_ORIGIN
}

#[cfg(not(any(target_os = "windows", target_os = "android")))]
fn core_asset_origin() -> &'static str {
    MAC_LINUX_CORE_ORIGIN
}

/// Replacement policy: D22-D1 never hot-replaces a Core already loaded into
/// the current Main WebView.  Installing a Core returns `restartRequired:
/// true` because a fresh process/WebView is required before the managed Core
/// is injected.
fn register_core_component(
    connection: &mut Connection,
    approved: &ApprovedCubismCore,
) -> Result<(), StorageError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| database_unavailable())?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| database_unavailable())?;
    transaction
        .execute(
            "INSERT OR REPLACE INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                CORE_COMPONENT_SLOT,
                approved.runtime_family,
                approved.version_label,
                approved.sha256,
                CORE_FIXED_RESOURCE_NAME,
                migration_now
            ],
        )
        .map_err(|_| registration_failed())?;
    transaction.commit().map_err(|_| registration_failed())?;
    Ok(())
}

impl StorageService {
    /// Import one explicitly selected local Core file through the full
    /// staged authority path.  Failures never become authoritative: a
    /// missing SQLite row means an untrusted filesystem orphan.
    pub fn import_cubism_core(
        &self,
        request: ImportCubismCoreRequest,
    ) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        self.import_cubism_core_with_allowlist(request, PRODUCTION_APPROVED_CORES)
    }

    /// Test-only import seam: the allowlist slice is supplied explicitly.
    /// Production always uses the immutable production allowlist; tests use
    /// the #[cfg(test)] fixture allowlist.
    #[cfg(test)]
    fn import_cubism_core_with_test_allowlist(
        &self,
        request: ImportCubismCoreRequest,
    ) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        let allowlist = Box::leak(test_approved_cores().into_boxed_slice());
        self.import_cubism_core_with_allowlist(request, allowlist)
    }

    #[cfg(test)]
    fn get_cubism_core_snapshot_with_test_allowlist(
        &self,
    ) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        let allowlist = Box::leak(test_approved_cores().into_boxed_slice());
        self.get_cubism_core_snapshot_with_allowlist(allowlist, false)
    }

    fn import_cubism_core_with_allowlist(
        &self,
        request: ImportCubismCoreRequest,
        allowlist: &[ApprovedCubismCore],
    ) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        if request.source_path.trim().is_empty() {
            return Err(invalid_input());
        }
        let source = Path::new(&request.source_path);

        // 1. Bounded read + SHA-256 of the real bytes.
        let bytes = read_file_with_limit(source, MAX_CORE_BYTES)?;
        let sha256 = hash_bytes(&bytes);

        // 2. Exact allowlist match.  Filename/size are never trust authority.
        let approved = find_approved_by_hash(allowlist, &sha256).ok_or_else(unapproved)?;

        let mut state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let (staging_root, active_root_dir) = managed_core_roots(&active_root)?;
        let staging_dir = staging_root.join(format!("import-{}", unique_suffix()));
        fs::create_dir(&staging_dir).map_err(|_| import_copy_failed())?;
        let staged_path = staging_dir.join(CORE_FIXED_RESOURCE_NAME);
        let staged_result = (|| -> Result<(), StorageError> {
            fs::write(&staged_path, &bytes).map_err(|_| import_copy_failed())?;
            // 3. Rehash staged bytes and verify exact equality.
            let staged = read_file_with_limit(&staged_path, MAX_CORE_BYTES)?;
            if hash_bytes(&staged) != sha256 {
                return Err(import_verify_failed());
            }
            Ok(())
        })();
        if let Err(error) = staged_result {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }

        // 4. Promote to the managed active location.  Replacement is allowed
        // at the authority level (a re-import always signals restartRequired
        // because the Main WebView never hot-replaces a loaded Core), but
        // never partially: the staged copy is atomic-renamed into place.
        let final_path = active_root_dir.join(CORE_FIXED_RESOURCE_NAME);
        if fs::symlink_metadata(&final_path).is_ok() {
            let _ = fs::remove_file(&final_path);
        }
        fs::rename(&staged_path, &final_path).map_err(|_| {
            let _ = fs::remove_dir_all(&staging_dir);
            import_copy_failed()
        })?;
        let _ = fs::remove_dir_all(&staging_dir);

        // 5. Register the component row.  If registration fails, the managed
        // file is removed so no untrusted orphan remains authoritative.
        let registration = register_core_component(&mut state.connection, approved);
        drop(state);
        if let Err(error) = registration {
            let _ = fs::remove_file(&final_path);
            return Err(error);
        }
        self.get_cubism_core_snapshot_with_allowlist(allowlist, true)
    }

    pub fn get_cubism_core_snapshot(&self) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        self.get_cubism_core_snapshot_with_allowlist(PRODUCTION_APPROVED_CORES, false)
    }

    fn get_cubism_core_snapshot_with_allowlist(
        &self,
        allowlist: &[ApprovedCubismCore],
        restart_required: bool,
    ) -> Result<ManagedCubismCoreSnapshot, StorageError> {
        let state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let component = read_registered_core(&state.connection)?;
        drop(state);
        Ok(snapshot_for_status(
            &active_root,
            component.as_ref(),
            restart_required,
            allowlist,
        ))
    }
}

#[tauri::command]
pub fn import_cubism_core(
    storage: State<'_, StorageService>,
    request: ImportCubismCoreRequest,
) -> Result<ManagedCubismCoreSnapshot, StorageError> {
    storage.import_cubism_core(request)
}

#[tauri::command]
pub fn get_cubism_core_snapshot(
    storage: State<'_, StorageService>,
) -> Result<ManagedCubismCoreSnapshot, StorageError> {
    storage.get_cubism_core_snapshot()
}

/// Fixed-resource protocol handler.  Only the Main WebView may receive
/// successful bytes; settings/chat/unknown labels are rejected before any
/// managed byte is read.  Only the exact fixed resource path is served.
pub(crate) fn serve_core_request_for_webview(
    storage: &StorageService,
    webview_label: &str,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    if webview_label != CORE_RENDERER_WEBVIEW_LABEL {
        return empty_core_response(StatusCode::FORBIDDEN);
    }
    serve_core_request(storage, request)
}

fn serve_core_request(storage: &StorageService, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return empty_core_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !parse_fixed_core_uri(request.uri()) {
        return empty_core_response(StatusCode::FORBIDDEN);
    }
    let (bytes, _component) = match load_servable_core_bytes(storage) {
        Ok(value) => value,
        Err(_) => return empty_core_response(StatusCode::NOT_FOUND),
    };
    let content_length = bytes.len().to_string();
    let body = if request.method() == Method::HEAD {
        Vec::new()
    } else {
        bytes
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("fixed core response must be valid")
}

fn empty_core_response(status: StatusCode) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Vec::new())
        .expect("fixed core response must be valid")
}

/// Accepts exactly one logical resource with the exact backend-generated
/// origin shape.  No caller-controlled relative path, no query, no fragment,
/// no alternate pathname, no port, no auth, no encoded traversal.
fn parse_fixed_core_uri(uri: &tauri::http::Uri) -> bool {
    if uri.path() != format!("/{CORE_FIXED_RESOURCE_NAME}") {
        return false;
    }
    if uri.query().is_some() {
        return false;
    }
    let Some(host) = uri.host() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    // Exact platform pairing, mirroring the backend-generated URL:
    //   Windows/Android: http://digital-life-core.localhost/<resource>
    //   macOS/Linux:     digital-life-core://localhost/<resource>
    match scheme {
        "http" => host == "digital-life-core.localhost",
        CORE_ASSET_PROTOCOL_SCHEME => host == "localhost",
        _ => false,
    }
}

fn load_servable_core_bytes(
    storage: &StorageService,
) -> Result<(Vec<u8>, RegisteredCoreComponent), StorageError> {
    let state = storage.state().map_err(|_| database_unavailable())?;
    let active_root = state.active_root.clone();
    let component =
        read_registered_core(&state.connection)?.ok_or_else(component_not_registered)?;
    drop(state);
    let bytes = core_component_available(&active_root, &component, PRODUCTION_APPROVED_CORES)?;
    Ok((bytes, component))
}

/// Test-only serve seam mirroring the production handler but resolving the
/// component against the test allowlist so the fixture hash can be served.
#[cfg(test)]
fn serve_core_request_for_test(
    storage: &StorageService,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return empty_core_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !parse_fixed_core_uri(request.uri()) {
        return empty_core_response(StatusCode::FORBIDDEN);
    }
    let state = storage.state().map_err(|_| database_unavailable());
    let Ok(state) = state else {
        return empty_core_response(StatusCode::NOT_FOUND);
    };
    let active_root = state.active_root.clone();
    let component = match read_registered_core(&state.connection) {
        Ok(Some(component)) => component,
        _ => return empty_core_response(StatusCode::NOT_FOUND),
    };
    drop(state);
    let allowlist = Box::leak(test_approved_cores().into_boxed_slice());
    let bytes = match core_component_available(&active_root, &component, allowlist) {
        Ok(bytes) => bytes,
        Err(_) => return empty_core_response(StatusCode::NOT_FOUND),
    };
    let content_length = bytes.len().to_string();
    let body = if request.method() == Method::HEAD {
        Vec::new()
    } else {
        bytes
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("fixed core response must be valid")
}

pub(crate) fn validate_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    for (table, expected_sql) in [(
        "live2d_core_component",
        include_str!("migrations/026_live2d_core_component_authority.live2d_core_component.sql"),
    )] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| migration_validation_failed())?;
        let Some(actual) = actual else {
            return Err(migration_validation_failed());
        };
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(migration_validation_failed());
        }
    }
    for (trigger, expected_sql) in [(
        "live2d_core_component_immutable_guard",
        include_str!(
            "migrations/026_live2d_core_component_authority.live2d_core_component_immutable_trigger.sql"
        ),
    )] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [trigger],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| migration_validation_failed())?;
        let Some(actual) = actual else {
            return Err(migration_validation_failed());
        };
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(migration_validation_failed());
        }
    }

    // The table must never carry original user paths, remote URLs, or script
    // source text.
    let forbidden_columns = [
        "source_path",
        "original_path",
        "url",
        "script_url",
        "remote_url",
        "source_text",
        "javascript",
        "payload",
    ];
    let columns: Vec<String> = connection
        .prepare("SELECT name FROM pragma_table_info('live2d_core_component')")
        .map_err(|_| migration_validation_failed())?
        .query_map([], |row| row.get(0))
        .map_err(|_| migration_validation_failed())?
        .collect::<Result<_, _>>()
        .map_err(|_| migration_validation_failed())?;
    for column in &columns {
        if forbidden_columns.contains(&column.as_str()) {
            return Err(migration_validation_failed());
        }
    }
    Ok(())
}

fn migration_validation_failed() -> StorageError {
    core_error(
        "MIGRATION_TRANSACTION_FAILED",
        "The managed Cubism Core schema could not be validated.",
        false,
    )
}

fn normalize_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .map(char::from)
        .collect()
}

const _: fn(&Connection) -> Result<(), StorageError> = validate_schema_objects;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tauri::http::{Method, Request, StatusCode};

    use super::*;
    use crate::storage::StorageService;

    struct Fixture {
        storage: StorageService,
        root: tempfile::TempDir,
        source: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            let storage =
                StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
            Self {
                storage,
                root,
                source,
            }
        }

        fn write_core(&self, bytes: &[u8]) -> PathBuf {
            let path = self.source.join(CORE_FIXED_RESOURCE_NAME);
            fs::write(&path, bytes).unwrap();
            path
        }

        fn active_core_path(&self) -> PathBuf {
            self.root
                .path()
                .join("data")
                .join(MANAGED_CORE_DIRECTORY)
                .join(MANAGED_CORE_SUBDIRECTORY)
                .join(MANAGED_CORE_ACTIVE_DIRECTORY)
                .join(CORE_FIXED_RESOURCE_NAME)
        }

        fn request(&self, method: Method, uri: &str) -> Request<Vec<u8>> {
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Vec::new())
                .unwrap_or_else(|error| panic!("invalid test URI {uri:?}: {error}"))
        }
    }

    fn windows_core_uri() -> String {
        format!("{WINDOWS_ANDROID_CORE_ORIGIN}{CORE_FIXED_RESOURCE_NAME}")
    }

    fn mac_linux_core_uri() -> String {
        format!("{MAC_LINUX_CORE_ORIGIN}{CORE_FIXED_RESOURCE_NAME}")
    }

    #[test]
    fn production_allowlist_is_empty_and_never_contains_test_hashes() {
        assert!(
            PRODUCTION_APPROVED_CORES.is_empty(),
            "D22-D1 production allowlist must intentionally contain zero hashes"
        );
        for approved in test_approved_cores() {
            assert!(
                find_approved_by_hash(PRODUCTION_APPROVED_CORES, approved.sha256).is_none(),
                "no test fixture hash may ever compile into the production allowlist"
            );
        }
    }

    #[test]
    fn hash_authority_accepts_only_exact_test_allowlist_matches() {
        let fixture = Fixture::new();
        let approved = fixture.write_core(TEST_FIXTURE_CORE_BYTES);
        let request = ImportCubismCoreRequest {
            source_path: approved.to_string_lossy().into_owned(),
        };
        let snapshot = fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap();
        assert_eq!(snapshot.status, ManagedCubismCoreStatus::ReadyForStartup);
        assert_eq!(
            snapshot.sha256.as_deref(),
            Some(test_fixture_sha256().as_str())
        );
        assert!(snapshot.script_url.is_some());
        assert!(
            snapshot.restart_required,
            "activation requires a fresh WebView"
        );

        // The same file is not approved by the production authority.
        let production_request = ImportCubismCoreRequest {
            source_path: approved.to_string_lossy().into_owned(),
        };
        let error = fixture
            .storage
            .import_cubism_core(production_request)
            .unwrap_err();
        assert_eq!(error.code, "LIVE2D_CORE_UNAPPROVED");
    }

    #[test]
    fn one_byte_different_core_is_rejected_and_filename_alone_cannot_approve() {
        let fixture = Fixture::new();
        let mut different = TEST_FIXTURE_CORE_BYTES.to_vec();
        different[0] ^= 0x01;
        let path = fixture.write_core(&different);
        let request = ImportCubismCoreRequest {
            source_path: path.to_string_lossy().into_owned(),
        };
        let error = fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap_err();
        assert_eq!(error.code, "LIVE2D_CORE_UNAPPROVED");

        // A file with the canonical name but wrong content is never approved
        // by filename alone.
        let wrong_hash = fixture.write_core(b"/* wrong bytes under the canonical name */");
        let request = ImportCubismCoreRequest {
            source_path: wrong_hash.to_string_lossy().into_owned(),
        };
        let error = fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap_err();
        assert_eq!(error.code, "LIVE2D_CORE_UNAPPROVED");
    }

    #[test]
    fn managed_storage_registers_atomic_and_orphans_are_not_trusted() {
        let fixture = Fixture::new();
        let approved = fixture.write_core(TEST_FIXTURE_CORE_BYTES);
        let request = ImportCubismCoreRequest {
            source_path: approved.to_string_lossy().into_owned(),
        };
        fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap();

        // The managed active file exists and the SQLite row is registered.
        assert!(fixture.active_core_path().exists());
        let state = fixture.storage.state().unwrap();
        let component = read_registered_core(&state.connection).unwrap().unwrap();
        let managed_relative_path: String = state
            .connection
            .query_row(
                "SELECT managed_relative_path FROM live2d_core_component WHERE slot='active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(state);
        assert_eq!(component.sha256, test_fixture_sha256());
        assert_eq!(managed_relative_path, CORE_FIXED_RESOURCE_NAME);

        // A filesystem orphan without a row is not trusted.
        fs::write(fixture.active_core_path(), TEST_FIXTURE_CORE_BYTES).unwrap();
        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute("DELETE FROM live2d_core_component", [])
            .unwrap();
        drop(state);
        let snapshot = fixture.storage.get_cubism_core_snapshot().unwrap();
        assert_eq!(snapshot.status, ManagedCubismCoreStatus::NotConfigured);
    }

    #[test]
    fn status_reflects_missing_and_corrupted_managed_files() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.storage.get_cubism_core_snapshot().unwrap().status,
            ManagedCubismCoreStatus::NotConfigured
        );

        let approved = fixture.write_core(TEST_FIXTURE_CORE_BYTES);
        let request = ImportCubismCoreRequest {
            source_path: approved.to_string_lossy().into_owned(),
        };
        fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap();
        assert_eq!(
            fixture
                .storage
                .get_cubism_core_snapshot_with_test_allowlist()
                .unwrap()
                .status,
            ManagedCubismCoreStatus::ReadyForStartup
        );

        fs::remove_file(fixture.active_core_path()).unwrap();
        assert_eq!(
            fixture
                .storage
                .get_cubism_core_snapshot_with_test_allowlist()
                .unwrap()
                .status,
            ManagedCubismCoreStatus::CorruptUnavailable
        );

        fixture
            .storage
            .import_cubism_core_with_test_allowlist(ImportCubismCoreRequest {
                source_path: approved.to_string_lossy().into_owned(),
            })
            .unwrap();
        fs::write(fixture.active_core_path(), b"corrupted bytes").unwrap();
        assert_eq!(
            fixture
                .storage
                .get_cubism_core_snapshot_with_test_allowlist()
                .unwrap()
                .status,
            ManagedCubismCoreStatus::CorruptUnavailable
        );
    }

    #[test]
    fn protocol_serves_only_main_with_the_fixed_resource_and_integrity() {
        let fixture = Fixture::new();
        let approved = fixture.write_core(TEST_FIXTURE_CORE_BYTES);
        let request = ImportCubismCoreRequest {
            source_path: approved.to_string_lossy().into_owned(),
        };
        fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap();

        // Non-main webviews are rejected before any byte is read.
        for label in ["settings", "chat", "unknown"] {
            let response = serve_core_request_for_webview(
                &fixture.storage,
                label,
                fixture.request(Method::GET, &windows_core_uri()),
            );
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{label} must be forbidden"
            );
        }

        // Fixed resource is served to main with the correct MIME.
        let response = serve_core_request_for_test(
            &fixture.storage,
            fixture.request(Method::GET, &windows_core_uri()),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/javascript"
        );

        // The mac/linux origin shape is also accepted.
        let response = serve_core_request_for_test(
            &fixture.storage,
            fixture.request(Method::GET, &mac_linux_core_uri()),
        );
        assert_eq!(response.status(), StatusCode::OK);

        // Query/fragment/alternate paths are rejected.
        for bad_uri in [
            format!("{}/?x=1", windows_core_uri()),
            format!("{}/../live2dcubismcore.min.js", windows_core_uri()),
            "digital-life-core://localhost/other.js".to_string(),
            "http://digital-life-core.localhost/live2dcubismcore.min.js?x=1".to_string(),
        ] {
            let response = serve_core_request_for_test(
                &fixture.storage,
                fixture.request(Method::GET, &bad_uri),
            );
            assert_ne!(
                response.status(),
                StatusCode::OK,
                "{bad_uri} must be rejected"
            );
        }

        // A corrupted managed file cannot be served.
        fs::write(fixture.active_core_path(), b"corrupted").unwrap();
        let response = serve_core_request_for_test(
            &fixture.storage,
            fixture.request(Method::GET, &windows_core_uri()),
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // The unapproved production authority cannot serve the test component.
        fixture
            .storage
            .import_cubism_core_with_test_allowlist(ImportCubismCoreRequest {
                source_path: approved.to_string_lossy().into_owned(),
            })
            .unwrap();
        let response = serve_core_request_for_webview(
            &fixture.storage,
            "main",
            fixture.request(Method::GET, &windows_core_uri()),
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn oversized_core_file_is_rejected_before_hashing_completes() {
        let fixture = Fixture::new();
        let oversized = vec![0x61_u8; (MAX_CORE_BYTES + 1) as usize];
        let path = fixture.write_core(&oversized);
        let request = ImportCubismCoreRequest {
            source_path: path.to_string_lossy().into_owned(),
        };
        let error = fixture
            .storage
            .import_cubism_core_with_test_allowlist(request)
            .unwrap_err();
        assert_eq!(error.code, "LIVE2D_CORE_TOO_LARGE");
    }
}
