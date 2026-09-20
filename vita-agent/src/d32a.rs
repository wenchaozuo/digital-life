//! D32-A fixed, sandboxed Cargo-check production façade.
//!
//! The façade deliberately contains no model-controlled process fields.  It
//! reuses the D29-H7 prepared-image, final-fence, Job and bounded-I/O
//! supervisor; the only new surface is the static zero-argument Cargo profile
//! and its AppContainer security-capabilities attribute.

#![allow(dead_code)]

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "d32-a-test-helper")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use vita_agent_protocol as protocol;

use crate::d29h7::{
    H7AuthorityPort, H7D32CatalogResources, H7ExecutableCatalog, H7PendingConfirmationBridge,
    H7PendingProcessAction, H7ProcessBroker, H7ProcessRequest, H7RetainedDirectory,
    H7SandboxProfile, H7ToolResult, VitaGitStatusAuthorityAdapter,
    VITA_WORKSPACE_CARGO_CHECK_CAPABILITY_ID, VITA_WORKSPACE_CARGO_CHECK_PROFILE_ID,
    VITA_WORKSPACE_CARGO_CHECK_TOOL_NAME,
};
use crate::{SidecarRunMode, TrustedWorkspaceRoot, VitaExecutionContext, VitaGitStatusAuthority};

pub(crate) const D32_CARGO_PROGRAM_ID: &str = "cargo-check-v1";
pub(crate) const D32_CARGO_PROFILE_ID: &str = VITA_WORKSPACE_CARGO_CHECK_PROFILE_ID;
pub(crate) const D32_CARGO_TOOL_NAME: &str = VITA_WORKSPACE_CARGO_CHECK_TOOL_NAME;
pub(crate) const D32_CARGO_CAPABILITY_ID: &str = VITA_WORKSPACE_CARGO_CHECK_CAPABILITY_ID;
pub(crate) use crate::d29h7::D32_CARGO_NO_GIT_METADATA_FENCE;

pub(crate) const D32_EXECUTION_ROOT_NAME: &str = "d32-cargo-check-v1";
pub(crate) const D32_SOURCE_DIR_NAME: &str = "source";
pub(crate) const D32_CARGO_HOME_DIR_NAME: &str = "cargo-home";
pub(crate) const D32_TARGET_DIR_NAME: &str = "target";

const D32_MAX_SOURCE_FILES: usize = 16_384;
const D32_MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const D32_MAX_TOOLCHAIN_FILES: usize = protocol::D32_MANIFEST_MAX_FILES;
const D32_MAX_TOOLCHAIN_FILE_BYTES: usize = protocol::D32_MANIFEST_MAX_FILE_BYTES as usize;
const D32_MAX_TOOLCHAIN_BYTES: u64 = protocol::D32_MANIFEST_MAX_TOTAL_BYTES;
const D32_MAX_SOURCE_FILE_BYTES: usize = 64 * 1024 * 1024;
const D32_MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;

pub(crate) const D32_TOOLCHAIN_MIRROR_ROOT_NAME: &str = "d32-toolchains";
pub(crate) const D32_RUNS_DIR_NAME: &str = "runs";
const D32_NATIVE_EVIDENCE_DIR_NAME: &str = ".d32-native-evidence-v1";
const D32_NATIVE_EVIDENCE_MAX_BYTES: usize = 64 * 1024;

#[cfg(feature = "d32-a-test-helper")]
static D32_TEST_EVIDENCE: OnceLock<Mutex<Option<Value>>> = OnceLock::new();

#[cfg(feature = "d32-a-test-helper")]
fn record_internal_evidence(value: Value) {
    let slot = D32_TEST_EVIDENCE.get_or_init(|| Mutex::new(None));
    if let Ok(mut evidence) = slot.lock() {
        *evidence = Some(value);
    }
}

#[cfg(feature = "d32-a-test-helper")]
pub(crate) fn take_internal_evidence() -> Option<Value> {
    D32_TEST_EVIDENCE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|mut evidence| evidence.take())
}

/// A Host-selected Rust toolchain mirrored below private app data.  The
/// selected user-profile root is consulted only while this immutable mirror
/// is built; production children receive only these app-owned paths.
#[derive(Clone)]
pub(crate) struct D32ToolchainMirror {
    pub(crate) root: PathBuf,
    pub(crate) retained_root: Arc<H7RetainedDirectory>,
    pub(crate) retained_bin: Arc<H7RetainedDirectory>,
    pub(crate) cargo_path: PathBuf,
    pub(crate) rustc_path: PathBuf,
    pub(crate) rustdoc_path: PathBuf,
    pub(crate) manifest_hash: String,
}

impl D32ToolchainMirror {
    pub(crate) fn prepare_from_retained(
        app_data_root_retained: Arc<H7RetainedDirectory>,
        selected_cargo_path: &std::path::Path,
        selected_root_retained: Arc<H7RetainedDirectory>,
        selected_bin_retained: Arc<H7RetainedDirectory>,
        expected_manifest_hash: &str,
    ) -> Result<Arc<Self>, String> {
        if !app_data_root_retained.path().is_absolute()
            || !selected_cargo_path.is_absolute()
            || expected_manifest_hash.len() != 64
            || expected_manifest_hash
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host toolchain mirror evidence was not exact".to_string());
        }
        selected_root_retained.revalidate()?;
        selected_bin_retained.revalidate()?;
        app_data_root_retained.revalidate()?;
        let app_data_retained = app_data_root_retained;
        let selected_cargo_name = OsStr::new("cargo.exe");
        if selected_cargo_path.file_name() != Some(selected_cargo_name)
            || selected_cargo_path.parent().is_none_or(|parent| {
                parent.to_string_lossy().to_ascii_lowercase()
                    != selected_bin_retained
                        .path()
                        .to_string_lossy()
                        .to_ascii_lowercase()
            })
        {
            return Err("D32 Host-selected Cargo path was not the retained bin child".to_string());
        }
        let selected_cargo_identity = selected_bin_retained
            .probe_file_bounded(selected_cargo_name, D32_MAX_IMAGE_BYTES as u64)?
            .ok_or_else(|| "D32 selected Cargo image was unavailable".to_string())?;
        let root_cargo_identity = selected_bin_retained
            .probe_file_bounded(OsStr::new("cargo.exe"), D32_MAX_IMAGE_BYTES as u64)?
            .ok_or_else(|| "D32 toolchain Cargo image was unavailable".to_string())?;
        let _root_rustc_retained = selected_bin_retained
            .probe_file_bounded(OsStr::new("rustc.exe"), D32_MAX_TOOLCHAIN_FILE_BYTES as u64)?
            .ok_or_else(|| "D32 toolchain rustc image was unavailable".to_string())?;
        let _root_rustdoc_retained = selected_bin_retained
            .probe_file_bounded(
                OsStr::new("rustdoc.exe"),
                D32_MAX_TOOLCHAIN_FILE_BYTES as u64,
            )?
            .ok_or_else(|| "D32 toolchain rustdoc image was unavailable".to_string())?;
        if selected_cargo_identity != root_cargo_identity {
            return Err("D32 Host-selected Rust toolchain was incomplete".to_string());
        }

        let mirror_parent_retained =
            app_data_retained.open_or_create_child(OsStr::new(D32_TOOLCHAIN_MIRROR_ROOT_NAME))?;
        let mirror_parent = mirror_parent_retained.path().to_path_buf();
        let mirror_root = mirror_parent.join(expected_manifest_hash);
        let existing_mirror = mirror_parent_retained
            .open_existing_child(OsStr::new(expected_manifest_hash))
            .ok();
        let valid_existing = existing_mirror.as_ref().is_some_and(|mirror| {
            mirror.revalidate().is_ok()
                && validate_existing_tree_without_reparse_retained(mirror).is_ok()
                && toolchain_manifest_hash_retained(mirror).ok().as_deref()
                    == Some(expected_manifest_hash)
                && retained_toolchain_images_present(mirror)
        });

        if !valid_existing {
            mirror_parent_retained
                .remove_child_tree_if_present(OsStr::new(expected_manifest_hash))?;
            let staging_name = OsString::from(format!(".{expected_manifest_hash}.staging"));
            mirror_parent_retained.remove_child_tree_if_present(&staging_name)?;
            let staging_retained = mirror_parent_retained.open_or_create_child(&staging_name)?;
            let mut limits = CopyLimits::new(D32_MAX_TOOLCHAIN_FILES, D32_MAX_TOOLCHAIN_BYTES);
            copy_tree_without_reparse(&selected_root_retained, &staging_retained, &mut limits)?;
            let staged_manifest = toolchain_manifest_hash_retained(&staging_retained)?;
            if staged_manifest != expected_manifest_hash {
                let _ = staging_retained.remove_self();
                return Err("D32 staged toolchain mirror did not match Host evidence".to_string());
            }
            drop(staging_retained);
            mirror_parent_retained.rename_directory(
                &staging_name,
                OsStr::new(expected_manifest_hash),
                false,
            )?;
        }

        let retained_root = Arc::new(
            mirror_parent_retained.open_existing_child(OsStr::new(expected_manifest_hash))?,
        );
        retained_root.revalidate()?;
        let retained_bin = Arc::new(retained_root.open_existing_child(OsStr::new("bin"))?);
        retained_bin.revalidate()?;
        let manifest_hash = toolchain_manifest_hash_retained(&retained_root)?;
        if manifest_hash != expected_manifest_hash {
            return Err("D32 toolchain mirror manifest changed".to_string());
        }
        Ok(Arc::new(Self {
            cargo_path: mirror_root.join("bin/cargo.exe"),
            rustc_path: mirror_root.join("bin/rustc.exe"),
            rustdoc_path: mirror_root.join("bin/rustdoc.exe"),
            root: mirror_root,
            retained_root,
            retained_bin,
            manifest_hash,
        }))
    }
}

/// The app-owned execution projection consumed by the sandboxed child.  The
/// live workspace and the user-profile toolchain never become the child cwd or
/// executable image; they are copied once, before the production contributor
/// is exposed, into this deterministic root.
#[derive(Clone)]
pub(crate) struct D32ExecutionProjection {
    pub(crate) root: PathBuf,
    pub(crate) retained_root: Arc<H7RetainedDirectory>,
    pub(crate) retained_source: Arc<H7RetainedDirectory>,
    pub(crate) retained_cargo_home: Arc<H7RetainedDirectory>,
    pub(crate) retained_target: Arc<H7RetainedDirectory>,
    pub(crate) retained_toolchain: Arc<H7RetainedDirectory>,
    pub(crate) retained_toolchain_bin: Arc<H7RetainedDirectory>,
    pub(crate) source_root: PathBuf,
    pub(crate) toolchain_root: PathBuf,
    pub(crate) cargo_home: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) cargo_path: PathBuf,
    pub(crate) rustc_path: PathBuf,
    pub(crate) rustdoc_path: PathBuf,
    pub(crate) toolchain_manifest_hash: String,
    rollback: Arc<D32ProjectionRollbackState>,
}

/// Owns the app-created run root until the projection has either been handed
/// to the H7 action or explicitly cleaned up.  This guard is intentionally
/// independent of the async tool path: an early `?`, a panic, or a failed
/// copy must not leave a partial app-owned projection behind.
struct D32ProjectionRollbackState {
    root: PathBuf,
    retained_root: Arc<H7RetainedDirectory>,
    armed: AtomicBool,
    cleanup_failed: AtomicBool,
    cleanup_failure: Mutex<Option<String>>,
}

impl D32ProjectionRollbackState {
    fn new(root: PathBuf, retained_root: Arc<H7RetainedDirectory>) -> Arc<Self> {
        Arc::new(Self {
            root,
            retained_root,
            armed: AtomicBool::new(true),
            cleanup_failed: AtomicBool::new(false),
            cleanup_failure: Mutex::new(None),
        })
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::Release);
    }

    fn mark_cleanup_failed(&self, error: impl Into<String>) {
        let error = error.into();
        self.cleanup_failed.store(true, Ordering::Release);
        if let Ok(mut failure) = self.cleanup_failure.lock() {
            if failure.is_none() {
                *failure = Some(error.clone());
            }
        }
        eprintln!(
            "D32 projection cleanup failed (fail-closed): root={} error={error}",
            self.root.display(),
        );
    }
}

impl Drop for D32ProjectionRollbackState {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        // A reparse point or an uninspectable tree is deliberately left in
        // place.  Removing an unsafe path during panic cleanup would turn a
        // containment failure into an arbitrary deletion primitive.
        if let Err(error) = self.retained_root.revalidate() {
            self.mark_cleanup_failed(format!(
                "D32 retained run root changed during rollback: {error}"
            ));
            return;
        }
        if let Err(error) = self.retained_root.remove_self() {
            self.mark_cleanup_failed(format!(
                "D32 run root could not be removed during rollback: {error}"
            ));
        } else {
            self.disarm();
        }
    }
}

impl D32ExecutionProjection {
    pub(crate) fn prepare(
        app_data_root_retained: Arc<H7RetainedDirectory>,
        workspace_root: &TrustedWorkspaceRoot,
        toolchain: Arc<D32ToolchainMirror>,
        session_id: &str,
        turn_id: &str,
        tool_call_id: &str,
    ) -> Result<Arc<Self>, String> {
        let projection = Self::prepare_layout(
            app_data_root_retained,
            workspace_root,
            toolchain,
            session_id,
            turn_id,
            tool_call_id,
        )?;
        projection.populate(workspace_root)?;
        projection.rollback.disarm();
        Ok(projection)
    }

    /// Reserve an app-owned run layout without reading the governed
    /// workspace.  D32's Host authority must complete its fresh D28 scope
    /// evaluation before [`Self::populate`] snapshots any workspace bytes.
    pub(crate) fn prepare_layout(
        app_data_root_retained: Arc<H7RetainedDirectory>,
        workspace_root: &TrustedWorkspaceRoot,
        toolchain: Arc<D32ToolchainMirror>,
        session_id: &str,
        turn_id: &str,
        tool_call_id: &str,
    ) -> Result<Arc<Self>, String> {
        if !app_data_root_retained.path().is_absolute()
            || session_id.is_empty()
            || turn_id.is_empty()
            || tool_call_id.is_empty()
        {
            return Err("D32 app-owned projection paths must be absolute".to_string());
        }
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D32 governed workspace changed before staging".to_string())?;
        let app_data_retained = app_data_root_retained;
        app_data_retained.revalidate()?;
        let execution_parent =
            app_data_retained.open_or_create_child(OsStr::new(D32_EXECUTION_ROOT_NAME))?;
        let runs_parent = execution_parent.open_or_create_child(OsStr::new(D32_RUNS_DIR_NAME))?;
        let run_name = OsString::from(d32_run_id(session_id, turn_id, tool_call_id));
        runs_parent.remove_child_tree_if_present(&run_name)?;
        let root = runs_parent.path().join(&run_name);
        let root_retained = Arc::new(runs_parent.open_or_create_child(&run_name)?);
        root_retained.revalidate()?;
        let source_root = root.join(D32_SOURCE_DIR_NAME);
        let toolchain_root = toolchain.root.clone();
        let cargo_home = root.join(D32_CARGO_HOME_DIR_NAME);
        let target = root.join(D32_TARGET_DIR_NAME);
        let rollback = D32ProjectionRollbackState::new(root.clone(), Arc::clone(&root_retained));
        for name in [
            OsStr::new(D32_SOURCE_DIR_NAME),
            OsStr::new(D32_CARGO_HOME_DIR_NAME),
            OsStr::new(D32_TARGET_DIR_NAME),
        ] {
            root_retained.open_or_create_child(name)?;
        }
        root_retained.revalidate()?;
        let retained_source =
            Arc::new(root_retained.open_existing_child(OsStr::new(D32_SOURCE_DIR_NAME))?);
        let retained_cargo_home =
            Arc::new(root_retained.open_existing_child(OsStr::new(D32_CARGO_HOME_DIR_NAME))?);
        let retained_target =
            Arc::new(root_retained.open_existing_child(OsStr::new(D32_TARGET_DIR_NAME))?);
        retained_source.revalidate()?;
        retained_cargo_home.revalidate()?;
        retained_target.revalidate()?;

        Ok(Arc::new(Self {
            root,
            retained_root: root_retained,
            retained_source,
            retained_cargo_home,
            retained_target,
            retained_toolchain: Arc::clone(&toolchain.retained_root),
            retained_toolchain_bin: Arc::clone(&toolchain.retained_bin),
            source_root,
            toolchain_root,
            cargo_home,
            target,
            cargo_path: toolchain.cargo_path.clone(),
            rustc_path: toolchain.rustc_path.clone(),
            rustdoc_path: toolchain.rustdoc_path.clone(),
            toolchain_manifest_hash: toolchain.manifest_hash.clone(),
            rollback,
        }))
    }

    /// Snapshot the currently governed workspace into the reserved app-owned
    /// source root.  The caller invokes this only after Host D28 scope
    /// evaluation has completed, then proceeds to confirmation and grant.
    pub(crate) fn populate(&self, workspace_root: &TrustedWorkspaceRoot) -> Result<(), String> {
        self.retained_root.revalidate()?;
        let source_retained = Arc::clone(&self.retained_source);
        source_retained.revalidate()?;
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D32 governed workspace changed before staging".to_string())?;
        // The retained workspace capability is derived only after the
        // handle-relative binding probe above.  The probe never reopens the
        // absolute requested pathname; the duplicated root handle remains
        // the authority for the snapshot below.
        let workspace_retained = H7RetainedDirectory::from_trusted_workspace_root(workspace_root)?;
        workspace_retained.revalidate()?;

        let mut source_limits = CopyLimits::new(D32_MAX_SOURCE_FILES, D32_MAX_SOURCE_BYTES);
        snapshot_workspace(
            &workspace_retained,
            &source_retained,
            PathBuf::new(),
            &mut source_limits,
        )?;

        if !retained_toolchain_images_present(&self.retained_toolchain) {
            return Err("D32 app-owned toolchain mirror was incomplete".to_string());
        }
        self.retained_root.revalidate()?;
        source_retained.revalidate()?;
        self.retained_cargo_home.revalidate()?;
        self.retained_target.revalidate()?;
        self.retained_toolchain.revalidate()?;
        workspace_retained.revalidate()?;
        Ok(())
    }

    pub(crate) fn cleanup(&self) -> Result<(), String> {
        self.retained_root.revalidate()?;
        if let Err(error) = self.retained_root.remove_self() {
            let error = format!("D32 run root could not be cleaned: {error}");
            self.rollback.mark_cleanup_failed(error.clone());
            return Err(error);
        }
        self.rollback.disarm();
        Ok(())
    }

    #[cfg(test)]
    fn cleanup_failed(&self) -> bool {
        self.rollback.cleanup_failed.load(Ordering::Acquire)
    }
}

pub(crate) fn d32_run_id(session_id: &str, turn_id: &str, tool_call_id: &str) -> String {
    crate::sha256_hex(
        format!("{session_id}\u{1f}{turn_id}\u{1f}{tool_call_id}\u{1f}{D32_CARGO_PROFILE_ID}")
            .as_bytes(),
    )
}

/// The only production D32 evidence writer.  It is constructed exclusively
/// for the typed `D32Canary` sidecar mode; ordinary production Cargo runs do
/// not create this namespace or publish a second result channel.
struct D32NativeEvidenceSink {
    directory: Arc<H7RetainedDirectory>,
}

impl D32NativeEvidenceSink {
    fn new(app_data_root_retained: Arc<H7RetainedDirectory>) -> Result<Self, String> {
        if !app_data_root_retained.path().is_absolute() {
            return Err("D32 native evidence root was not absolute".to_string());
        }
        app_data_root_retained.revalidate()?;
        let directory = app_data_root_retained
            .open_or_create_child(OsStr::new(D32_NATIVE_EVIDENCE_DIR_NAME))?;
        let sink = Self {
            directory: Arc::new(directory),
        };
        sink.validate_directory(&[])?;
        Ok(sink)
    }

    fn validate_directory(&self, allowed: &[&OsStr]) -> Result<(), String> {
        self.directory.revalidate()?;
        let mut entries = 0usize;
        for name in self.directory.enumerate_children()? {
            if !allowed.iter().any(|allowed| **allowed == name) {
                return Err("D32 native evidence directory had stale or extra state".to_string());
            }
            self.directory.probe_file(&name)?;
            entries = entries.saturating_add(1);
            if entries > allowed.len() {
                return Err(
                    "D32 native evidence directory was stale or had extra entries".to_string(),
                );
            }
        }
        self.directory.revalidate()?;
        Ok(())
    }

    fn read_bounded(&self, name: &OsStr) -> Result<Vec<u8>, String> {
        let before = self.directory.probe_file(name)?;
        let bytes = self
            .directory
            .read_file(name, D32_NATIVE_EVIDENCE_MAX_BYTES)?;
        let after = self.directory.probe_file(name)?;
        if before != after || bytes.len() > D32_NATIVE_EVIDENCE_MAX_BYTES {
            return Err("D32 native evidence file identity changed during read".to_string());
        }
        Ok(bytes)
    }

    fn publish(
        &self,
        context: &VitaExecutionContext,
        session_id: &str,
        turn_id: &str,
        tool_call_id: &str,
        result: &H7ToolResult,
    ) -> Result<(), String> {
        self.validate_directory(&[])?;
        let run_id = d32_run_id(session_id, turn_id, tool_call_id);
        let final_name = OsString::from(format!("{run_id}.json"));
        let temporary_name = OsString::from(format!(".{run_id}.tmp"));
        if self.directory.probe_file(&final_name)?.is_some()
            || self.directory.probe_file(&temporary_name)?.is_some()
        {
            return Err("D32 native evidence publication found stale state".to_string());
        }

        let mut record = result.d32_native_evidence();
        let object = record
            .as_object_mut()
            .ok_or_else(|| "D32 native evidence was not an object".to_string())?;
        object.insert("version".to_string(), json!(1));
        object.insert("run_id".to_string(), json!(run_id));
        object.insert("session_id".to_string(), json!(session_id));
        object.insert("life_id".to_string(), json!(context.life_id()));
        object.insert("task_id".to_string(), json!(context.task_id()));
        object.insert("turn_id".to_string(), json!(turn_id));
        object.insert("tool_call_id".to_string(), json!(tool_call_id));
        object.insert("capability_id".to_string(), json!(D32_CARGO_CAPABILITY_ID));
        object.insert("program_id".to_string(), json!(D32_CARGO_PROGRAM_ID));
        object.insert("profile_id".to_string(), json!(D32_CARGO_PROFILE_ID));
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| "D32 native evidence serialization failed".to_string())?;
        if bytes.is_empty() || bytes.len() > D32_NATIVE_EVIDENCE_MAX_BYTES {
            return Err("D32 native evidence exceeded its publication bound".to_string());
        }

        let result = (|| {
            self.directory.create_new_file(&temporary_name, &bytes)?;
            self.directory.revalidate()?;
            let written = self.read_bounded(&temporary_name)?;
            if written != bytes || crate::sha256_hex(&written) != crate::sha256_hex(&bytes) {
                return Err("D32 native evidence temporary file identity/hash changed".to_string());
            }
            self.directory.revalidate()?;
            self.directory.rename_file(&temporary_name, &final_name)?;
            self.directory.revalidate()?;
            let published = self.read_bounded(&final_name)?;
            if published != bytes || crate::sha256_hex(&published) != crate::sha256_hex(&bytes) {
                return Err("D32 native evidence published identity/hash changed".to_string());
            }
            self.validate_directory(&[&final_name])
        })();
        result
    }
}

fn validate_existing_tree_without_reparse_retained(
    root: &H7RetainedDirectory,
) -> Result<(), String> {
    fn visit(
        current: &H7RetainedDirectory,
        depth: usize,
        entries: &mut usize,
    ) -> Result<(), String> {
        if depth > 256 {
            return Err("D32 stale app-owned projection exceeded its path-depth bound".to_string());
        }
        for name in current.enumerate_children()? {
            *entries = entries.saturating_add(1);
            if *entries > D32_MAX_TOOLCHAIN_FILES + D32_MAX_SOURCE_FILES {
                return Err("D32 stale app-owned projection exceeded its entry bound".to_string());
            }
            if let Ok(child) = current.open_existing_child(&name) {
                visit(&child, depth.saturating_add(1), entries)?;
            } else if current.probe_file_bounded(&name, u64::MAX)?.is_none() {
                return Err(
                    "D32 stale app-owned projection contained an unsupported entry".to_string(),
                );
            }
        }
        Ok(())
    }

    root.revalidate()?;
    let mut entries = 0usize;
    visit(root, 0, &mut entries)?;
    root.revalidate()
}

fn retained_toolchain_images_present(root: &H7RetainedDirectory) -> bool {
    let Ok(bin) = root.open_existing_child(OsStr::new("bin")) else {
        return false;
    };
    bin.probe_file_bounded(OsStr::new("cargo.exe"), D32_MAX_IMAGE_BYTES as u64)
        .ok()
        .flatten()
        .is_some()
        && bin
            .probe_file_bounded(OsStr::new("rustc.exe"), D32_MAX_TOOLCHAIN_FILE_BYTES as u64)
            .ok()
            .flatten()
            .is_some()
        && bin
            .probe_file_bounded(
                OsStr::new("rustdoc.exe"),
                D32_MAX_TOOLCHAIN_FILE_BYTES as u64,
            )
            .ok()
            .flatten()
            .is_some()
}

struct CopyLimits {
    files: usize,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
}

impl CopyLimits {
    fn new(max_files: usize, max_bytes: u64) -> Self {
        Self {
            files: 0,
            bytes: 0,
            max_files,
            max_bytes,
        }
    }

    fn file(&mut self, size: u64) -> Result<(), String> {
        self.files = self.files.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
        if self.files > self.max_files || self.bytes > self.max_bytes {
            return Err("D32 app-owned projection exceeded its bounded copy limit".to_string());
        }
        Ok(())
    }
}

fn snapshot_workspace(
    source: &H7RetainedDirectory,
    destination: &H7RetainedDirectory,
    relative: PathBuf,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    source.revalidate()?;
    destination.revalidate()?;
    for name in source.enumerate_children()? {
        if relative.as_os_str().is_empty()
            && matches!(
                name.to_string_lossy().as_ref(),
                "target" | ".git" | ".cargo"
            )
        {
            continue;
        }
        let child_relative = relative.join(&name);
        if let Ok(source_child) = source.open_existing_child(&name) {
            let destination_child = destination.open_or_create_child(&name)?;
            snapshot_workspace(&source_child, &destination_child, child_relative, limits)?;
        } else if let Some(identity) =
            source.probe_file_bounded(&name, D32_MAX_SOURCE_FILE_BYTES as u64)?
        {
            let size = identity.file_size();
            if size > D32_MAX_SOURCE_FILE_BYTES as u64 {
                return Err("D32 workspace snapshot file exceeded its bound".to_string());
            }
            limits.file(size)?;
            destination.copy_file_from(source, &name, &name, D32_MAX_SOURCE_FILE_BYTES as u64)?;
        } else {
            return Err(
                "D32 workspace snapshot encountered an unsupported namespace entry".to_string(),
            );
        }
    }
    Ok(())
}

fn copy_tree_without_reparse(
    source_retained: &H7RetainedDirectory,
    destination_retained: &H7RetainedDirectory,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    source_retained.revalidate()?;
    destination_retained.revalidate()?;
    for name in source_retained.enumerate_children()? {
        if let Ok(source_child) = source_retained.open_existing_child(&name) {
            let destination_child = destination_retained.open_or_create_child(&name)?;
            copy_tree_without_reparse(&source_child, &destination_child, limits)?;
        } else {
            let identity = source_retained
                .probe_file_bounded(&name, D32_MAX_TOOLCHAIN_FILE_BYTES as u64)?
                .ok_or_else(|| {
                    "D32 toolchain projection encountered an unsupported namespace entry"
                        .to_string()
                })?;
            limits.file(identity.file_size())?;
            destination_retained.copy_file_from(
                source_retained,
                &name,
                &name,
                D32_MAX_TOOLCHAIN_FILE_BYTES as u64,
            )?;
        }
    }
    source_retained.revalidate()?;
    destination_retained.revalidate()?;
    Ok(())
}

pub(crate) fn toolchain_manifest_hash_retained(
    retained: &H7RetainedDirectory,
) -> Result<String, String> {
    let mut entries = Vec::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    collect_manifest_entries_retained(
        retained,
        PathBuf::new(),
        &mut entries,
        &mut file_count,
        &mut total_bytes,
    )?;
    let digest = protocol::d32_manifest_hash_hex(&mut entries)
        .map_err(|_| "D32 toolchain manifest canonical encoding failed".to_string())?;
    Ok(digest)
}

fn collect_manifest_entries_retained(
    retained: &H7RetainedDirectory,
    relative_prefix: PathBuf,
    entries: &mut Vec<(Vec<u8>, [u8; 32])>,
    file_count: &mut usize,
    total_bytes: &mut u64,
) -> Result<(), String> {
    retained.revalidate()?;
    for name in retained.enumerate_children()? {
        let relative = relative_prefix.join(&name);
        if let Ok(child) = retained.open_existing_child(&name) {
            collect_manifest_entries_retained(&child, relative, entries, file_count, total_bytes)?;
        } else {
            let (identity, digest) = retained
                .hash_file_bounded_with_identity(&name, D32_MAX_TOOLCHAIN_FILE_BYTES as u64)?;
            *file_count = file_count.saturating_add(1);
            *total_bytes = total_bytes.saturating_add(identity.file_size());
            if *file_count > D32_MAX_TOOLCHAIN_FILES || *total_bytes > D32_MAX_TOOLCHAIN_BYTES {
                return Err("D32 toolchain manifest exceeded its bounded total".to_string());
            }
            let relative = relative
                .to_str()
                .ok_or_else(|| "D32 toolchain manifest path was not UTF-8".to_string())?
                .replace('\\', "/")
                .into_bytes();
            entries.push((relative, digest));
        }
    }
    retained.revalidate()?;
    Ok(())
}

type CargoConfirmationReceiver = tokio::sync::mpsc::Receiver<H7PendingProcessAction>;

struct CargoInner {
    context: VitaExecutionContext,
    workspace_root: TrustedWorkspaceRoot,
    app_data_root_retained: Arc<H7RetainedDirectory>,
    session_id: String,
    toolchain: Arc<D32ToolchainMirror>,
    sandbox: Arc<H7SandboxProfile>,
    authority: Arc<dyn H7AuthorityPort>,
    confirmation: Arc<H7PendingConfirmationBridge>,
    active_broker: Mutex<Option<Arc<H7ProcessBroker>>>,
    run_mode: SidecarRunMode,
    native_evidence: Option<Arc<D32NativeEvidenceSink>>,
}

/// Production D32 Cargo profile.  If a trusted toolchain or AppContainer
/// cannot be established, the model-visible tool remains fail-closed and the
/// caller can report the exact prerequisite blocker without weakening the
/// process boundary.
pub struct VitaCargoCheckProduction {
    inner: Option<Arc<CargoInner>>,
    confirmation: Arc<H7PendingConfirmationBridge>,
    receiver: Mutex<Option<CargoConfirmationReceiver>>,
    unavailable_reason: Option<String>,
}

impl VitaCargoCheckProduction {
    pub fn new(
        context: VitaExecutionContext,
        workspace_root: TrustedWorkspaceRoot,
        cargo_selection: Option<crate::sidecar::ResolvedCargoSelection>,
        authority: Arc<dyn VitaGitStatusAuthority>,
        session_id: String,
        run_mode: SidecarRunMode,
    ) -> Self {
        let (confirmation, receiver) =
            H7PendingConfirmationBridge::new_with_timeout(std::time::Duration::from_secs(30));
        let attempted = (|| {
            let selected = cargo_selection
                .ok_or_else(|| "D32 Host Cargo selection was unavailable".to_string())?;
            let app_data_root_retained = Arc::clone(&selected.app_data_root_retained);
            let toolchain = D32ToolchainMirror::prepare_from_retained(
                Arc::clone(&app_data_root_retained),
                &selected.cargo_path,
                Arc::clone(&selected.toolchain_root_retained),
                Arc::clone(&selected.toolchain_bin_retained),
                &selected.toolchain_manifest_sha256,
            )?;
            let sandbox = H7SandboxProfile::new()?;
            let native_evidence = if run_mode == SidecarRunMode::D32Canary {
                Some(Arc::new(D32NativeEvidenceSink::new(Arc::clone(
                    &app_data_root_retained,
                ))?))
            } else {
                None
            };
            let authority: Arc<dyn H7AuthorityPort> =
                Arc::new(VitaGitStatusAuthorityAdapter::new(authority));
            Ok::<_, String>(Arc::new(CargoInner {
                context,
                workspace_root,
                app_data_root_retained,
                session_id,
                toolchain,
                sandbox,
                authority,
                confirmation: Arc::clone(&confirmation),
                active_broker: Mutex::new(None),
                run_mode,
                native_evidence,
            }))
        })();
        let (inner, unavailable_reason) = match attempted {
            Ok(inner) => (Some(inner), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            inner,
            confirmation,
            receiver: Mutex::new(Some(receiver)),
            unavailable_reason,
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        self.inner.is_some()
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }

    pub fn contributor(&self) -> VitaCargoCheckToolContributor {
        VitaCargoCheckToolContributor {
            inner: self.inner.clone(),
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn take_confirmation_receiver(&self) -> Option<CargoConfirmationReceiver> {
        self.receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    pub fn cancel(&self) {
        if let Some(inner) = &self.inner {
            if let Ok(broker) = inner.active_broker.lock() {
                if let Some(broker) = broker.as_ref() {
                    broker.cancel();
                }
            }
        }
        self.confirmation.cancel_pending();
    }

    pub fn begin_turn(&self) {
        self.confirmation.begin_turn();
        if let Some(inner) = &self.inner {
            if let Ok(broker) = inner.active_broker.lock() {
                if let Some(broker) = broker.as_ref() {
                    broker.begin_turn();
                }
            }
        }
    }

    pub fn cancel_turn(&self) {
        if let Some(inner) = &self.inner {
            if let Ok(broker) = inner.active_broker.lock() {
                if let Some(broker) = broker.as_ref() {
                    broker.cancel_turn();
                }
            }
        }
        self.confirmation.cancel_pending();
    }
}

pub struct VitaCargoCheckToolContributor {
    inner: Option<Arc<CargoInner>>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaCargoCheckToolContributor {
    pub(crate) fn available(&self) -> bool {
        self.inner.is_some()
    }
}

impl ToolContributor for VitaCargoCheckToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        if !self.available() {
            // A missing toolchain, scratch root, or AppContainer profile is a
            // production prerequisite failure.  Do not advertise a tool that
            // cannot ever reach the fixed sandbox; the Host descriptor stays
            // fail-closed and the sidecar can report the blocker explicitly.
            return Vec::new();
        }
        vec![Arc::new(VitaCargoCheckTool {
            inner: self.inner.clone(),
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoCheckArguments {}

fn cargo_check_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": false
    })
}

fn bounded_tool_id(value: &str) -> Option<String> {
    (!value.is_empty() && value.chars().count() <= 256 && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn denied_value() -> Value {
    json!({
        "status": "denied",
        "exit_code": null,
        "timed_out": false,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": false,
        "stderr_truncated": false
    })
}

struct VitaCargoCheckTool {
    inner: Option<Arc<CargoInner>>,
    tool_call_count: Arc<AtomicUsize>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaCargoCheckTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(D32_CARGO_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: D32_CARGO_TOOL_NAME.to_string(),
            description: "Run the fixed Host-owned sandboxed cargo check profile.".to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&cargo_check_schema_contract())
                .expect("D32 cargo schema is static and valid"),
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
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        let inner = self.inner.clone();
        Box::pin(async move {
            let value = match (
                inner,
                call.tool_name.name == D32_CARGO_TOOL_NAME && call.tool_name.is_default_namespace(),
                bounded_tool_id(&call.call_id),
                bounded_tool_id(&call.turn_id),
                call.function_arguments()
                    .ok()
                    .and_then(|raw| serde_json::from_str::<CargoCheckArguments>(raw).ok()),
            ) {
                (Some(inner), true, Some(call_id), Some(turn_id), Some(_)) => {
                    // Reserve only app-owned directories first.  The governed
                    // workspace remains unread until Host has performed its
                    // canonical D28 scope evaluation below.
                    let projection = D32ExecutionProjection::prepare_layout(
                        Arc::clone(&inner.app_data_root_retained),
                        &inner.workspace_root,
                        Arc::clone(&inner.toolchain),
                        &inner.session_id,
                        &turn_id,
                        &call_id,
                    );
                    let projection = match projection {
                        Ok(projection) => projection,
                        Err(_) => {
                            return Ok(Box::new(JsonToolOutput::with_success(
                                denied_value(),
                                Some(false),
                            )) as Box<dyn ToolOutput>)
                        }
                    };
                    let catalog = match H7ExecutableCatalog::cargo_check_projected(
                        H7D32CatalogResources {
                            execution_root: Arc::clone(&projection.retained_root),
                            source_root: Arc::clone(&projection.retained_source),
                            cargo_home: Arc::clone(&projection.retained_cargo_home),
                            target: Arc::clone(&projection.retained_target),
                            toolchain_root: Arc::clone(&projection.retained_toolchain),
                            toolchain_bin: Arc::clone(&projection.retained_toolchain_bin),
                        },
                        projection.toolchain_manifest_hash.clone(),
                    ) {
                        Ok(catalog) => Arc::new(catalog),
                        Err(_error) => {
                            if let Err(error) = projection.cleanup() {
                                eprintln!("D32 catalog cleanup denied: {error}");
                            }
                            return Ok(Box::new(JsonToolOutput::with_success(
                                denied_value(),
                                Some(false),
                            )) as Box<dyn ToolOutput>);
                        }
                    };
                    if inner
                        .sandbox
                        .grant_execution_root(
                            &projection.retained_root,
                            &projection.retained_toolchain,
                        )
                        .is_err()
                    {
                        if let Err(error) = projection.cleanup() {
                            eprintln!("D32 sandbox cleanup denied: {error}");
                        }
                        return Ok(Box::new(JsonToolOutput::with_success(
                            denied_value(),
                            Some(false),
                        )) as Box<dyn ToolOutput>);
                    }
                    let broker = if inner.run_mode == SidecarRunMode::D32Canary {
                        H7ProcessBroker::new_with_d32_real_canary(
                            inner.context.clone(),
                            Arc::clone(&catalog),
                            Arc::clone(&inner.authority),
                            Arc::clone(&inner.confirmation),
                        )
                    } else {
                        H7ProcessBroker::new(
                            inner.context.clone(),
                            Arc::clone(&catalog),
                            Arc::clone(&inner.authority),
                            Arc::clone(&inner.confirmation),
                        )
                    };
                    let request = H7ProcessRequest::synthetic_fixed(
                        &call_id,
                        &turn_id,
                        D32_CARGO_PROGRAM_ID,
                        &["check", "--locked"],
                    );
                    let result = match catalog.prepare_fixed_workspace_action(
                        inner.context.clone(),
                        request,
                        D32_CARGO_CAPABILITY_ID,
                        D32_CARGO_PROFILE_ID,
                        inner.workspace_root.clone(),
                        Arc::clone(&inner.sandbox),
                    ) {
                        Ok(action) => {
                            // D28 scope evaluation is the first Host-owned
                            // operation.  Only after it completes may the
                            // projection read the governed workspace.
                            if inner.authority.evaluate_workspace_scope(&action).is_err()
                                || projection.populate(&inner.workspace_root).is_err()
                            {
                                denied_value()
                            } else {
                                if let Ok(mut active) = inner.active_broker.lock() {
                                    *active = Some(Arc::clone(&broker));
                                }
                                let result = broker.execute(action).await;
                                if let Ok(mut active) = inner.active_broker.lock() {
                                    if active
                                        .as_ref()
                                        .is_some_and(|current| Arc::ptr_eq(current, &broker))
                                    {
                                        *active = None;
                                    }
                                }
                                #[cfg(feature = "d32-a-test-helper")]
                                record_internal_evidence(result.internal_process_evidence());
                                let evidence_published = if inner.run_mode
                                    == SidecarRunMode::D32Canary
                                {
                                    inner
                                        .native_evidence
                                        .as_ref()
                                        .ok_or_else(|| {
                                            "D32 native evidence sink was unavailable".to_string()
                                        })
                                        .and_then(|sink| {
                                            sink.publish(
                                                &inner.context,
                                                &inner.session_id,
                                                &turn_id,
                                                &call_id,
                                                &result,
                                            )
                                        })
                                } else {
                                    Ok(())
                                };
                                if evidence_published.is_ok() {
                                    result.cargo_value()
                                } else {
                                    denied_value()
                                }
                            }
                        }
                        Err(_error) => denied_value(),
                    };
                    // The catalog retains the prepared source-directory handle
                    // used by the H7 binding.  Release the broker/catalog before
                    // removing this per-action projection; otherwise Windows
                    // correctly reports ERROR_SHARING_VIOLATION even after the
                    // child Job has reached terminal state.
                    drop(broker);
                    drop(catalog);
                    if let Err(error) = projection.cleanup() {
                        // A terminal run must not be reported as a successful
                        // Cargo result while its app-owned run root is still
                        // present or has become unsafe to remove.
                        eprintln!("D32 terminal cleanup denied: {error}");
                        denied_value()
                    } else {
                        result
                    }
                }
                _ => denied_value(),
            };
            Ok(Box::new(JsonToolOutput::with_success(value, Some(false))) as Box<dyn ToolOutput>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_model_schema_is_exactly_zero_argument() {
        assert_eq!(
            cargo_check_schema_contract(),
            json!({
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            })
        );
        assert!(serde_json::from_str::<CargoCheckArguments>(r#"{}"#).is_ok());
        assert!(serde_json::from_str::<CargoCheckArguments>(r#"{"args": []}"#).is_err());
    }

    #[test]
    fn cargo_profile_identity_is_static() {
        assert_eq!(D32_CARGO_PROGRAM_ID, "cargo-check-v1");
        assert_eq!(D32_CARGO_PROFILE_ID, "d32.workspace.cargo_check.v1");
        assert_eq!(D32_CARGO_TOOL_NAME, "vita_workspace_cargo_check");
        assert_eq!(
            D32_CARGO_CAPABILITY_ID,
            "vita.process.workspace.cargo_check"
        );
        assert_eq!(D32_CARGO_NO_GIT_METADATA_FENCE, "d32-no-git-fence-v1");
    }

    #[test]
    fn each_call_has_a_distinct_profile_bound_run_identity() {
        let first = d32_run_id("session", "turn", "call-a");
        let second = d32_run_id("session", "turn", "call-b");
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert_eq!(first, d32_run_id("session", "turn", "call-a"));
    }

    #[test]
    fn denied_cargo_output_is_the_frozen_public_shape() {
        let value = denied_value();
        let object = value.as_object().expect("D32 denied object");
        assert_eq!(object.len(), 7);
        for field in [
            "status",
            "exit_code",
            "timed_out",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
        ] {
            assert!(object.contains_key(field), "missing frozen field: {field}");
        }
        for forbidden in [
            "process_created",
            "user_code_started",
            "process_tree_remaining",
            "job_terminated",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "telemetry leaked: {forbidden}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn projection_copy_failure_rolls_back_partial_run_root() {
        let app_data = tempfile::tempdir().expect("D32 projection app data");
        let workspace = tempfile::tempdir().expect("D32 projection workspace");
        fs::write(workspace.path().join("Cargo.toml"), b"[package]\n").expect("manifest");
        let trusted = TrustedWorkspaceRoot::acquire(workspace.path()).expect("trusted root");
        let toolchain = tempfile::tempdir().expect("D32 projection toolchain");
        fs::create_dir_all(toolchain.path().join("bin")).expect("toolchain bin");
        let cargo = toolchain.path().join("bin/cargo.exe");
        let rustc = toolchain.path().join("bin/rustc.exe");
        let rustdoc = toolchain.path().join("bin/rustdoc.exe");
        for path in [&cargo, &rustc, &rustdoc] {
            fs::write(path, b"fixture").expect("toolchain image");
        }
        let mirror = Arc::new(D32ToolchainMirror {
            root: toolchain.path().to_path_buf(),
            retained_root: Arc::new(
                H7RetainedDirectory::open(toolchain.path()).expect("retained toolchain"),
            ),
            retained_bin: Arc::new(
                H7RetainedDirectory::open(toolchain.path().join("bin").as_path())
                    .expect("retained toolchain bin"),
            ),
            cargo_path: cargo.clone(),
            rustc_path: rustc,
            rustdoc_path: rustdoc,
            manifest_hash: "0".repeat(64),
        });
        let projection = D32ExecutionProjection::prepare_layout(
            Arc::new(H7RetainedDirectory::open(app_data.path()).expect("retained app data root")),
            &trusted,
            mirror,
            "d32-test-session",
            "d32-test-turn",
            "d32-test-call",
        )
        .expect("projection layout");
        let run_root = projection.root.clone();
        fs::remove_file(cargo).expect("remove toolchain image for deterministic failure");
        assert!(projection.populate(&trusted).is_err());
        drop(projection);
        assert!(
            !run_root.exists(),
            "partial D32 projection root survived a copy failure"
        );
    }
}
