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
use sha2::Digest;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use crate::d29h7::{
    H7AuthorityPort, H7ExecutableCatalog, H7PendingConfirmationBridge, H7PendingProcessAction,
    H7ProcessBroker, H7ProcessRequest, H7SandboxProfile, VitaGitStatusAuthorityAdapter,
    VITA_WORKSPACE_CARGO_CHECK_CAPABILITY_ID, VITA_WORKSPACE_CARGO_CHECK_PROFILE_ID,
    VITA_WORKSPACE_CARGO_CHECK_TOOL_NAME,
};
use crate::{TrustedWorkspaceRoot, VitaExecutionContext, VitaGitStatusAuthority};

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
const D32_MAX_TOOLCHAIN_FILES: usize = 131_072;
const D32_MAX_TOOLCHAIN_FILE_BYTES: usize = 512 * 1024 * 1024;
const D32_MAX_TOOLCHAIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const D32_MAX_SOURCE_FILE_BYTES: usize = 64 * 1024 * 1024;
const D32_MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;

pub(crate) const D32_TOOLCHAIN_MIRROR_ROOT_NAME: &str = "d32-toolchains";
pub(crate) const D32_RUNS_DIR_NAME: &str = "runs";

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
#[derive(Clone, Debug)]
pub(crate) struct D32ToolchainMirror {
    pub(crate) root: PathBuf,
    pub(crate) cargo_path: PathBuf,
    pub(crate) rustc_path: PathBuf,
    pub(crate) rustdoc_path: PathBuf,
    pub(crate) manifest_hash: String,
}

impl D32ToolchainMirror {
    pub(crate) fn prepare(
        app_data_root: &std::path::Path,
        selected_cargo_path: &std::path::Path,
        selected_root: &std::path::Path,
        expected_manifest_hash: &str,
    ) -> Result<Arc<Self>, String> {
        if !app_data_root.is_absolute()
            || !selected_cargo_path.is_absolute()
            || !selected_root.is_absolute()
            || expected_manifest_hash.len() != 64
            || expected_manifest_hash
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit())
        {
            return Err("D32 Host toolchain mirror evidence was not exact".to_string());
        }
        let app_data_root = fs::canonicalize(app_data_root)
            .map_err(|_| "D32 app-data root could not be canonicalized".to_string())?;
        let selected_root = fs::canonicalize(selected_root)
            .map_err(|_| "D32 selected toolchain root could not be canonicalized".to_string())?;
        let selected_cargo = fs::canonicalize(selected_cargo_path).ok();
        let root_cargo = fs::canonicalize(selected_root.join("bin/cargo.exe")).ok();
        if !selected_root.is_dir()
            || !selected_root.join("bin/rustc.exe").is_file()
            || !selected_root.join("bin/rustdoc.exe").is_file()
            || selected_cargo.is_none()
            || selected_cargo != root_cargo
        {
            return Err("D32 Host-selected Rust toolchain was incomplete".to_string());
        }

        let mirror_parent = app_data_root.join(D32_TOOLCHAIN_MIRROR_ROOT_NAME);
        fs::create_dir_all(&mirror_parent)
            .map_err(|_| "D32 toolchain mirror parent could not be created".to_string())?;
        let mirror_root = mirror_parent.join(expected_manifest_hash);
        let valid_existing = fs::symlink_metadata(&mirror_root)
            .ok()
            .is_some_and(|metadata| !is_reparse(&metadata))
            && mirror_root.is_dir()
            && validate_existing_tree_without_reparse(&mirror_root).is_ok()
            && toolchain_manifest_hash(&mirror_root).ok().as_deref()
                == Some(expected_manifest_hash)
            && mirror_root.join("bin/cargo.exe").is_file()
            && mirror_root.join("bin/rustc.exe").is_file()
            && mirror_root.join("bin/rustdoc.exe").is_file();

        if !valid_existing {
            if fs::symlink_metadata(&mirror_root).is_ok() {
                validate_existing_tree_without_reparse(&mirror_root)?;
                fs::remove_dir_all(&mirror_root)
                    .map_err(|_| "D32 stale toolchain mirror could not be removed".to_string())?;
            }
            let staging = mirror_parent.join(format!(".{expected_manifest_hash}.staging"));
            if fs::symlink_metadata(&staging).is_ok() {
                validate_existing_tree_without_reparse(&staging)?;
                fs::remove_dir_all(&staging)
                    .map_err(|_| "D32 stale toolchain staging could not be removed".to_string())?;
            }
            fs::create_dir_all(&staging)
                .map_err(|_| "D32 toolchain staging root could not be created".to_string())?;
            let mut limits = CopyLimits::new(D32_MAX_TOOLCHAIN_FILES, D32_MAX_TOOLCHAIN_BYTES);
            copy_tree_without_reparse(&selected_root, &staging, &mut limits)?;
            copy_regular_file_without_reparse(
                selected_cargo_path,
                &staging.join("bin/cargo.exe"),
                D32_MAX_IMAGE_BYTES,
            )?;
            let staged_manifest = toolchain_manifest_hash(&staging)?;
            if staged_manifest != expected_manifest_hash {
                let _ = fs::remove_dir_all(&staging);
                return Err("D32 staged toolchain mirror did not match Host evidence".to_string());
            }
            fs::rename(&staging, &mirror_root)
                .map_err(|_| "D32 toolchain mirror could not be finalized".to_string())?;
        }

        let manifest_hash = toolchain_manifest_hash(&mirror_root)?;
        if manifest_hash != expected_manifest_hash {
            return Err("D32 toolchain mirror manifest changed".to_string());
        }
        Ok(Arc::new(Self {
            cargo_path: mirror_root.join("bin/cargo.exe"),
            rustc_path: mirror_root.join("bin/rustc.exe"),
            rustdoc_path: mirror_root.join("bin/rustdoc.exe"),
            root: mirror_root,
            manifest_hash,
        }))
    }
}

/// The app-owned execution projection consumed by the sandboxed child.  The
/// live workspace and the user-profile toolchain never become the child cwd or
/// executable image; they are copied once, before the production contributor
/// is exposed, into this deterministic root.
#[derive(Clone, Debug)]
pub(crate) struct D32ExecutionProjection {
    pub(crate) root: PathBuf,
    pub(crate) source_root: PathBuf,
    pub(crate) toolchain_root: PathBuf,
    pub(crate) cargo_home: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) cargo_path: PathBuf,
    pub(crate) rustc_path: PathBuf,
    pub(crate) rustdoc_path: PathBuf,
    pub(crate) toolchain_manifest_hash: String,
}

impl D32ExecutionProjection {
    pub(crate) fn prepare(
        app_data_root: PathBuf,
        workspace_root: &TrustedWorkspaceRoot,
        toolchain: Arc<D32ToolchainMirror>,
        session_id: &str,
        turn_id: &str,
        tool_call_id: &str,
    ) -> Result<Arc<Self>, String> {
        if !app_data_root.is_absolute()
            || session_id.is_empty()
            || turn_id.is_empty()
            || tool_call_id.is_empty()
        {
            return Err("D32 app-owned projection paths must be absolute".to_string());
        }
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D32 governed workspace changed before staging".to_string())?;
        let app_data_root = fs::canonicalize(&app_data_root)
            .map_err(|_| "D32 app-data root could not be canonicalized".to_string())?;
        let root = app_data_root
            .join(D32_EXECUTION_ROOT_NAME)
            .join(D32_RUNS_DIR_NAME)
            .join(d32_run_id(session_id, turn_id, tool_call_id));
        match fs::symlink_metadata(&root) {
            Ok(metadata) => {
                if is_reparse(&metadata) {
                    return Err("D32 stale app-owned projection was a reparse point".to_string());
                }
                validate_existing_tree_without_reparse(&root)?;
                fs::remove_dir_all(&root).map_err(|_| {
                    "D32 stale app-owned projection could not be removed".to_string()
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err("D32 stale app-owned projection metadata was unavailable".to_string())
            }
        }
        let source_root = root.join(D32_SOURCE_DIR_NAME);
        let toolchain_root = toolchain.root.clone();
        let cargo_home = root.join(D32_CARGO_HOME_DIR_NAME);
        let target = root.join(D32_TARGET_DIR_NAME);
        for path in [&source_root, &cargo_home, &target] {
            fs::create_dir_all(path).map_err(|_| {
                format!(
                    "D32 projection directory could not be created: {}",
                    path.display()
                )
            })?;
        }

        let mut source_limits = CopyLimits::new(D32_MAX_SOURCE_FILES, D32_MAX_SOURCE_BYTES);
        snapshot_workspace(
            workspace_root,
            workspace_root.final_path(),
            &source_root,
            PathBuf::new(),
            &mut source_limits,
        )?;

        if !toolchain_root.is_absolute()
            || !toolchain_root.is_dir()
            || !toolchain.cargo_path.is_file()
            || !toolchain.rustc_path.is_file()
            || !toolchain.rustdoc_path.is_file()
        {
            return Err("D32 app-owned toolchain mirror was incomplete".to_string());
        }
        let manifest_hash = toolchain.manifest_hash.clone();
        Ok(Arc::new(Self {
            root,
            source_root,
            toolchain_root,
            cargo_home,
            target,
            cargo_path: toolchain.cargo_path.clone(),
            rustc_path: toolchain.rustc_path.clone(),
            rustdoc_path: toolchain.rustdoc_path.clone(),
            toolchain_manifest_hash: manifest_hash,
        }))
    }

    pub(crate) fn cleanup(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) => {
                if is_reparse(&metadata) {
                    return Err("D32 run root became a reparse point".to_string());
                }
                validate_existing_tree_without_reparse(&self.root)?;
                fs::remove_dir_all(&self.root)
                    .map_err(|_| "D32 run root could not be cleaned".to_string())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("D32 run root metadata was unavailable".to_string()),
        }
        Ok(())
    }
}

pub(crate) fn d32_run_id(session_id: &str, turn_id: &str, tool_call_id: &str) -> String {
    crate::sha256_hex(
        format!("{session_id}\u{1f}{turn_id}\u{1f}{tool_call_id}\u{1f}{D32_CARGO_PROFILE_ID}")
            .as_bytes(),
    )
}

fn validate_existing_tree_without_reparse(root: &std::path::Path) -> Result<(), String> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut entries = 0usize;
    while let Some((current, depth)) = pending.pop() {
        if depth > 256 {
            return Err("D32 stale app-owned projection exceeded its path-depth bound".to_string());
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| "D32 stale app-owned projection metadata was unavailable".to_string())?;
        if is_reparse(&metadata) {
            return Err(format!(
                "D32 stale app-owned projection contained a reparse entry: {}",
                current.display()
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&current)
                .map_err(|_| "D32 stale app-owned projection enumeration failed".to_string())?
            {
                let entry = entry
                    .map_err(|_| "D32 stale app-owned projection enumeration failed".to_string())?;
                entries = entries.saturating_add(1);
                if entries > D32_MAX_TOOLCHAIN_FILES + D32_MAX_SOURCE_FILES {
                    return Err(
                        "D32 stale app-owned projection exceeded its entry bound".to_string()
                    );
                }
                pending.push((entry.path(), depth.saturating_add(1)));
            }
        } else if !metadata.is_file() {
            return Err(
                "D32 stale app-owned projection contained an unsupported entry".to_string(),
            );
        }
    }
    Ok(())
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

fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn snapshot_workspace(
    root: &TrustedWorkspaceRoot,
    source: &std::path::Path,
    destination: &std::path::Path,
    relative: PathBuf,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    let entries = fs::read_dir(source).map_err(|_| {
        format!(
            "D32 governed workspace could not be enumerated: {}",
            source.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| "D32 governed workspace enumeration failed".to_string())?;
        let name = entry.file_name();
        if relative.as_os_str().is_empty()
            && matches!(
                name.to_string_lossy().as_ref(),
                "target" | ".git" | ".cargo"
            )
        {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "D32 workspace metadata read failed".to_string())?;
        if is_reparse(&metadata) {
            return Err(format!(
                "D32 workspace snapshot rejected reparse entry: {}",
                path.display()
            ));
        }
        let child_relative = relative.join(&name);
        let child_destination = destination.join(&name);
        if metadata.is_dir() {
            fs::create_dir_all(&child_destination)
                .map_err(|_| "D32 source projection directory creation failed".to_string())?;
            snapshot_workspace(root, &path, &child_destination, child_relative, limits)?;
        } else if metadata.is_file() {
            let prepared = root
                .prepare_target(&child_relative)
                .map_err(|_| "D32 workspace target preparation failed".to_string())?;
            if prepared.kind() != crate::PreparedWorkspaceTargetKind::ExistingFile {
                return Err("D32 workspace snapshot target classification changed".to_string());
            }
            let size = metadata.len();
            if size > D32_MAX_SOURCE_FILE_BYTES as u64 {
                return Err("D32 workspace snapshot file exceeded its bound".to_string());
            }
            limits.file(size)?;
            let bytes = prepared
                .read_existing_file_raw_bounded(D32_MAX_SOURCE_FILE_BYTES)
                .map_err(|_| "D32 workspace snapshot read failed".to_string())?;
            if bytes.len() as u64 != size {
                return Err("D32 workspace snapshot changed during read".to_string());
            }
            fs::write(&child_destination, bytes)
                .map_err(|_| "D32 source projection write failed".to_string())?;
        } else {
            return Err(
                "D32 workspace snapshot encountered an unsupported namespace entry".to_string(),
            );
        }
    }
    Ok(())
}

fn copy_tree_without_reparse(
    source: &std::path::Path,
    destination: &std::path::Path,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    let entries = fs::read_dir(source)
        .map_err(|_| "D32 toolchain projection enumeration failed".to_string())?;
    for entry in entries {
        let entry = entry.map_err(|_| "D32 toolchain projection enumeration failed".to_string())?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|_| "D32 toolchain metadata read failed".to_string())?;
        if is_reparse(&metadata) {
            return Err(format!(
                "D32 toolchain projection rejected reparse entry: {}",
                source_path.display()
            ));
        }
        if metadata.is_dir() {
            fs::create_dir_all(&destination_path)
                .map_err(|_| "D32 toolchain projection directory creation failed".to_string())?;
            copy_tree_without_reparse(&source_path, &destination_path, limits)?;
        } else if metadata.is_file() {
            copy_regular_file_without_reparse_with_limits(&source_path, &destination_path, limits)?;
        } else {
            return Err(
                "D32 toolchain projection encountered an unsupported namespace entry".to_string(),
            );
        }
    }
    Ok(())
}

fn copy_regular_file_without_reparse(
    source: &std::path::Path,
    destination: &std::path::Path,
    max_bytes: usize,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| "D32 executable metadata read failed".to_string())?;
    if is_reparse(&metadata) || !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err("D32 executable projection source was not a bounded regular file".to_string());
    }
    stream_copy(source, destination, metadata.len())?;
    Ok(())
}

fn copy_regular_file_without_reparse_with_limits(
    source: &std::path::Path,
    destination: &std::path::Path,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| "D32 toolchain metadata read failed".to_string())?;
    if is_reparse(&metadata)
        || !metadata.is_file()
        || metadata.len() > D32_MAX_TOOLCHAIN_FILE_BYTES as u64
    {
        return Err("D32 toolchain projection source was not a bounded regular file".to_string());
    }
    limits.file(metadata.len())?;
    stream_copy(source, destination, metadata.len())?;
    Ok(())
}

fn stream_copy(
    source: &std::path::Path,
    destination: &std::path::Path,
    expected_bytes: u64,
) -> Result<(), String> {
    let mut input =
        File::open(source).map_err(|_| "D32 projection source could not be opened".to_string())?;
    let mut output = File::create(destination)
        .map_err(|_| "D32 projection destination could not be created".to_string())?;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|_| "D32 projection source could not be read".to_string())?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| "D32 projection destination could not be written".to_string())?;
        copied = copied.saturating_add(read as u64);
    }
    if copied != expected_bytes {
        return Err("D32 projection source changed during streaming copy".to_string());
    }
    output
        .flush()
        .map_err(|_| "D32 projection destination could not be flushed".to_string())?;
    Ok(())
}

fn toolchain_manifest_hash(root: &std::path::Path) -> Result<String, String> {
    let mut entries = Vec::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    collect_manifest_entries(root, root, &mut entries, &mut file_count, &mut total_bytes)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded = serde_json::to_vec(&entries)
        .map_err(|_| "D32 toolchain manifest serialization failed".to_string())?;
    Ok(crate::sha256_hex(&encoded))
}

fn collect_manifest_entries(
    root: &std::path::Path,
    current: &std::path::Path,
    entries: &mut Vec<(String, String)>,
    file_count: &mut usize,
    total_bytes: &mut u64,
) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|_| "D32 toolchain manifest enumeration failed".to_string())?
    {
        let entry = entry.map_err(|_| "D32 toolchain manifest enumeration failed".to_string())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "D32 toolchain manifest metadata failed".to_string())?;
        if is_reparse(&metadata) {
            return Err("D32 toolchain manifest rejected reparse entry".to_string());
        }
        if metadata.is_dir() {
            collect_manifest_entries(root, &path, entries, file_count, total_bytes)?;
        } else if metadata.is_file() {
            *file_count = file_count.saturating_add(1);
            *total_bytes = total_bytes.saturating_add(metadata.len());
            if *file_count > D32_MAX_TOOLCHAIN_FILES || *total_bytes > D32_MAX_TOOLCHAIN_BYTES {
                return Err("D32 toolchain manifest exceeded its bounded total".to_string());
            }
            let digest = hash_bounded_file(&path, D32_MAX_TOOLCHAIN_FILE_BYTES as u64)?;
            entries.push((
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest,
            ));
        }
    }
    Ok(())
}

fn hash_bounded_file(path: &std::path::Path, max_bytes: u64) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|_| "D32 toolchain manifest file open failed".to_string())?;
    let mut digest = sha2::Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "D32 toolchain manifest file read failed".to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err("D32 toolchain manifest file exceeded its bound".to_string());
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

type CargoConfirmationReceiver = tokio::sync::mpsc::Receiver<H7PendingProcessAction>;

struct CargoInner {
    context: VitaExecutionContext,
    workspace_root: TrustedWorkspaceRoot,
    app_data_root: PathBuf,
    session_id: String,
    toolchain: Arc<D32ToolchainMirror>,
    sandbox: Arc<H7SandboxProfile>,
    authority: Arc<dyn H7AuthorityPort>,
    confirmation: Arc<H7PendingConfirmationBridge>,
    active_broker: Mutex<Option<Arc<H7ProcessBroker>>>,
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
        app_data_root: PathBuf,
        cargo_path: PathBuf,
        trusted_toolchain_root: Option<PathBuf>,
        expected_toolchain_manifest_hash: Option<String>,
        authority: Arc<dyn VitaGitStatusAuthority>,
        session_id: String,
    ) -> Self {
        let (confirmation, receiver) =
            H7PendingConfirmationBridge::new_with_timeout(std::time::Duration::from_secs(30));
        let attempted = (|| {
            let selected_root = trusted_toolchain_root
                .ok_or_else(|| "D32 Host-selected Rust toolchain was unavailable".to_string())?;
            let expected_manifest_hash = expected_toolchain_manifest_hash.ok_or_else(|| {
                "D32 Host toolchain manifest evidence was unavailable".to_string()
            })?;
            let toolchain = D32ToolchainMirror::prepare(
                &app_data_root,
                &cargo_path,
                &selected_root,
                &expected_manifest_hash,
            )?;
            let sandbox = H7SandboxProfile::new()?;
            let authority: Arc<dyn H7AuthorityPort> =
                Arc::new(VitaGitStatusAuthorityAdapter::new(authority));
            Ok::<_, String>(Arc::new(CargoInner {
                context,
                workspace_root,
                app_data_root,
                session_id,
                toolchain,
                sandbox,
                authority,
                confirmation: Arc::clone(&confirmation),
                active_broker: Mutex::new(None),
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
                    let projection = D32ExecutionProjection::prepare(
                        inner.app_data_root.clone(),
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
                        projection.cargo_path.clone(),
                        projection.source_root.clone(),
                        projection.root.clone(),
                        projection.toolchain_root.clone(),
                        projection.rustc_path.clone(),
                        projection.rustdoc_path.clone(),
                    ) {
                        Ok(catalog) => Arc::new(catalog),
                        Err(_) => {
                            let _ = projection.cleanup();
                            return Ok(Box::new(JsonToolOutput::with_success(
                                denied_value(),
                                Some(false),
                            )) as Box<dyn ToolOutput>);
                        }
                    };
                    if inner
                        .sandbox
                        .grant_execution_root(&projection.root, &projection.toolchain_root)
                        .is_err()
                    {
                        let _ = projection.cleanup();
                        return Ok(Box::new(JsonToolOutput::with_success(
                            denied_value(),
                            Some(false),
                        )) as Box<dyn ToolOutput>);
                    }
                    let broker = H7ProcessBroker::new(
                        inner.context.clone(),
                        Arc::clone(&catalog),
                        Arc::clone(&inner.authority),
                        Arc::clone(&inner.confirmation),
                    );
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
                            result.cargo_value()
                        }
                        Err(_) => denied_value(),
                    };
                    if projection.cleanup().is_err() {
                        // A terminal run must not be reported as a successful
                        // Cargo result while its app-owned run root is still
                        // present or has become unsafe to remove.
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
}
