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
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use crate::d29h7::{
    H7ExecutableCatalog, H7PendingConfirmationBridge, H7PendingProcessAction, H7ProcessBroker,
    H7ProcessRequest, H7SandboxProfile, VitaGitStatusAuthorityAdapter,
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
pub(crate) const D32_TOOLCHAIN_DIR_NAME: &str = "toolchain";
pub(crate) const D32_CARGO_HOME_DIR_NAME: &str = "cargo-home";
pub(crate) const D32_TARGET_DIR_NAME: &str = "target";

const D32_MAX_SOURCE_FILES: usize = 16_384;
const D32_MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const D32_MAX_TOOLCHAIN_FILES: usize = 131_072;
const D32_MAX_TOOLCHAIN_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const D32_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

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
        cargo_path: PathBuf,
        trusted_toolchain_root: Option<PathBuf>,
        expected_toolchain_manifest_hash: Option<&str>,
    ) -> Result<Arc<Self>, String> {
        if !app_data_root.is_absolute() || !cargo_path.is_absolute() {
            return Err("D32 app-owned projection paths must be absolute".to_string());
        }
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D32 governed workspace changed before staging".to_string())?;
        let app_data_root = fs::canonicalize(&app_data_root)
            .map_err(|_| "D32 app-data root could not be canonicalized".to_string())?;
        let root = app_data_root.join(D32_EXECUTION_ROOT_NAME);
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
        let toolchain_root = root.join(D32_TOOLCHAIN_DIR_NAME);
        let cargo_home = root.join(D32_CARGO_HOME_DIR_NAME);
        let target = root.join(D32_TARGET_DIR_NAME);
        for path in [&source_root, &toolchain_root, &cargo_home, &target] {
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

        let toolchain_source = match trusted_toolchain_root {
            Some(root) => root,
            None => crate::d29h7::d32_trusted_toolchain_root(&cargo_path)?,
        };
        if !toolchain_source.is_absolute()
            || !toolchain_source.is_dir()
            || !toolchain_source.join("bin/rustc.exe").is_file()
            || !toolchain_source.join("bin/rustdoc.exe").is_file()
        {
            return Err("D32 Host-selected Rust toolchain was incomplete".to_string());
        }
        let mut toolchain_limits =
            CopyLimits::new(D32_MAX_TOOLCHAIN_FILES, D32_MAX_TOOLCHAIN_BYTES);
        copy_tree_without_reparse(&toolchain_source, &toolchain_root, &mut toolchain_limits)?;

        let staged_bin = toolchain_root.join("bin");
        fs::create_dir_all(&staged_bin)
            .map_err(|_| "D32 staged toolchain bin directory could not be created".to_string())?;
        let staged_cargo = staged_bin.join("cargo.exe");
        copy_regular_file_without_reparse(&cargo_path, &staged_cargo, D32_MAX_FILE_BYTES)?;
        let rustc_source = toolchain_source.join("bin").join("rustc.exe");
        let rustdoc_source = toolchain_source.join("bin").join("rustdoc.exe");
        let staged_rustc = staged_bin.join("rustc.exe");
        let staged_rustdoc = staged_bin.join("rustdoc.exe");
        if !staged_rustc.is_file() || !staged_rustdoc.is_file() {
            return Err("D32 staged Rust toolchain did not contain rustc/rustdoc".to_string());
        }
        let manifest_hash = toolchain_manifest_hash(&toolchain_root)?;
        if expected_toolchain_manifest_hash.is_some_and(|expected| expected != manifest_hash) {
            return Err("D32 projected toolchain did not match Host profile".to_string());
        }
        if !rustc_source.is_file() || !rustdoc_source.is_file() {
            return Err("D32 trusted Rust toolchain was incomplete".to_string());
        }
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D32 governed workspace changed after staging".to_string())?;
        Ok(Arc::new(Self {
            root,
            source_root,
            toolchain_root,
            cargo_home,
            target,
            cargo_path: staged_cargo,
            rustc_path: staged_rustc,
            rustdoc_path: staged_rustdoc,
            toolchain_manifest_hash: manifest_hash,
        }))
    }
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
            if size > D32_MAX_FILE_BYTES as u64 {
                return Err("D32 workspace snapshot file exceeded its bound".to_string());
            }
            limits.file(size)?;
            let bytes = prepared
                .read_existing_file_raw_bounded(D32_MAX_FILE_BYTES)
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
    fs::copy(source, destination)
        .map_err(|_| "D32 executable projection copy failed".to_string())?;
    Ok(())
}

fn copy_regular_file_without_reparse_with_limits(
    source: &std::path::Path,
    destination: &std::path::Path,
    limits: &mut CopyLimits,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| "D32 toolchain metadata read failed".to_string())?;
    if is_reparse(&metadata) || !metadata.is_file() || metadata.len() > D32_MAX_FILE_BYTES as u64 {
        return Err("D32 toolchain projection source was not a bounded regular file".to_string());
    }
    limits.file(metadata.len())?;
    fs::copy(source, destination)
        .map_err(|_| "D32 toolchain projection copy failed".to_string())?;
    Ok(())
}

fn toolchain_manifest_hash(root: &std::path::Path) -> Result<String, String> {
    let mut entries = Vec::new();
    collect_manifest_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded = serde_json::to_vec(&entries)
        .map_err(|_| "D32 toolchain manifest serialization failed".to_string())?;
    Ok(crate::sha256_hex(&encoded))
}

fn collect_manifest_entries(
    root: &std::path::Path,
    current: &std::path::Path,
    entries: &mut Vec<(String, String)>,
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
            collect_manifest_entries(root, &path, entries)?;
        } else if metadata.is_file() {
            let mut file = File::open(&path)
                .map_err(|_| "D32 toolchain manifest file open failed".to_string())?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|_| "D32 toolchain manifest file read failed".to_string())?;
            entries.push((
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                crate::sha256_hex(&bytes),
            ));
        }
    }
    Ok(())
}

type CargoConfirmationReceiver = tokio::sync::mpsc::Receiver<H7PendingProcessAction>;

struct CargoInner {
    broker: Arc<H7ProcessBroker>,
    catalog: Arc<H7ExecutableCatalog>,
    context: VitaExecutionContext,
    workspace_root: TrustedWorkspaceRoot,
    sandbox: Arc<H7SandboxProfile>,
    projection: Arc<D32ExecutionProjection>,
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
    ) -> Self {
        let (confirmation, receiver) =
            H7PendingConfirmationBridge::new_with_timeout(std::time::Duration::from_secs(30));
        let attempted = (|| {
            let projection = D32ExecutionProjection::prepare(
                app_data_root,
                &workspace_root,
                cargo_path,
                trusted_toolchain_root,
                expected_toolchain_manifest_hash.as_deref(),
            )?;
            let catalog = Arc::new(H7ExecutableCatalog::cargo_check_projected(
                projection.cargo_path.clone(),
                projection.source_root.clone(),
                projection.root.clone(),
                projection.rustc_path.clone(),
                projection.rustdoc_path.clone(),
            )?);
            let sandbox = H7SandboxProfile::new()?;
            sandbox.grant_execution_root(&projection.root)?;
            let authority = Arc::new(VitaGitStatusAuthorityAdapter::new(authority));
            let broker = H7ProcessBroker::new(
                context.clone(),
                Arc::clone(&catalog),
                authority,
                Arc::clone(&confirmation),
            );
            Ok::<_, String>(Arc::new(CargoInner {
                broker,
                catalog,
                context,
                workspace_root,
                sandbox,
                projection,
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
            inner.broker.cancel();
        }
        self.confirmation.cancel_pending();
    }

    pub fn begin_turn(&self) {
        if let Some(inner) = &self.inner {
            inner.broker.begin_turn();
        }
    }

    pub fn cancel_turn(&self) {
        if let Some(inner) = &self.inner {
            inner.broker.cancel_turn();
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
                    let request = H7ProcessRequest::synthetic_fixed(
                        &call_id,
                        &turn_id,
                        D32_CARGO_PROGRAM_ID,
                        &["check", "--locked"],
                    );
                    match inner.catalog.prepare_fixed_workspace_action(
                        inner.context.clone(),
                        request,
                        D32_CARGO_CAPABILITY_ID,
                        D32_CARGO_PROFILE_ID,
                        inner.workspace_root.clone(),
                        Arc::clone(&inner.sandbox),
                    ) {
                        Ok(action) => inner.broker.execute(action).await.cargo_value(),
                        Err(_) => denied_value(),
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
}
