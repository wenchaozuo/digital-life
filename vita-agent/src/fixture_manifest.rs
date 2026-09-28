//! Strict, test-only validation for the D32/D29 prebuilt fixture manifest.
//!
//! The fixture binaries are intentionally existing-only inputs to the tests.
//! This module keeps the test helpers from silently falling back to ambient
//! target directories, timestamps, or nested Cargo builds.  The PowerShell
//! prebuild script is the producer; this is the consumer-side revalidation
//! immediately before a fixture is spawned.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const D32_FIXTURE_MANIFEST_ENV: &str = "D32_FIXTURE_MANIFEST_PATH";
pub(crate) const D32_FIXTURE_SCHEMA_VERSION: u32 = 3;
const D32_EXPECTED_CANDIDATE_SHA_ENV: &str = "D32_EXPECTED_CANDIDATE_SHA";
const D32_FIXTURE_PROCESS_TREE_TIMEOUT_ACTION: &str =
    "native Job Object kill-on-close, then verify every captured identity and relevant descendant";

const FIXTURE_NAMES: [&str; 5] = [
    "d29h1-authority-fixture",
    "d29h7-authority-fixture",
    "d29h7-process-fixture",
    "d29h7-git-helper-fixture",
    "d32a-sandbox-fixture",
];

#[derive(Debug, Clone, Copy)]
struct FixtureSpec {
    name: &'static str,
    project: &'static str,
    manifest: &'static str,
    binary: &'static str,
    artifact: &'static str,
    features: &'static [&'static str],
}

const FIXTURE_SPECS: [FixtureSpec; 5] = [
    FixtureSpec {
        name: "d29h1-authority-fixture",
        project: "src-tauri",
        manifest: "src-tauri/Cargo.toml",
        binary: "d29h1-authority-fixture",
        artifact: "src-tauri/target/debug/d29h1-authority-fixture.exe",
        features: &["d29-h1-host-fixture"],
    },
    FixtureSpec {
        name: "d29h7-authority-fixture",
        project: "src-tauri",
        manifest: "src-tauri/Cargo.toml",
        binary: "d29h7-authority-fixture",
        artifact: "src-tauri/target/debug/d29h7-authority-fixture.exe",
        features: &["d29-h7-host-fixture"],
    },
    FixtureSpec {
        name: "d29h7-process-fixture",
        project: "vita-agent",
        manifest: "vita-agent/Cargo.toml",
        binary: "d29h7-process-fixture",
        artifact: "vita-agent/target/debug/d29h7-process-fixture.exe",
        features: &[],
    },
    FixtureSpec {
        name: "d29h7-git-helper-fixture",
        project: "vita-agent",
        manifest: "vita-agent/Cargo.toml",
        binary: "d29h7-git-helper-fixture",
        artifact: "vita-agent/target/debug/d29h7-git-helper-fixture.exe",
        features: &["d29-h7-test-helper"],
    },
    FixtureSpec {
        name: "d32a-sandbox-fixture",
        project: "vita-agent",
        manifest: "vita-agent/Cargo.toml",
        binary: "d32a-sandbox-fixture",
        artifact: "vita-agent/target/debug/d32a-sandbox-fixture.exe",
        features: &["d32-a-test-helper"],
    },
];

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema_version: u32,
    candidate_sha: String,
    source_repo: String,
    generated_at_utc: String,
    started_at_utc: String,
    elapsed_ms: f64,
    working_tree_status: String,
    build_policy: BuildPolicy,
    environment: BuildEnvironment,
    process_tree_check: String,
    process_tree_error: Option<String>,
    fixtures: Vec<FixtureRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildPolicy {
    timeout_seconds: u64,
    cargo_build_jobs: u64,
    nested_builds: bool,
    process_tree_timeout_action: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildEnvironment {
    original_userprofile: String,
    codex_home: String,
    userprofile: String,
    cargo_home: String,
    rustup_home: String,
    rustup_toolchain: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecord {
    phase: u32,
    name: String,
    project: String,
    binary: String,
    manifest_path: String,
    features: Vec<String>,
    command: String,
    status: String,
    exit_code: Option<i32>,
    pid: Option<u32>,
    descendant_pids: Vec<u32>,
    root_identity: Option<ProcessIdentityDocument>,
    descendant_identities: Vec<ProcessIdentityDocument>,
    residual_descendant_identities: Vec<ProcessIdentityDocument>,
    reap: Option<ReapDocument>,
    elapsed_ms: Option<f64>,
    phase_log: String,
    stdout_log: String,
    stderr_log: String,
    error: Option<String>,
    artifact: Option<ArtifactRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRecord {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentityDocument {
    process_id: u32,
    parent_process_id: Option<u32>,
    name: Option<String>,
    creation_date: Option<String>,
    command_line: Option<String>,
    observed_at_utc: String,
    identity_verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCleanupDocument {
    job_terminate_call_succeeded: bool,
    job_terminate_last_error: i32,
    process_was_already_signaled: bool,
    process_wait_signaled: bool,
    job_active_process_count_verified: bool,
    job_active_process_count: u32,
    job_active_process_count_last_error: i32,
    job_close_succeeded: bool,
    cleanup_succeeded: bool,
    already_closed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ReapDocument {
    process_ids: Vec<u32>,
    verified_at_utc: String,
    residual_identities: Vec<ProcessIdentityDocument>,
    native_cleanup: Option<NativeCleanupDocument>,
    kill_output: Vec<String>,
}

/// Serde normally treats a missing `Option<T>` field as `None`, which would
/// make a producer omission indistinguishable from an explicit JSON `null`.
/// Fixture v3 requires the field itself to be present while preserving the
/// existing nullable value semantics.  The wire helpers below use this
/// presence-aware value for every nullable fixture field, then convert back to
/// the stable in-memory `Option<T>` representation.
#[derive(Debug)]
struct RequiredNullable<T> {
    present: bool,
    value: Option<T>,
}

impl<T> Default for RequiredNullable<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            present: true,
            value: Option::<T>::deserialize(deserializer)?,
        })
    }
}

impl<T> RequiredNullable<T> {
    fn into_option<E>(self, field: &'static str) -> Result<Option<T>, E>
    where
        E: serde::de::Error,
    {
        if self.present {
            Ok(self.value)
        } else {
            Err(E::custom(format!(
                "missing required nullable field `{field}`"
            )))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifestWire {
    schema_version: u32,
    candidate_sha: String,
    source_repo: String,
    generated_at_utc: String,
    started_at_utc: String,
    elapsed_ms: f64,
    working_tree_status: String,
    build_policy: BuildPolicy,
    environment: BuildEnvironment,
    process_tree_check: String,
    #[serde(default)]
    process_tree_error: RequiredNullable<String>,
    fixtures: Vec<FixtureRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildEnvironmentWire {
    original_userprofile: String,
    codex_home: String,
    userprofile: String,
    cargo_home: String,
    rustup_home: String,
    #[serde(default)]
    rustup_toolchain: RequiredNullable<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecordWire {
    phase: u32,
    name: String,
    project: String,
    binary: String,
    manifest_path: String,
    features: Vec<String>,
    command: String,
    status: String,
    #[serde(default)]
    exit_code: RequiredNullable<i32>,
    #[serde(default)]
    pid: RequiredNullable<u32>,
    descendant_pids: Vec<u32>,
    #[serde(default)]
    root_identity: RequiredNullable<ProcessIdentityDocument>,
    descendant_identities: Vec<ProcessIdentityDocument>,
    residual_descendant_identities: Vec<ProcessIdentityDocument>,
    #[serde(default)]
    reap: RequiredNullable<ReapDocument>,
    #[serde(default)]
    elapsed_ms: RequiredNullable<f64>,
    phase_log: String,
    stdout_log: String,
    stderr_log: String,
    #[serde(default)]
    error: RequiredNullable<String>,
    #[serde(default)]
    artifact: RequiredNullable<ArtifactRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentityWire {
    process_id: u32,
    #[serde(default)]
    parent_process_id: RequiredNullable<u32>,
    #[serde(default)]
    name: RequiredNullable<String>,
    #[serde(default)]
    creation_date: RequiredNullable<String>,
    #[serde(default)]
    command_line: RequiredNullable<String>,
    observed_at_utc: String,
    identity_verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReapDocumentWire {
    process_ids: Vec<u32>,
    verified_at_utc: String,
    residual_identities: Vec<ProcessIdentityDocument>,
    #[serde(default)]
    native_cleanup: RequiredNullable<NativeCleanupDocument>,
    kill_output: Vec<String>,
}

impl<'de> Deserialize<'de> for FixtureManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FixtureManifestWire::deserialize(deserializer)?;
        Ok(Self {
            schema_version: wire.schema_version,
            candidate_sha: wire.candidate_sha,
            source_repo: wire.source_repo,
            generated_at_utc: wire.generated_at_utc,
            started_at_utc: wire.started_at_utc,
            elapsed_ms: wire.elapsed_ms,
            working_tree_status: wire.working_tree_status,
            build_policy: wire.build_policy,
            environment: wire.environment,
            process_tree_check: wire.process_tree_check,
            process_tree_error: wire.process_tree_error.into_option("process_tree_error")?,
            fixtures: wire.fixtures,
        })
    }
}

impl<'de> Deserialize<'de> for BuildEnvironment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = BuildEnvironmentWire::deserialize(deserializer)?;
        Ok(Self {
            original_userprofile: wire.original_userprofile,
            codex_home: wire.codex_home,
            userprofile: wire.userprofile,
            cargo_home: wire.cargo_home,
            rustup_home: wire.rustup_home,
            rustup_toolchain: wire
                .rustup_toolchain
                .into_option("environment.rustup_toolchain")?,
        })
    }
}

impl<'de> Deserialize<'de> for FixtureRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FixtureRecordWire::deserialize(deserializer)?;
        Ok(Self {
            phase: wire.phase,
            name: wire.name,
            project: wire.project,
            binary: wire.binary,
            manifest_path: wire.manifest_path,
            features: wire.features,
            command: wire.command,
            status: wire.status,
            exit_code: wire.exit_code.into_option("fixture.exit_code")?,
            pid: wire.pid.into_option("fixture.pid")?,
            descendant_pids: wire.descendant_pids,
            root_identity: wire.root_identity.into_option("fixture.root_identity")?,
            descendant_identities: wire.descendant_identities,
            residual_descendant_identities: wire.residual_descendant_identities,
            reap: wire.reap.into_option("fixture.reap")?,
            elapsed_ms: wire.elapsed_ms.into_option("fixture.elapsed_ms")?,
            phase_log: wire.phase_log,
            stdout_log: wire.stdout_log,
            stderr_log: wire.stderr_log,
            error: wire.error.into_option("fixture.error")?,
            artifact: wire.artifact.into_option("fixture.artifact")?,
        })
    }
}

impl<'de> Deserialize<'de> for ProcessIdentityDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ProcessIdentityWire::deserialize(deserializer)?;
        Ok(Self {
            process_id: wire.process_id,
            parent_process_id: wire
                .parent_process_id
                .into_option("process_identity.parent_process_id")?,
            name: wire.name.into_option("process_identity.name")?,
            creation_date: wire
                .creation_date
                .into_option("process_identity.creation_date")?,
            command_line: wire
                .command_line
                .into_option("process_identity.command_line")?,
            observed_at_utc: wire.observed_at_utc,
            identity_verified: wire.identity_verified,
        })
    }
}

impl<'de> Deserialize<'de> for ReapDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReapDocumentWire::deserialize(deserializer)?;
        Ok(Self {
            process_ids: wire.process_ids,
            verified_at_utc: wire.verified_at_utc,
            residual_identities: wire.residual_identities,
            native_cleanup: wire.native_cleanup.into_option("reap.native_cleanup")?,
            kill_output: wire.kill_output,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
    length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileDigest {
    identity: FileIdentity,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct PinnedExecutable {
    path: PathBuf,
    identity: FileIdentity,
    sha256: String,
    locked_file: File,
}

#[derive(Debug)]
struct LockedGitMetadataFile {
    path: PathBuf,
    file: File,
    digest: FileDigest,
}

#[derive(Debug)]
struct LockedGitMetadata {
    index: LockedGitMetadataFile,
    info_exclude: LockedGitMetadataFile,
}

fn invalid(message: impl Into<String>) -> String {
    format!("FIXTURE_MANIFEST_INVALID: {}", message.into())
}

#[cfg(test)]
pub(crate) fn clear_inherited_git_environment(command: &mut Command) {
    command.env_clear();
}

/// Create a real Windows mount-point junction without starting a command
/// processor. The target is canonicalized before the reparse record is built,
/// and the link is a newly-created directory opened with
/// FILE_FLAG_OPEN_REPARSE_POINT so the handle refers to the link itself.
#[cfg(windows)]
pub(crate) fn create_test_junction(link: &Path, target: &Path) -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;

    fn wide(path: &OsStr) -> Vec<u16> {
        path.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn mount_point_names(target: &Path) -> std::io::Result<(Vec<u16>, Vec<u16>)> {
        let canonical = std::fs::canonicalize(target)?;
        if !canonical.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "junction target is not a directory",
            ));
        }
        let printable = canonical.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "junction target path is not valid Unicode",
            )
        })?;
        let printable = printable.strip_prefix(r"\\?\").unwrap_or(printable);
        let substitute = if let Some(unc) = printable.strip_prefix(r"\\") {
            format!(r"\??\UNC\{unc}")
        } else {
            format!(r"\??\{printable}")
        };
        Ok((
            substitute.encode_utf16().collect(),
            printable.encode_utf16().collect(),
        ))
    }

    let (substitute, printable) = mount_point_names(target)?;
    let substitute_bytes = substitute.len().checked_mul(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "junction target path overflowed",
        )
    })?;
    let printable_bytes = printable.len().checked_mul(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "junction print path overflowed",
        )
    })?;
    let print_offset = substitute_bytes.checked_add(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "junction path offset overflowed",
        )
    })?;
    let path_bytes = substitute_bytes
        .checked_add(2)
        .and_then(|length| length.checked_add(printable_bytes))
        .and_then(|length| length.checked_add(2))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "junction path size overflowed",
            )
        })?;
    let data_length = 8usize.checked_add(path_bytes).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "junction record size overflowed",
        )
    })?;
    if substitute_bytes > u16::MAX as usize
        || printable_bytes > u16::MAX as usize
        || print_offset > u16::MAX as usize
        || data_length > u16::MAX as usize
        || data_length + 8 > MAXIMUM_REPARSE_DATA_BUFFER_SIZE
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "junction target path exceeds the native reparse-point bound",
        ));
    }

    let mut reparse = Vec::with_capacity(data_length + 8);
    reparse.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    reparse.extend_from_slice(&(data_length as u16).to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&(substitute_bytes as u16).to_le_bytes());
    reparse.extend_from_slice(&(print_offset as u16).to_le_bytes());
    reparse.extend_from_slice(&(printable_bytes as u16).to_le_bytes());
    for unit in substitute
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .chain(printable.iter().copied())
        .chain(std::iter::once(0))
    {
        reparse.extend_from_slice(&unit.to_le_bytes());
    }

    std::fs::create_dir(link)?;
    let link_wide = wide(link.as_os_str());
    let handle = unsafe {
        CreateFileW(
            link_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir(link);
        return Err(error);
    }

    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            reparse.as_ptr().cast(),
            reparse.len() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    let error = (result == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseHandle(handle);
    }
    if let Some(error) = error {
        let _ = std::fs::remove_dir(link);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn create_test_junction(_link: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native test junction creation is available only on Windows",
    ))
}

fn metadata_is_reparse(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn reject_reparse_components(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} path must be absolute")));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(invalid(format!(
            "{label} path must not contain dot or parent components"
        )));
    }
    for current in path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
    {
        let metadata = std::fs::symlink_metadata(current).map_err(|error| {
            invalid(format!(
                "{label} path component is unavailable at {}: {error}",
                current.display()
            ))
        })?;
        if metadata_is_reparse(&metadata) {
            return Err(invalid(format!(
                "{label} path contains a reparse component: {}",
                current.display()
            )));
        }
    }
    Ok(())
}

fn canonical(path: &Path, label: &str) -> Result<PathBuf, String> {
    reject_reparse_components(path, label)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| invalid(format!("{label} cannot be canonicalized: {error}")))?;
    reject_reparse_components(&canonical, label)?;
    Ok(canonical)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn path_is_strictly_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let path = path.to_string_lossy().replace('/', "\\");
        let root = root.to_string_lossy().replace('/', "\\");
        let root = root.trim_end_matches('\\');
        let has_root_prefix = path
            .get(..root.len())
            .map(|prefix| prefix.eq_ignore_ascii_case(root))
            .unwrap_or(false);
        return path.len() > root.len()
            && has_root_prefix
            && path.as_bytes().get(root.len()) == Some(&b'\\');
    }
    #[cfg(not(windows))]
    {
        path != root && path.starts_with(root)
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(invalid(format!("{label} is not a 64-hex SHA-256")));
    }
    Ok(())
}

fn validate_candidate_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(invalid(format!(
            "{label} is not a 40-character lowercase Git SHA"
        )));
    }
    Ok(())
}

fn validate_expected_candidate_sha(actual: &str, expected: &str) -> Result<(), String> {
    validate_candidate_sha(actual, "current candidate SHA")?;
    validate_candidate_sha(expected, "expected candidate SHA")?;
    if actual != expected {
        return Err(invalid(
            "current candidate SHA does not match the independent caller pin",
        ));
    }
    Ok(())
}

fn validate_clean_git_status(status: &[u8]) -> Result<(), String> {
    if !status.is_empty() {
        return Err(invalid("current working tree is not clean"));
    }
    Ok(())
}

fn open_pinned_git_lock(path: &Path) -> Result<File, String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::OpenOptions::new()
            .read(true)
            // Win32 has no FILE_SHARE_EXECUTE bit. Sharing read only permits
            // CreateProcess to map the image while denying write/delete opens.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| {
                invalid(format!(
                    "pinned executable or Git metadata cannot be locked: {error}"
                ))
            })
    }
    #[cfg(not(windows))]
    {
        File::open(path).map_err(|error| {
            invalid(format!(
                "pinned executable or Git metadata cannot be opened: {error}"
            ))
        })
    }
}

fn pin_executable_from_inputs(
    path: &Path,
    expected_sha256: &str,
) -> Result<PinnedExecutable, String> {
    validate_sha256(expected_sha256, "pinned executable SHA-256")?;
    if !path.is_absolute() {
        return Err(invalid("pinned executable path must be absolute"));
    }
    let path = canonical(path, "pinned executable")?;
    let locked_file = open_pinned_git_lock(&path)?;
    let locked_identity = file_identity(&locked_file)?;
    let digest = hash_artifact(&path)?;
    if digest.identity != locked_identity || digest.sha256 != expected_sha256 {
        return Err(invalid(
            "pinned executable does not match its locked identity and independent SHA-256",
        ));
    }
    Ok(PinnedExecutable {
        path,
        identity: digest.identity,
        sha256: digest.sha256,
        locked_file,
    })
}

fn validate_local_git_config(git_dir: &Path) -> Result<(), String> {
    let config_path = git_dir.join("config");
    reject_reparse_components(&config_path, "repository Git config")?;
    let config = std::fs::read_to_string(&config_path)
        .map_err(|error| invalid(format!("repository Git config cannot be read: {error}")))?;
    let mut section = String::new();
    for (line_number, raw_line) in config.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(invalid(format!(
                    "repository Git config has an invalid section at line {}",
                    line_number + 1
                )));
            }
            section = line[1..line.len() - 1]
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !matches!(
                section.as_str(),
                "core" | "remote" | "branch" | "extensions"
            ) {
                return Err(invalid(format!(
                    "repository Git config section is not allowed: {section}"
                )));
            }
            continue;
        }

        let key = line
            .split(|character: char| character == '=' || character.is_whitespace())
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let allowed = match section.as_str() {
            "core" => matches!(
                key.as_str(),
                "repositoryformatversion"
                    | "filemode"
                    | "bare"
                    | "logallrefupdates"
                    | "ignorecase"
                    | "precomposeunicode"
                    | "symlinks"
                    | "longpaths"
                    | "quotepath"
            ),
            "remote" => matches!(
                key.as_str(),
                "url" | "fetch" | "pushurl" | "tagopt" | "prune" | "mirror"
            ),
            "branch" => matches!(key.as_str(), "remote" | "merge"),
            "extensions" => {
                key == "objectformat"
                    && line
                        .split_once('=')
                        .map(|(_, value)| value.trim().eq_ignore_ascii_case("sha1"))
                        .unwrap_or(false)
            }
            _ => false,
        };
        if !allowed {
            return Err(invalid(format!(
                "repository Git config key is not allowed: {section}.{key}"
            )));
        }
    }

    let worktree_config = git_dir.join("config.worktree");
    match std::fs::symlink_metadata(&worktree_config) {
        Ok(_) => Err(invalid(
            "repository Git config.worktree indirection is not allowed",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(invalid(format!(
            "repository Git config.worktree could not be checked: {error}"
        ))),
    }
}

fn reject_optional_git_metadata_indirection(git_dir: &Path, name: &str) -> Result<(), String> {
    let path = git_dir.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Err(invalid(format!(
            "repository Git metadata indirection is not allowed: {name}"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(invalid(format!(
            "repository Git metadata indirection could not be checked: {name}: {error}"
        ))),
    }
}

fn reject_reparse_metadata_tree(path: &Path, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("{label} metadata is unavailable: {error}")))?;
    if metadata_is_reparse(&metadata) {
        return Err(invalid(format!(
            "{label} contains a reparse component: {}",
            path.display()
        )));
    }
    if metadata.is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|error| invalid(format!("{label} cannot be enumerated: {error}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| invalid(format!("{label} entry cannot be read: {error}")))?;
            reject_reparse_metadata_tree(&entry.path(), label)?;
        }
    } else if !metadata.is_file() {
        return Err(invalid(format!(
            "{label} contains a non-file metadata entry: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_git_info_exclude(git_dir: &Path) -> Result<(), String> {
    let info_dir = git_dir.join("info");
    reject_reparse_components(&info_dir, "repository Git info metadata")?;
    reject_reparse_metadata_tree(&info_dir, "repository Git info metadata")?;
    let entries = std::fs::read_dir(&info_dir).map_err(|error| {
        invalid(format!(
            "repository Git info metadata cannot be enumerated: {error}"
        ))
    })?;
    let mut saw_exclude = false;
    for entry in entries {
        let entry = entry.map_err(|error| {
            invalid(format!("repository Git info entry cannot be read: {error}"))
        })?;
        if entry.file_name() != "exclude" || saw_exclude {
            return Err(invalid(
                "repository .git/info may contain only the exact approved exclude file",
            ));
        }
        saw_exclude = true;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| {
            invalid(format!(
                "repository Git info/exclude metadata is unavailable: {error}"
            ))
        })?;
        if !metadata.is_file() || metadata_is_reparse(&metadata) {
            return Err(invalid(
                "repository .git/info/exclude must be a regular non-reparse file",
            ));
        }
    }
    if !saw_exclude {
        return Err(invalid("repository .git/info/exclude is missing"));
    }

    let exclude = std::fs::read_to_string(info_dir.join("exclude")).map_err(|error| {
        invalid(format!(
            "repository .git/info/exclude cannot be read as UTF-8: {error}"
        ))
    })?;
    let mut approved_count = 0_u32;
    for raw_line in exclude.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if line != "vita-agent/target/" {
            return Err(invalid(
                "repository .git/info/exclude contains a non-approved active pattern",
            ));
        }
        approved_count += 1;
    }
    if approved_count != 1 {
        return Err(invalid(
            "repository .git/info/exclude must contain exactly one active vita-agent/target/ rule",
        ));
    }

    let repo_root = git_dir
        .parent()
        .ok_or_else(|| invalid("repository Git metadata has no candidate root"))?;
    let repo_root = canonical(repo_root, "repository root")?;
    let vita_agent = canonical(
        &repo_root.join("vita-agent"),
        "repo-local vita-agent directory",
    )?;
    if !vita_agent.is_dir() || !path_is_strictly_within(&vita_agent, &repo_root) {
        return Err(invalid(
            "repo-local vita-agent directory is not a direct candidate child",
        ));
    }
    let target = vita_agent.join("target");
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse(&metadata) {
                return Err(invalid(
                    "repo-local vita-agent/target must be a regular non-reparse directory",
                ));
            }
            let target = canonical(&target, "repo-local vita-agent target")?;
            if !path_is_strictly_within(&target, &repo_root) {
                return Err(invalid("vita-agent target path escaped the candidate root"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(invalid(format!(
                "repo-local vita-agent target cannot be inspected: {error}"
            )))
        }
    }
    Ok(())
}

fn validate_index_flags(output: &[u8]) -> Result<(), String> {
    if output.is_empty() {
        return Ok(());
    }
    if output.last() != Some(&0) {
        return Err(invalid("Git index flag inventory is not NUL-terminated"));
    }
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 3 || record[0] != b'H' || record[1] != b' ' || record[2..].is_empty() {
            return Err(invalid(
                "Git index contains assume-unchanged, skip-worktree, unmerged, or malformed flags",
            ));
        }
    }
    Ok(())
}

fn digest_open_file(file: &mut File) -> Result<FileDigest, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| invalid(format!("locked Git metadata seek failed: {error}")))?;
    let before = file_identity(file)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| invalid(format!("locked Git metadata read failed: {error}")))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("locked Git metadata byte count overflowed"))?;
    }
    let after = file_identity(file)?;
    if before != after || after.length != bytes {
        return Err(invalid(
            "locked Git metadata identity or size changed while hashing",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| invalid(format!("locked Git metadata rewind failed: {error}")))?;
    Ok(FileDigest {
        identity: before,
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn open_locked_git_metadata_file(path: &Path) -> Result<LockedGitMetadataFile, String> {
    reject_reparse_components(path, "locked repository Git metadata")?;
    let mut file = open_pinned_git_lock(path)?;
    let digest = digest_open_file(&mut file)?;
    let path_digest = hash_artifact(path)?;
    if path_digest != digest {
        return Err(invalid(
            "locked Git metadata path identity or bytes changed during handle acquisition",
        ));
    }
    Ok(LockedGitMetadataFile {
        path: path.to_path_buf(),
        file,
        digest,
    })
}

fn verify_locked_git_metadata_file(locked: &mut LockedGitMetadataFile) -> Result<(), String> {
    reject_reparse_components(&locked.path, "locked repository Git metadata")?;
    let handle_digest = digest_open_file(&mut locked.file)?;
    let path_digest = hash_artifact(&locked.path)?;
    if handle_digest != locked.digest || path_digest != locked.digest {
        return Err(invalid(
            "locked Git metadata identity or contents changed across Git process creation",
        ));
    }
    Ok(())
}

fn open_locked_git_metadata(repo_root: &Path, git_dir: &Path) -> Result<LockedGitMetadata, String> {
    validate_repository_git_metadata(git_dir)?;
    let mut metadata = LockedGitMetadata {
        index: open_locked_git_metadata_file(&git_dir.join("index"))?,
        info_exclude: open_locked_git_metadata_file(&git_dir.join("info").join("exclude"))?,
    };
    validate_repository_git_metadata(git_dir)?;
    verify_locked_git_metadata_file(&mut metadata.index)?;
    verify_locked_git_metadata_file(&mut metadata.info_exclude)?;
    if canonical(repo_root, "repository root")? != git_dir.parent().unwrap_or(git_dir) {
        return Err(invalid(
            "repository root changed while locking Git metadata",
        ));
    }
    Ok(metadata)
}

fn verify_locked_git_metadata(metadata: &mut LockedGitMetadata) -> Result<(), String> {
    verify_locked_git_metadata_file(&mut metadata.index)?;
    verify_locked_git_metadata_file(&mut metadata.info_exclude)
}

fn validate_repository_git_metadata(git_dir: &Path) -> Result<(), String> {
    reject_reparse_components(git_dir, "repository Git metadata")?;
    if !git_dir.is_dir() {
        return Err(invalid(
            "repository must use a direct non-reparse .git directory",
        ));
    }
    for name in ["gitdir", "commondir", "config.worktree"] {
        reject_optional_git_metadata_indirection(git_dir, name)?;
    }
    for name in ["config", "HEAD", "index"] {
        reject_reparse_components(&git_dir.join(name), "repository Git metadata")?;
    }
    let packed_refs = git_dir.join("packed-refs");
    match std::fs::symlink_metadata(&packed_refs) {
        Ok(_) => reject_reparse_components(&packed_refs, "repository Git metadata")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(invalid(format!(
                "repository Git packed refs could not be checked: {error}"
            )));
        }
    }

    // Refs and the object-store fanout are Git-controlled path components.
    // Walk them rather than validating only their roots, so nested junctions
    // cannot redirect Git reads outside the candidate's own metadata tree.
    for name in ["refs", "objects"] {
        let path = git_dir.join(name);
        reject_reparse_components(&path, "repository Git metadata tree")?;
        reject_reparse_metadata_tree(&path, "repository Git metadata tree")?;
    }
    for name in [
        "objects/info/alternates",
        "objects/info/http-alternates",
        "info/grafts",
    ] {
        reject_optional_git_metadata_indirection(git_dir, name)?;
    }
    validate_git_info_exclude(git_dir)?;
    validate_local_git_config(git_dir)
}

#[cfg(windows)]
fn verify_spawned_process_image(
    process_id: u32,
    executable: &PinnedExecutable,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(invalid(
            "spawned pinned process identity could not be opened",
        ));
    }
    let result = (|| {
        let mut image = vec![0_u16; 32_768];
        let mut image_length = image.len() as u32;
        let image_ok = unsafe {
            QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut image_length)
        };
        if image_ok == 0 || image_length == 0 {
            return Err(invalid(
                "spawned pinned process image path could not be verified",
            ));
        }
        image.truncate(image_length as usize);
        let image_path = canonical(
            Path::new(&std::ffi::OsString::from_wide(&image)),
            "spawned pinned process image",
        )?;
        if !paths_equal(&image_path, &executable.path) {
            return Err(invalid(
                "spawned process image path does not match the pinned executable",
            ));
        }

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(invalid(
                "spawned pinned process creation identity could not be verified",
            ));
        }
        let creation_ticks =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if creation_ticks == 0 {
            return Err(invalid(
                "spawned pinned process has no stable creation identity",
            ));
        }

        let image_digest = hash_artifact(&image_path)?;
        if image_digest.identity != executable.identity || image_digest.sha256 != executable.sha256
        {
            return Err(invalid(
                "spawned process image identity does not match the locked pin",
            ));
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(process);
    }
    result
}

#[cfg(not(windows))]
fn verify_spawned_process_image(
    _process_id: u32,
    _executable: &PinnedExecutable,
) -> Result<(), String> {
    Err(invalid(
        "pinned process image verification is supported only on Windows",
    ))
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentity, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("artifact metadata could not be read: {error}")))?;
    if !metadata.is_file() || metadata_is_reparse(&metadata) {
        return Err(invalid("artifact handle is not a non-reparse regular file"));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if ok == 0 {
        return Err(invalid("artifact identity could not be read"));
    }
    Ok(FileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        length: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    })
}

#[cfg(not(windows))]
fn file_identity(file: &File) -> Result<FileIdentity, String> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("artifact metadata could not be read: {error}")))?;
    if !metadata.is_file() || metadata_is_reparse(&metadata) {
        return Err(invalid("artifact handle is not a non-reparse regular file"));
    }
    #[cfg(unix)]
    {
        Ok(FileIdentity {
            volume_serial: metadata.dev() as u32,
            file_index: metadata.ino(),
            length: metadata.len(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            volume_serial: 0,
            file_index: 0,
            length: metadata.len(),
        })
    }
}

fn hash_artifact(path: &Path) -> Result<FileDigest, String> {
    reject_reparse_components(path, "artifact")?;
    #[cfg(windows)]
    let mut file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| invalid(format!("artifact cannot be opened: {error}")))?
    };
    #[cfg(not(windows))]
    let mut file =
        File::open(path).map_err(|error| invalid(format!("artifact cannot be opened: {error}")))?;
    let before = file_identity(&file)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| invalid(format!("artifact read failed: {error}")))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("artifact byte count overflowed"))?;
    }
    let after = file_identity(&file)?;
    if before != after || after.length != bytes {
        return Err(invalid("artifact identity or size changed while hashing"));
    }
    drop(file);

    // Reopen after hashing to bind the pathname to the same native identity
    // immediately before the caller spawns it. Timestamps are not evidence.
    reject_reparse_components(path, "artifact")?;
    #[cfg(windows)]
    let rebound = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| invalid(format!("artifact disappeared after hashing: {error}")))?
    };
    #[cfg(not(windows))]
    let rebound = File::open(path)
        .map_err(|error| invalid(format!("artifact disappeared after hashing: {error}")))?;
    let rebound_identity = file_identity(&rebound)?;
    if rebound_identity != before {
        return Err(invalid("artifact identity changed after hashing"));
    }
    Ok(FileDigest {
        identity: before,
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn normalise_command(command: &str) -> Vec<String> {
    command
        .replace('/', "\\")
        .split_whitespace()
        .map(|token| token.trim_matches('"').to_string())
        .collect()
}

fn expected_command(repo_root: &Path, spec: FixtureSpec) -> String {
    let manifest = repo_root.join(spec.manifest);
    let mut command = format!(
        "cargo build --quiet --locked --manifest-path {} --bin {}",
        manifest.display(),
        spec.binary
    );
    if !spec.features.is_empty() {
        command.push_str(" --features ");
        command.push_str(&spec.features.join(" "));
    }
    command
}

fn expected_manifest_path(repo_root: &Path, spec: FixtureSpec) -> PathBuf {
    repo_root.join(spec.manifest)
}

fn expected_artifact_path(repo_root: &Path, spec: FixtureSpec) -> PathBuf {
    repo_root.join(spec.artifact)
}

fn find_spec(name: &str) -> Option<FixtureSpec> {
    FIXTURE_SPECS.iter().copied().find(|spec| spec.name == name)
}

fn validate_record_shape(
    record: &FixtureRecord,
    spec: FixtureSpec,
    repo_root: &Path,
) -> Result<(), String> {
    if record.name != spec.name
        || record.project != spec.project
        || record.binary != spec.binary
        || record.phase
            != FIXTURE_NAMES
                .iter()
                .position(|name| *name == spec.name)
                .expect("fixture spec is canonical") as u32
                + 1
    {
        return Err(invalid(format!(
            "fixture {} identity fields are not exact",
            spec.name
        )));
    }
    if record.features
        != spec
            .features
            .iter()
            .map(|feature| (*feature).to_string())
            .collect::<Vec<_>>()
    {
        return Err(invalid(format!(
            "fixture {} features are not exact",
            spec.name
        )));
    }
    if record.status != "succeeded" || record.exit_code != Some(0) {
        return Err(invalid(format!(
            "fixture {} is not a successful zero-exit build",
            spec.name
        )));
    }
    if record.pid.is_none()
        || !record.descendant_pids.is_empty()
        || record.root_identity.is_none()
        || record.elapsed_ms.is_none()
        || record.phase_log.is_empty()
        || record.stdout_log.is_empty()
        || record.stderr_log.is_empty()
        || record.error.is_some()
    {
        return Err(invalid(format!(
            "fixture {} build metadata is incomplete",
            spec.name
        )));
    }
    let declared_manifest = canonical(Path::new(&record.manifest_path), "fixture manifest path")?;
    let expected_manifest = canonical(
        &expected_manifest_path(repo_root, spec),
        "expected Cargo manifest",
    )?;
    if !paths_equal(&declared_manifest, &expected_manifest) {
        return Err(invalid(format!(
            "fixture {} manifest path is not exact",
            spec.name
        )));
    }
    let expected_command = normalise_command(&expected_command(repo_root, spec));
    if normalise_command(&record.command) != expected_command {
        return Err(invalid(format!(
            "fixture {} build command is not exact",
            spec.name
        )));
    }
    let artifact = record
        .artifact
        .as_ref()
        .ok_or_else(|| invalid(format!("fixture {} artifact record is missing", spec.name)))?;
    validate_sha256(
        &artifact.sha256,
        &format!("fixture {} artifact hash", spec.name),
    )?;
    let declared_artifact = canonical(Path::new(&artifact.path), "fixture artifact path")?;
    let expected_artifact = canonical(
        &expected_artifact_path(repo_root, spec),
        "expected fixture artifact",
    )?;
    let canonical_repo = canonical(repo_root, "repository root")?;
    if !path_is_strictly_within(&expected_artifact, &canonical_repo) {
        return Err(invalid(format!(
            "fixture {} artifact escapes the repository root",
            spec.name
        )));
    }
    if !paths_equal(&declared_artifact, &expected_artifact) {
        return Err(invalid(format!(
            "fixture {} artifact path is not exact",
            spec.name
        )));
    }
    let digest = hash_artifact(&declared_artifact)?;
    if digest.bytes != artifact.bytes || digest.sha256 != artifact.sha256.to_ascii_lowercase() {
        return Err(invalid(format!(
            "fixture {} artifact hash or size does not match",
            spec.name
        )));
    }
    if digest.identity.length != digest.bytes {
        return Err(invalid(format!(
            "fixture {} artifact identity size is not exact",
            spec.name
        )));
    }
    Ok(())
}

fn validate_build_policy(policy: &BuildPolicy) -> Result<(), String> {
    if policy.timeout_seconds == 0
        || policy.cargo_build_jobs == 0
        || policy.nested_builds
        || policy.process_tree_timeout_action != D32_FIXTURE_PROCESS_TREE_TIMEOUT_ACTION
    {
        return Err(invalid(
            "manifest build policy is not the bounded existing-only policy",
        ));
    }
    Ok(())
}

fn parse_manifest(path: &Path) -> Result<FixtureManifest, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| invalid(format!("fixture manifest cannot be read: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("fixture manifest schema is invalid: {error}")))
}

fn validate_manifest_common(
    manifest: &FixtureManifest,
    repo_root: &Path,
    expected_candidate_sha: &str,
) -> Result<(), String> {
    if manifest.schema_version != D32_FIXTURE_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version={} expected {}",
            manifest.schema_version, D32_FIXTURE_SCHEMA_VERSION
        )));
    }
    validate_candidate_sha(&manifest.candidate_sha, "candidate_sha")?;
    if manifest.candidate_sha != expected_candidate_sha {
        return Err(invalid(format!(
            "candidate_sha does not match independently pinned candidate {expected_candidate_sha}"
        )));
    }
    let source_repo = canonical(Path::new(&manifest.source_repo), "source_repo")?;
    let expected_repo = canonical(repo_root, "repository root")?;
    if !paths_equal(&source_repo, &expected_repo) {
        return Err(invalid(
            "source_repo does not match the current repository root",
        ));
    }
    if manifest.generated_at_utc.trim().is_empty()
        || manifest.started_at_utc.trim().is_empty()
        || !manifest.elapsed_ms.is_finite()
        || manifest.elapsed_ms < 0.0
        || !manifest.working_tree_status.is_empty()
    {
        return Err(invalid("manifest build provenance metadata is not exact"));
    }
    validate_build_policy(&manifest.build_policy)?;
    if manifest.process_tree_check != "succeeded" || manifest.process_tree_error.is_some() {
        return Err(invalid("global fixture process cleanup did not succeed"));
    }
    if manifest.environment.original_userprofile.trim().is_empty()
        || manifest.environment.codex_home.trim().is_empty()
        || manifest.environment.userprofile.trim().is_empty()
        || manifest.environment.cargo_home.trim().is_empty()
        || manifest.environment.rustup_home.trim().is_empty()
    {
        return Err(invalid("manifest build environment metadata is incomplete"));
    }
    if manifest.fixtures.len() != FIXTURE_SPECS.len() {
        return Err(invalid(format!(
            "expected exactly {} fixture records",
            FIXTURE_SPECS.len()
        )));
    }
    let names = manifest
        .fixtures
        .iter()
        .map(|record| record.name.as_str())
        .collect::<Vec<_>>();
    if names != FIXTURE_NAMES {
        return Err(invalid("fixture names/order are not the canonical five"));
    }
    Ok(())
}

/// Resolve and revalidate one existing fixture immediately before it is
/// spawned. All five manifest records are schema-checked; only the selected
/// image is reopened, rehashed, and identity-checked on this call.
pub(crate) fn existing_fixture(repo_root: &Path, name: &str) -> Result<PathBuf, String> {
    let expected_candidate_sha = std::env::var(D32_EXPECTED_CANDIDATE_SHA_ENV)
        .map_err(|_| invalid(format!("{D32_EXPECTED_CANDIDATE_SHA_ENV} is not set")))?;
    validate_candidate_sha(&expected_candidate_sha, "expected candidate SHA")?;
    let manifest_path = std::env::var_os(D32_FIXTURE_MANIFEST_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("{D32_FIXTURE_MANIFEST_ENV} is not set")))?;
    if !manifest_path.is_absolute() {
        return Err(invalid("fixture manifest path must be absolute"));
    }
    let manifest_path = canonical(&manifest_path, "fixture manifest")?;
    let manifest = parse_manifest(&manifest_path)?;
    validate_manifest_common(&manifest, repo_root, &expected_candidate_sha)?;
    let spec = find_spec(name).ok_or_else(|| invalid(format!("unknown fixture name {name}")))?;
    let record = manifest
        .fixtures
        .iter()
        .find(|record| record.name == name)
        .ok_or_else(|| invalid(format!("fixture record {name} is missing")))?;
    validate_record_shape(record, spec, repo_root)?;
    let artifact = record
        .artifact
        .as_ref()
        .ok_or_else(|| invalid(format!("fixture {name} artifact record is missing")))?;
    let path = PathBuf::from(&artifact.path);
    let digest = hash_artifact(&path)?;
    if digest.bytes != artifact.bytes || digest.sha256 != artifact.sha256.to_ascii_lowercase() {
        return Err(invalid(format!("fixture {name} changed before spawn")));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn process_identity_value(process_id: u32) -> Value {
        json!({
            "process_id": process_id,
            "parent_process_id": null,
            "name": "cargo.exe",
            "creation_date": "2026-09-22T00:00:00.0000000Z",
            "command_line": "cargo build",
            "observed_at_utc": "2026-09-22T00:00:00.0000000Z",
            "identity_verified": true
        })
    }

    fn producer_manifest_value() -> Value {
        let fixtures = FIXTURE_SPECS
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let process_id = 1000 + index as u32;
                json!({
                    "phase": index + 1,
                    "name": spec.name,
                    "project": spec.project,
                    "binary": spec.binary,
                    "manifest_path": format!(r"C:\repo\{}", spec.manifest),
                    "features": spec.features,
                    "command": expected_command(Path::new(r"C:\repo"), *spec),
                    "status": "succeeded",
                    "exit_code": 0,
                    "pid": process_id,
                    "descendant_pids": [],
                    "root_identity": process_identity_value(process_id),
                    "descendant_identities": [process_identity_value(process_id + 1)],
                    "residual_descendant_identities": [],
                    "reap": {
                        "process_ids": [process_id, process_id + 1],
                        "verified_at_utc": "2026-09-22T00:00:00.0000000Z",
                        "residual_identities": [],
                        "native_cleanup": {
                            "job_terminate_call_succeeded": true,
                            "job_terminate_last_error": 0,
                            "process_was_already_signaled": false,
                            "process_wait_signaled": true,
                            "job_active_process_count_verified": true,
                            "job_active_process_count": 0,
                            "job_active_process_count_last_error": 0,
                            "job_close_succeeded": true,
                            "cleanup_succeeded": true,
                            "already_closed": false,
                            "detail": ""
                        },
                        "kill_output": []
                    },
                    "elapsed_ms": 1.0,
                    "phase_log": format!(r"C:\logs\{}", spec.name),
                    "stdout_log": format!(r"C:\logs\{}.stdout.log", spec.name),
                    "stderr_log": format!(r"C:\logs\{}.stderr.log", spec.name),
                    "error": null,
                    "artifact": {
                        "path": format!(r"C:\repo\{}", spec.artifact),
                        "bytes": 1,
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema_version": D32_FIXTURE_SCHEMA_VERSION,
            "candidate_sha": "0123456789abcdef0123456789abcdef01234567",
            "source_repo": r"C:\repo",
            "generated_at_utc": "2026-09-22T00:00:00.0000000Z",
            "started_at_utc": "2026-09-22T00:00:00.0000000Z",
            "elapsed_ms": 1.0,
            "working_tree_status": "",
            "build_policy": {
                "timeout_seconds": 1,
                "cargo_build_jobs": 1,
                "nested_builds": false,
                "process_tree_timeout_action": D32_FIXTURE_PROCESS_TREE_TIMEOUT_ACTION
            },
            "environment": {
                "original_userprofile": r"C:\user",
                "codex_home": r"C:\codex",
                "userprofile": r"C:\profile",
                "cargo_home": r"C:\cargo",
                "rustup_home": r"C:\rustup",
                "rustup_toolchain": null
            },
            "process_tree_check": "succeeded",
            "process_tree_error": null,
            "fixtures": fixtures
        })
    }

    #[derive(Clone, Copy)]
    enum RequiredNullableField {
        Manifest(&'static str),
        Environment(&'static str),
        Fixture(&'static str),
        ProcessIdentity(&'static str),
        Reap(&'static str),
    }

    fn set_object_field(object: &mut Value, name: &str, value: Option<Value>) {
        let object = object
            .as_object_mut()
            .expect("fixture test path must identify an object");
        match value {
            Some(value) => {
                object.insert(name.to_string(), value);
            }
            None => {
                assert!(
                    object.remove(name).is_some(),
                    "fixture test field must exist before removal: {name}"
                );
            }
        }
    }

    fn set_required_nullable_field(
        manifest: &mut Value,
        field: RequiredNullableField,
        value: Option<Value>,
    ) {
        match field {
            RequiredNullableField::Manifest(name) => set_object_field(manifest, name, value),
            RequiredNullableField::Environment(name) => {
                set_object_field(&mut manifest["environment"], name, value)
            }
            RequiredNullableField::Fixture(name) => {
                set_object_field(&mut manifest["fixtures"][0], name, value)
            }
            RequiredNullableField::ProcessIdentity(name) => {
                set_object_field(&mut manifest["fixtures"][0]["root_identity"], name, value)
            }
            RequiredNullableField::Reap(name) => {
                set_object_field(&mut manifest["fixtures"][0]["reap"], name, value)
            }
        }
    }

    fn assert_required_nullable_field(field: RequiredNullableField, label: &str) {
        let mut missing = producer_manifest_value();
        set_required_nullable_field(&mut missing, field, None);
        assert!(
            serde_json::from_value::<FixtureManifest>(missing).is_err(),
            "{label}: missing field must be rejected"
        );

        let mut explicit_null = producer_manifest_value();
        set_required_nullable_field(&mut explicit_null, field, Some(Value::Null));
        assert!(
            serde_json::from_value::<FixtureManifest>(explicit_null).is_ok(),
            "{label}: explicit null must be accepted"
        );
    }

    #[test]
    fn canonical_fixture_schema_has_five_exact_names() {
        assert_eq!(FIXTURE_NAMES.len(), 5);
        assert_eq!(FIXTURE_SPECS.len(), FIXTURE_NAMES.len());
        for (index, spec) in FIXTURE_SPECS.iter().enumerate() {
            assert_eq!(spec.name, FIXTURE_NAMES[index]);
            assert!(!spec.project.is_empty());
            assert!(!spec.manifest.is_empty());
            assert!(!spec.binary.is_empty());
            assert!(!spec.artifact.is_empty());
        }
    }

    #[test]
    fn command_validation_keeps_features_in_build_metadata() {
        let root = Path::new(r"C:\repo");
        let command = expected_command(root, FIXTURE_SPECS[0]);
        assert_eq!(normalise_command(&command)[0], "cargo");
        assert!(normalise_command(&command)
            .windows(2)
            .any(|pair| pair == ["--features", "d29-h1-host-fixture"]));
        assert_ne!(
            normalise_command(&command),
            normalise_command(&command.replace("d29-h1-host-fixture", "wrong-feature"))
        );
    }

    #[test]
    fn candidate_sha_requires_exact_lowercase_git_shape() {
        let valid = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(valid.len(), 40);
        assert!(validate_candidate_sha(valid, "candidate_sha").is_ok());
        assert!(validate_candidate_sha(&valid[..39], "candidate_sha").is_err());
        assert!(validate_candidate_sha(
            "0123456789abcdef0123456789abcdef012345678",
            "candidate_sha"
        )
        .is_err());
        assert!(validate_candidate_sha(
            "0123456789ABCDEF0123456789abcdef01234567",
            "candidate_sha"
        )
        .is_err());
        assert!(validate_candidate_sha(
            "0123456789abcdef0123456789abcdef0123456g",
            "candidate_sha"
        )
        .is_err());
    }

    #[test]
    fn repository_git_config_rejects_execution_and_indirection() {
        let root = tempfile::tempdir().expect("temporary Git metadata root");
        let git_dir = root.path().join(".git");
        std::fs::create_dir(&git_dir).expect("temporary Git metadata directory");
        let config = git_dir.join("config");
        std::fs::write(
            &config,
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n\tignorecase = true\n[remote \"origin\"]\n\turl = https://example.invalid/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
        )
        .expect("write ordinary clone config");
        assert!(validate_local_git_config(&git_dir).is_ok());

        for hostile in [
            "[filter \"evil\"]\n\tclean = write-owned-marker\n",
            "[include]\n\tpath = outside.gitconfig\n",
            "[includeIf \"gitdir:/\"]\n\tpath = outside.gitconfig\n",
            "[core]\n\tfsmonitor = write-owned-marker\n",
            "[extensions]\n\tworktreeConfig = true\n",
        ] {
            std::fs::write(&config, hostile).expect("write hostile clone config");
            assert!(
                validate_local_git_config(&git_dir).is_err(),
                "hostile Git config must be rejected: {hostile}"
            );
        }
    }

    fn create_minimal_direct_git_metadata(git_dir: &Path) {
        std::fs::create_dir_all(git_dir.join("objects/info")).expect("Git objects info");
        std::fs::create_dir_all(git_dir.join("objects/pack")).expect("Git pack directory");
        std::fs::create_dir_all(git_dir.join("refs/heads")).expect("Git refs directory");
        std::fs::create_dir_all(git_dir.join("info")).expect("Git info directory");
        let repo_root = git_dir.parent().expect("fake Git repository root");
        std::fs::create_dir_all(repo_root.join("vita-agent/target"))
            .expect("approved ignored target");
        std::fs::write(
            git_dir.join("info/exclude"),
            "# test metadata\n\nvita-agent/target/\n",
        )
        .expect("Git info exclude");
        std::fs::write(
            git_dir.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n",
        )
        .expect("Git config");
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("Git HEAD");
        std::fs::write(git_dir.join("index"), b"").expect("Git index");
    }

    #[test]
    fn git_metadata_indirections_and_nested_reparse_paths_are_rejected() {
        let root = tempfile::tempdir().expect("temporary Git metadata root");
        let git_dir = root.path().join(".git");
        create_minimal_direct_git_metadata(&git_dir);
        assert!(validate_repository_git_metadata(&git_dir).is_ok());

        for relative in [
            "gitdir",
            "commondir",
            "config.worktree",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "info/grafts",
        ] {
            let path = git_dir.join(relative);
            std::fs::write(&path, "outside-metadata\n").expect("write forbidden Git metadata");
            assert!(
                validate_repository_git_metadata(&git_dir).is_err(),
                "Git metadata indirection must be rejected: {relative}"
            );
            std::fs::remove_file(path).expect("remove forbidden Git metadata");
        }

        let hidden_untracked = git_dir
            .parent()
            .expect("fake Git repository root")
            .join("hidden-source.rs");
        std::fs::write(&hidden_untracked, "untracked source\n").expect("hidden untracked source");
        std::fs::write(
            git_dir.join("info/exclude"),
            "# comments and blanks are allowed\n\nvita-agent/target/\nhidden-source.rs\n",
        )
        .expect("inject forbidden hidden-untracked rule");
        assert!(
            validate_repository_git_metadata(&git_dir).is_err(),
            "an info/exclude rule that hides an untracked source must be rejected"
        );
        std::fs::remove_file(hidden_untracked).expect("remove hidden untracked source");
        std::fs::write(
            git_dir.join("info/exclude"),
            "# comments and blanks are allowed\n\nvita-agent/target/\n",
        )
        .expect("restore exact approved ignore policy");

        std::fs::write(
            git_dir.join("info/exclude"),
            "# comments\nvita-agent/target/\n!hidden-source.rs\n",
        )
        .expect("inject forbidden negated rule");
        assert!(validate_repository_git_metadata(&git_dir).is_err());
        std::fs::write(git_dir.join("info/exclude"), "vita-agent/target/\n")
            .expect("restore exact approved ignore policy");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let outside = root.path().join("outside-refs");
            std::fs::create_dir(&outside).expect("outside refs target");
            let heads = git_dir.join("refs/heads");
            std::fs::remove_dir(&heads).expect("remove direct refs directory");
            symlink(&outside, &heads).expect("create nested refs symlink");
            assert!(
                validate_repository_git_metadata(&git_dir).is_err(),
                "nested refs symlink must be rejected"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn nested_git_metadata_junction_is_rejected() {
        let root = tempfile::tempdir().expect("temporary Git metadata root");
        let git_dir = root.path().join(".git");
        create_minimal_direct_git_metadata(&git_dir);
        let outside = root.path().join("outside-refs");
        std::fs::create_dir(&outside).expect("outside refs target");
        let heads = git_dir.join("refs/heads");
        std::fs::remove_dir(&heads).expect("remove direct refs directory");

        create_test_junction(&heads, &outside).expect("create nested Git metadata junction");
        assert!(
            validate_repository_git_metadata(&git_dir).is_err(),
            "nested Git metadata junction must be rejected"
        );
    }

    #[test]
    fn repo_local_vita_agent_target_indirection_is_rejected() {
        let root = tempfile::tempdir().expect("temporary candidate root");
        let git_dir = root.path().join(".git");
        create_minimal_direct_git_metadata(&git_dir);
        let target = root.path().join("vita-agent/target");
        std::fs::remove_dir_all(&target).expect("remove direct repo-local target");
        let outside = root.path().join("outside-target");
        std::fs::create_dir(&outside).expect("outside target");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, &target).expect("create target symlink");
        }
        #[cfg(windows)]
        {
            create_test_junction(&target, &outside).expect("create repo-local target junction");
        }

        assert!(
            validate_repository_git_metadata(&git_dir).is_err(),
            "the only allowlisted exclude target cannot redirect outside the candidate root"
        );
    }

    #[cfg(windows)]
    #[test]
    fn nested_git_info_junction_is_rejected() {
        let root = tempfile::tempdir().expect("temporary Git metadata root");
        let git_dir = root.path().join(".git");
        create_minimal_direct_git_metadata(&git_dir);
        let outside = root.path().join("outside-info");
        std::fs::create_dir(&outside).expect("outside info target");
        let nested = git_dir.join("info/external");
        create_test_junction(&nested, &outside).expect("create nested Git info junction");
        assert!(
            validate_repository_git_metadata(&git_dir).is_err(),
            "nested Git info junction must be rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn git_metadata_handles_remain_locked_across_process_creation() {
        use std::process::Stdio;

        let root = tempfile::tempdir().expect("temporary retained Git metadata root");
        let git_dir = root.path().join(".git");
        create_minimal_direct_git_metadata(&git_dir);
        let repo_root = root.path().to_path_buf();
        let mut metadata = open_locked_git_metadata(&repo_root, &git_dir)
            .expect("index and info/exclude should be retained under read-only locks");

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7 process-fixture repository root");
        let process_fixture = existing_fixture(repo_root, "d29h7-process-fixture")
            .unwrap_or_else(|error| panic!("{error}"));
        let child = Command::new(process_fixture)
            .args(["fast-exit-both"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("create bounded process while metadata handles are retained");
        let output = child
            .wait_with_output()
            .expect("wait for process-creation probe");
        assert!(
            output.status.success(),
            "process-creation probe must exit successfully"
        );

        for path in [git_dir.join("index"), git_dir.join("info/exclude")] {
            let write_open = std::fs::OpenOptions::new().write(true).open(&path);
            assert!(
                write_open.is_err(),
                "retained Git metadata handle must deny write opens after process creation: {}",
                path.display()
            );
            let remove = std::fs::remove_file(&path);
            assert!(
                remove.is_err(),
                "retained Git metadata handle must deny pathname replacement after process creation: {}",
                path.display()
            );
        }
        verify_locked_git_metadata(&mut metadata)
            .expect("metadata identity and bytes remain bound across process creation");
    }

    #[test]
    fn candidate_sha_pin_and_dirty_status_reject_negative_evidence() {
        let expected = "0123456789abcdef0123456789abcdef01234567";
        let changed = "1123456789abcdef0123456789abcdef01234567";
        assert!(validate_expected_candidate_sha(expected, expected).is_ok());
        assert!(validate_expected_candidate_sha(changed, expected).is_err());
        assert!(validate_clean_git_status(b"").is_ok());
        assert!(validate_clean_git_status(b"?? untracked-file\n").is_err());
        assert!(
            validate_clean_git_status(b" M tracked-file\n").is_err(),
            "tracked edits must be rejected"
        );
        assert!(validate_index_flags(b"H tracked-file\0H nested/source.rs\0").is_ok());
        assert!(
            validate_index_flags(b"h tracked-file\0").is_err(),
            "assume-unchanged flags must be rejected"
        );
        assert!(
            validate_index_flags(b"S tracked-file\0").is_err(),
            "skip-worktree flags must be rejected"
        );
        assert!(
            validate_index_flags(b"H tracked-file").is_err(),
            "unterminated index inventory must be rejected"
        );
    }

    #[test]
    fn pinned_git_rejects_relative_paths_and_fake_sha_before_spawn() {
        let root = tempfile::tempdir().expect("temporary fake Git root");
        let fake_git = root.path().join("git.exe");
        std::fs::write(&fake_git, b"not a Git executable").expect("write fake Git image");
        let actual_sha = hash_artifact(&fake_git)
            .expect("hash fake Git image")
            .sha256;

        assert!(pin_executable_from_inputs(Path::new("git.exe"), &actual_sha).is_err());
        assert!(pin_executable_from_inputs(&fake_git, &"0".repeat(64)).is_err());
        pin_executable_from_inputs(&fake_git, &actual_sha)
            .unwrap_or_else(|error| panic!("exact fake Git pin should validate: {error}"));
    }

    #[test]
    fn hostile_inherited_git_environment_is_cleared_before_spawn() {
        let mut command = Command::new("unused-git.exe");
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "alias.status=write-marker")
            .env("GIT_CONFIG_VALUE_0", "!write-marker")
            .env("GIT_CONFIG_PARAMETERS", "core.fsmonitor=write-marker")
            .env("GIT_DIR", "outside-metadata")
            .env("GIT_TRACE", "write-marker");
        clear_inherited_git_environment(&mut command);
        assert_eq!(
            command.get_envs().count(),
            0,
            "the approved Git command builder must clear inherited variables before spawn"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pinned_git_lock_denies_replacement_and_spawned_process_image_is_verified() {
        use std::process::Stdio;

        let root = tempfile::tempdir().expect("temporary locked Git root");
        let fake_git = root.path().join("fake-git.exe");
        std::fs::write(&fake_git, b"not a Git image").expect("write fake Git image");
        let fake_sha = hash_artifact(&fake_git)
            .expect("hash fake Git image")
            .sha256;
        let fake_pin = pin_executable_from_inputs(&fake_git, &fake_sha).expect("lock fake path");

        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&fake_git)
                .is_err(),
            "locked executable handle must deny write access"
        );
        let moved_fake = root.path().join("moved-fake-git.exe");
        assert!(
            std::fs::rename(&fake_git, &moved_fake).is_err(),
            "locked executable handle must deny path replacement"
        );
        drop(fake_pin);
        std::fs::rename(&fake_git, &moved_fake)
            .expect("replacement becomes possible only after lock release");

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7 process-fixture repository root");
        let process_fixture_source = existing_fixture(repo_root, "d29h7-process-fixture")
            .unwrap_or_else(|error| panic!("{error}"));
        let source_digest =
            hash_artifact(&process_fixture_source).expect("hash manifest-bound process fixture");
        let process_fixture = root.path().join("d29h7-process-fixture.exe");
        std::fs::copy(&process_fixture_source, &process_fixture)
            .expect("copy manifest-bound fixture into isolated lock test root");
        let process_digest =
            hash_artifact(&process_fixture).expect("hash isolated process fixture copy");
        assert_eq!(
            process_digest.sha256, source_digest.sha256,
            "isolated process probe must retain exact V3 manifest-bound fixture bytes"
        );
        let process_sha = process_digest.sha256;
        let process_pin = pin_executable_from_inputs(&process_fixture, &process_sha)
            .expect("lock manifest-bound process fixture");
        let mut child = Command::new(&process_pin.path)
            .args(["sleep", "5000"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pinned-image identity test process");
        assert!(verify_spawned_process_image(child.id(), &process_pin).is_ok());
        let raced_replacement = root.path().join("pinned-process-replacement.exe");
        assert!(
            std::fs::rename(&process_fixture, &raced_replacement).is_err(),
            "pinned process path replacement must fail while the verified process is running"
        );
        let wrong_pin = pin_executable_from_inputs(
            &moved_fake,
            &hash_artifact(&moved_fake)
                .expect("hash moved fake Git image")
                .sha256,
        )
        .expect("lock wrong expected image");
        assert!(verify_spawned_process_image(child.id(), &wrong_pin).is_err());
        let _ = child.kill();
        let _ = child.wait();
        drop(process_pin);
        std::fs::rename(&process_fixture, &raced_replacement)
            .expect("path replacement becomes possible only after process and lock release");
    }

    #[cfg(unix)]
    #[test]
    fn pinned_git_rejects_symlinked_executable_components() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary Git symlink root");
        let real_dir = root.path().join("real");
        std::fs::create_dir(&real_dir).expect("real Git directory");
        let real_git = real_dir.join("git");
        std::fs::write(&real_git, b"pinned bytes").expect("write fake Git image");
        let linked_dir = root.path().join("linked");
        symlink(&real_dir, &linked_dir).expect("create Git path symlink");
        let linked_git = linked_dir.join("git");
        let expected_sha = hash_artifact(&real_git)
            .expect("hash fake Git image")
            .sha256;

        assert!(pin_executable_from_inputs(&linked_git, &expected_sha).is_err());
    }

    #[test]
    fn producer_consumer_round_trip_covers_all_five_fixture_records() {
        let produced = producer_manifest_value();
        assert_eq!(
            produced["environment"]
                .as_object()
                .expect("producer environment object")
                .len(),
            6,
            "producer schema-v3 environment retains the strict six-field consumer wire shape"
        );
        let parsed: FixtureManifest = serde_json::from_value(produced.clone())
            .expect("the producer-shaped manifest must satisfy the strict consumer");
        assert_eq!(parsed.fixtures.len(), 5);
        assert!(parsed
            .fixtures
            .iter()
            .all(|record| record.root_identity.is_some()));
        assert!(parsed.fixtures.iter().all(|record| record.reap.is_some()));

        let serialized = serde_json::to_value(&parsed).expect("manifest must round-trip");
        assert_eq!(serialized["schema_version"], produced["schema_version"]);
        assert!(serialized["process_tree_error"].is_null());
        assert!(serialized["environment"]["rustup_toolchain"].is_null());
        assert!(serialized["fixtures"][0]["error"].is_null());
        assert!(serialized["fixtures"][0]["reap"]["native_cleanup"].is_object());
        assert!(serialized["fixtures"][0]
            .get("captured_descendant_pids")
            .is_none());
        let reparsed: FixtureManifest = serde_json::from_value(serialized)
            .expect("the serialized manifest must remain consumable");
        assert_eq!(reparsed.fixtures.len(), 5);

        let mut provenance_must_stay_separate = produced;
        provenance_must_stay_separate["environment"]["toolchain_profile_sha256"] =
            json!("a".repeat(64));
        assert!(
            serde_json::from_value::<FixtureManifest>(provenance_must_stay_separate).is_err(),
            "toolchain provenance must not be added to the v3 BuildEnvironmentWire"
        );
    }

    #[test]
    fn every_fixture_v3_nullable_field_requires_presence_but_accepts_null() {
        for (field, label) in [
            (
                RequiredNullableField::Manifest("process_tree_error"),
                "process_tree_error",
            ),
            (
                RequiredNullableField::Environment("rustup_toolchain"),
                "environment.rustup_toolchain",
            ),
            (
                RequiredNullableField::Fixture("exit_code"),
                "fixture.exit_code",
            ),
            (RequiredNullableField::Fixture("pid"), "fixture.pid"),
            (
                RequiredNullableField::Fixture("root_identity"),
                "fixture.root_identity",
            ),
            (RequiredNullableField::Fixture("reap"), "fixture.reap"),
            (
                RequiredNullableField::Fixture("elapsed_ms"),
                "fixture.elapsed_ms",
            ),
            (RequiredNullableField::Fixture("error"), "fixture.error"),
            (
                RequiredNullableField::Fixture("artifact"),
                "fixture.artifact",
            ),
            (
                RequiredNullableField::ProcessIdentity("parent_process_id"),
                "process_identity.parent_process_id",
            ),
            (
                RequiredNullableField::ProcessIdentity("name"),
                "process_identity.name",
            ),
            (
                RequiredNullableField::ProcessIdentity("creation_date"),
                "process_identity.creation_date",
            ),
            (
                RequiredNullableField::ProcessIdentity("command_line"),
                "process_identity.command_line",
            ),
            (
                RequiredNullableField::Reap("native_cleanup"),
                "reap.native_cleanup",
            ),
        ] {
            assert_required_nullable_field(field, label);
        }
    }

    #[test]
    fn strict_manifest_rejects_legacy_or_nested_unknown_fields() {
        let mut legacy = producer_manifest_value();
        legacy["fixtures"][0]["captured_descendant_pids"] = json!([1001]);
        assert!(serde_json::from_value::<FixtureManifest>(legacy).is_err());

        let mut nested = producer_manifest_value();
        nested["fixtures"][0]["descendant_identities"][0]["captured_processes"] = json!([]);
        assert!(serde_json::from_value::<FixtureManifest>(nested).is_err());
    }

    #[test]
    fn timeout_action_uses_one_static_canonical_value() {
        assert_eq!(
            D32_FIXTURE_PROCESS_TREE_TIMEOUT_ACTION,
            "native Job Object kill-on-close, then verify every captured identity and relevant descendant"
        );
        let valid = BuildPolicy {
            timeout_seconds: 1,
            cargo_build_jobs: 1,
            nested_builds: false,
            process_tree_timeout_action: D32_FIXTURE_PROCESS_TREE_TIMEOUT_ACTION.to_string(),
        };
        assert!(validate_build_policy(&valid).is_ok());
        let invalid_policy = BuildPolicy {
            process_tree_timeout_action: "taskkill /T /F then verify every captured descendant PID"
                .to_string(),
            ..valid
        };
        assert!(validate_build_policy(&invalid_policy).is_err());
    }
}
