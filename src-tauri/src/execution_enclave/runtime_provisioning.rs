//! D29-C private trusted Codex runtime provisioning.
//!
//! This module is intentionally below the private execution-enclave module.
//! It accepts a source file only as candidate bytes, derives the destination
//! from the compile-time descriptor, and returns a launch binding only after
//! the finalized executable has been verified.

use super::{
    CodexLaunchSpec, CodexRuntimeError, IsolatedExecutionRoot, TrustedCodexRuntimeDescriptor,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_WRITE_THROUGH,
};

const FINAL_EXECUTABLE_NAME: &str = "codex-app-server.exe";
const PRIVATE_CODEX_HOME_NAME: &str = "codex-home";
const STAGING_FILE_PREFIX: &str = ".codex-app-server";

#[derive(Clone, Debug)]
pub(super) struct TrustedCodexRuntimeProvisioner {
    descriptor: TrustedCodexRuntimeDescriptor,
    layout: TrustedCodexRuntimeLayout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TrustedCodexRuntimeLayout {
    app_data_root: PathBuf,
    runtime_root: PathBuf,
    version_root: PathBuf,
    trusted_runtime_root: PathBuf,
    executable: PathBuf,
    private_codex_home: PathBuf,
}

#[derive(Clone, Debug)]
pub(super) struct TrustedCodexRuntime {
    descriptor: TrustedCodexRuntimeDescriptor,
    layout: TrustedCodexRuntimeLayout,
    reused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    size: u64,
    sha256: String,
}

impl TrustedCodexRuntimeProvisioner {
    /// Construct the only production descriptor accepted by D29-C.  The
    /// application supplies its already selected private app-data directory;
    /// no runtime asset or executable path is caller-selectable here.
    pub(super) fn new(app_data_root: &Path) -> Result<Self, CodexRuntimeError> {
        Self::new_with_descriptor(app_data_root, TrustedCodexRuntimeDescriptor::pinned())
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        app_data_root: &Path,
        descriptor: TrustedCodexRuntimeDescriptor,
    ) -> Result<Self, CodexRuntimeError> {
        Self::new_with_descriptor(app_data_root, descriptor)
    }

    fn new_with_descriptor(
        app_data_root: &Path,
        descriptor: TrustedCodexRuntimeDescriptor,
    ) -> Result<Self, CodexRuntimeError> {
        ensure_supported_platform(&descriptor)?;
        let app_data_root = prepare_app_data_root(app_data_root)?;
        let layout = TrustedCodexRuntimeLayout::from_app_data_root(&app_data_root, descriptor)?;
        Ok(Self { descriptor, layout })
    }

    pub(super) fn layout(&self) -> &TrustedCodexRuntimeLayout {
        &self.layout
    }

    /// Provision from candidate bytes into the fixed app-private runtime
    /// location.  The source filename is never used to derive the destination.
    pub(super) fn provision_from_verified_source_file(
        &self,
        source_file: &Path,
    ) -> Result<TrustedCodexRuntime, CodexRuntimeError> {
        let staging_path = self.layout.staging_path();
        self.provision_from_source_file_with_staging_path(source_file, &staging_path)
    }

    fn provision_from_source_file_with_staging_path(
        &self,
        source_file: &Path,
        staging_path: &Path,
    ) -> Result<TrustedCodexRuntime, CodexRuntimeError> {
        ensure_supported_platform(&self.descriptor)?;
        let source_file = canonical_source_file(source_file)?;
        self.layout.ensure_directories()?;

        if existing_runtime_is_exact(&self.layout.executable, self.descriptor)? {
            return Ok(TrustedCodexRuntime {
                descriptor: self.descriptor,
                layout: self.layout.clone(),
                reused: true,
            });
        }

        let mut staging_guard = StagingPathGuard::new(staging_path.to_path_buf());
        copy_and_verify_source(&source_file, staging_path, self.descriptor)?;

        // A final path may have appeared while the candidate was copied.  It
        // is reused only when it is independently exact; it is never replaced.
        if existing_runtime_is_exact(&self.layout.executable, self.descriptor)? {
            return Ok(TrustedCodexRuntime {
                descriptor: self.descriptor,
                layout: self.layout.clone(),
                reused: true,
            });
        }
        match publish_staged_file_no_replace(staging_path, &self.layout.executable) {
            Ok(()) => {
                staging_guard.disarm();
                verify_runtime_file(&self.layout.executable, self.descriptor)
                    .map_err(|_| CodexRuntimeError::RuntimeIdentityMismatch)?;
                Ok(TrustedCodexRuntime {
                    descriptor: self.descriptor,
                    layout: self.layout.clone(),
                    reused: false,
                })
            }
            Err(CodexRuntimeError::AtomicFinalizeFailed) => {
                reuse_exact_runtime_after_failed_publish(&self.layout.executable, self.descriptor)?;
                Ok(TrustedCodexRuntime {
                    descriptor: self.descriptor,
                    layout: self.layout.clone(),
                    reused: true,
                })
            }
            Err(error) => Err(error),
        }
    }
}

impl TrustedCodexRuntimeLayout {
    fn from_app_data_root(
        app_data_root: &Path,
        descriptor: TrustedCodexRuntimeDescriptor,
    ) -> Result<Self, CodexRuntimeError> {
        let runtime_root = app_data_root.join("runtime").join("codex");
        let version_root = runtime_root.join(descriptor.release());
        let trusted_runtime_root = version_root.join(descriptor.asset_sha256());
        let executable = trusted_runtime_root.join(FINAL_EXECUTABLE_NAME);
        let private_codex_home = trusted_runtime_root.join(PRIVATE_CODEX_HOME_NAME);
        let layout = Self {
            app_data_root: app_data_root.to_path_buf(),
            runtime_root,
            version_root,
            trusted_runtime_root,
            executable,
            private_codex_home,
        };
        layout.validate_shape()?;
        Ok(layout)
    }

    fn validate_shape(&self) -> Result<(), CodexRuntimeError> {
        if !path_is_within_case_insensitive(&self.app_data_root, &self.runtime_root)
            || !path_is_within_case_insensitive(&self.runtime_root, &self.version_root)
            || !path_is_within_case_insensitive(&self.version_root, &self.trusted_runtime_root)
            || !path_is_within_case_insensitive(&self.trusted_runtime_root, &self.executable)
            || !path_is_within_case_insensitive(
                &self.trusted_runtime_root,
                &self.private_codex_home,
            )
        {
            return Err(CodexRuntimeError::RuntimePathRejected);
        }
        Ok(())
    }

    fn ensure_directories(&self) -> Result<(), CodexRuntimeError> {
        self.validate_shape()?;
        for directory in [
            &self.runtime_root,
            &self.version_root,
            &self.trusted_runtime_root,
            &self.private_codex_home,
        ] {
            reject_reparse_components(directory, CodexRuntimeError::RuntimePathRejected)?;
            fs::create_dir_all(directory).map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
            reject_reparse_components(directory, CodexRuntimeError::RuntimePathRejected)?;
        }
        reject_reparse_components(&self.app_data_root, CodexRuntimeError::RuntimePathRejected)?;
        let canonical_root = fs::canonicalize(&self.trusted_runtime_root)
            .map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
        let canonical_app_root = fs::canonicalize(&self.app_data_root)
            .map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
        if !path_is_within_case_insensitive(&canonical_app_root, &canonical_root) {
            return Err(CodexRuntimeError::RuntimePathRejected);
        }
        Ok(())
    }

    pub(super) fn app_data_root(&self) -> &Path {
        &self.app_data_root
    }

    pub(super) fn trusted_runtime_root(&self) -> &Path {
        &self.trusted_runtime_root
    }

    pub(super) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(super) fn private_codex_home(&self) -> &Path {
        &self.private_codex_home
    }

    fn staging_path(&self) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.trusted_runtime_root.join(format!(
            "{STAGING_FILE_PREFIX}-{}-{nanos}.staging",
            std::process::id()
        ))
    }
}

impl TrustedCodexRuntime {
    pub(super) fn descriptor(&self) -> TrustedCodexRuntimeDescriptor {
        self.descriptor
    }

    pub(super) fn executable(&self) -> &Path {
        self.layout.executable()
    }

    pub(super) fn private_codex_home(&self) -> &Path {
        self.layout.private_codex_home()
    }

    pub(super) fn trusted_runtime_root(&self) -> &Path {
        self.layout.trusted_runtime_root()
    }

    pub(super) fn was_reused(&self) -> bool {
        self.reused
    }

    pub(super) fn launch_spec(&self, isolation_root: IsolatedExecutionRoot) -> CodexLaunchSpec {
        CodexLaunchSpec {
            executable: self.executable().to_path_buf(),
            args: Vec::new(),
            isolation_root,
            upstream_release: self.descriptor.release().to_owned(),
            upstream_commit: self.descriptor.upstream_commit().to_owned(),
            private_codex_home: Some(self.private_codex_home().to_path_buf()),
            trusted_runtime_root: Some(self.trusted_runtime_root().to_path_buf()),
            trusted_runtime_descriptor: Some(self.descriptor),
        }
    }
}

pub(super) fn verify_runtime_identity_before_spawn(
    executable: &Path,
    trusted_runtime_root: &Path,
    descriptor: TrustedCodexRuntimeDescriptor,
) -> Result<PathBuf, CodexRuntimeError> {
    ensure_supported_platform(&descriptor)?;
    validate_existing_absolute_path(
        trusted_runtime_root,
        CodexRuntimeError::RuntimeIdentityMismatch,
    )?;
    validate_existing_absolute_path(executable, CodexRuntimeError::RuntimeIdentityMismatch)?;

    let canonical_root = fs::canonicalize(trusted_runtime_root)
        .map_err(|_| CodexRuntimeError::RuntimeIdentityMismatch)?;
    let canonical_executable =
        fs::canonicalize(executable).map_err(|_| CodexRuntimeError::RuntimeIdentityMismatch)?;
    reject_reparse_components(&canonical_root, CodexRuntimeError::RuntimeIdentityMismatch)?;
    reject_reparse_components(executable, CodexRuntimeError::RuntimeIdentityMismatch)?;
    if !canonical_root.is_dir()
        || !path_is_within_case_insensitive(&canonical_root, &canonical_executable)
        || !path_equal_case_insensitive(
            &canonical_executable,
            &canonical_root.join(FINAL_EXECUTABLE_NAME),
        )
    {
        return Err(CodexRuntimeError::RuntimeIdentityMismatch);
    }
    verify_runtime_file(&canonical_executable, descriptor)
        .map_err(|_| CodexRuntimeError::RuntimeIdentityMismatch)?;
    Ok(canonical_executable)
}

pub(super) fn verify_private_codex_home_before_spawn(
    private_codex_home: &Path,
    trusted_runtime_root: &Path,
) -> Result<PathBuf, CodexRuntimeError> {
    validate_existing_absolute_path(private_codex_home, CodexRuntimeError::RuntimePathRejected)?;
    validate_existing_absolute_path(trusted_runtime_root, CodexRuntimeError::RuntimePathRejected)?;
    let canonical_root = fs::canonicalize(trusted_runtime_root)
        .map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
    let canonical_home =
        fs::canonicalize(private_codex_home).map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
    reject_reparse_components(private_codex_home, CodexRuntimeError::RuntimePathRejected)?;
    if !canonical_home.is_dir()
        || !path_is_within_case_insensitive(&canonical_root, &canonical_home)
        || !path_equal_case_insensitive(
            &canonical_home,
            &canonical_root.join(PRIVATE_CODEX_HOME_NAME),
        )
    {
        return Err(CodexRuntimeError::RuntimePathRejected);
    }
    Ok(canonical_home)
}

fn ensure_supported_platform(
    descriptor: &TrustedCodexRuntimeDescriptor,
) -> Result<(), CodexRuntimeError> {
    ensure_supported_platform_for(descriptor, std::env::consts::OS, std::env::consts::ARCH)
}

fn ensure_supported_platform_for(
    descriptor: &TrustedCodexRuntimeDescriptor,
    target_os: &str,
    target_arch: &str,
) -> Result<(), CodexRuntimeError> {
    if !cfg!(windows)
        || target_os != descriptor.target_os()
        || target_arch != descriptor.target_arch()
    {
        return Err(CodexRuntimeError::UnsupportedPlatform);
    }
    Ok(())
}

fn prepare_app_data_root(path: &Path) -> Result<PathBuf, CodexRuntimeError> {
    validate_absolute_path_shape(path, CodexRuntimeError::RuntimePathRejected)?;
    reject_reparse_components(path, CodexRuntimeError::RuntimePathRejected)?;
    fs::create_dir_all(path).map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
    reject_reparse_components(path, CodexRuntimeError::RuntimePathRejected)?;
    let canonical = fs::canonicalize(path).map_err(|_| CodexRuntimeError::RuntimePathRejected)?;
    validate_existing_absolute_path(&canonical, CodexRuntimeError::RuntimePathRejected)?;
    if !canonical.is_dir() {
        return Err(CodexRuntimeError::RuntimePathRejected);
    }
    Ok(canonical)
}

fn canonical_source_file(path: &Path) -> Result<PathBuf, CodexRuntimeError> {
    validate_absolute_path_shape(path, CodexRuntimeError::SourcePathRejected)?;
    reject_reparse_components(path, CodexRuntimeError::SourcePathRejected)?;
    let canonical = fs::canonicalize(path).map_err(|_| CodexRuntimeError::SourcePathRejected)?;
    reject_reparse_components(path, CodexRuntimeError::SourcePathRejected)?;
    validate_existing_absolute_path(&canonical, CodexRuntimeError::SourcePathRejected)?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|_| CodexRuntimeError::SourcePathRejected)?;
    if !metadata.is_file() {
        return Err(CodexRuntimeError::SourcePathRejected);
    }
    Ok(canonical)
}

fn validate_existing_absolute_path(
    path: &Path,
    error: CodexRuntimeError,
) -> Result<(), CodexRuntimeError> {
    validate_absolute_path_shape(path, error)?;
    reject_reparse_components(path, error)?;
    Ok(())
}

fn validate_absolute_path_shape(
    path: &Path,
    error: CodexRuntimeError,
) -> Result<(), CodexRuntimeError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || is_unc_or_device_path(path)
    {
        return Err(error);
    }
    Ok(())
}

fn is_unc_or_device_path(path: &Path) -> bool {
    let path = path.as_os_str().to_string_lossy().to_ascii_lowercase();
    if path.starts_with(r"\\?\") || path.starts_with("//?/") {
        return path.starts_with(r"\\?\unc\")
            || path.starts_with("//?/unc/")
            || path.starts_with(r"\\?\globalroot\")
            || path.starts_with("//?/globalroot/")
            || path.starts_with(r"\\?\volume{")
            || path.starts_with("//?/volume{");
    }
    path.starts_with(r"\\")
        || path.starts_with("//")
        || path.starts_with(r"\\.\")
        || path.starts_with("//./")
}

fn reject_reparse_components(
    path: &Path,
    error: CodexRuntimeError,
) -> Result<(), CodexRuntimeError> {
    #[cfg(windows)]
    {
        for ancestor in path.ancestors() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                    return Err(error);
                }
                Ok(_) => {}
                Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(error),
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(CodexRuntimeError::UnsupportedPlatform)
    }
}

fn copy_and_verify_source(
    source: &Path,
    staging: &Path,
    descriptor: TrustedCodexRuntimeDescriptor,
) -> Result<(), CodexRuntimeError> {
    let mut input = File::open(source).map_err(|_| CodexRuntimeError::SourcePathRejected)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging)
        .map_err(|_| CodexRuntimeError::StagingFailed)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let bytes_read = input
            .read(&mut buffer)
            .map_err(|_| CodexRuntimeError::StagingFailed)?;
        if bytes_read == 0 {
            break;
        }
        total = total
            .checked_add(bytes_read as u64)
            .ok_or(CodexRuntimeError::SourceSizeMismatch)?;
        if total > descriptor.asset_size() {
            return Err(CodexRuntimeError::SourceSizeMismatch);
        }
        hasher.update(&buffer[..bytes_read]);
        output
            .write_all(&buffer[..bytes_read])
            .map_err(|_| CodexRuntimeError::StagingFailed)?;
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|_| CodexRuntimeError::StagingFailed)?;

    if total != descriptor.asset_size() {
        return Err(CodexRuntimeError::SourceSizeMismatch);
    }
    let digest = digest_hex(hasher.finalize());
    if digest != descriptor.asset_sha256() {
        return Err(CodexRuntimeError::SourceHashMismatch);
    }
    let staged_metadata =
        fs::symlink_metadata(staging).map_err(|_| CodexRuntimeError::StagingFailed)?;
    if !staged_metadata.is_file() || staged_metadata.len() != descriptor.asset_size() {
        return Err(CodexRuntimeError::StagingFailed);
    }
    Ok(())
}

#[cfg(windows)]
fn publish_staged_file_no_replace(
    staging: &Path,
    final_path: &Path,
) -> Result<(), CodexRuntimeError> {
    let mut staging_wide = staging.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut final_wide = final_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if staging_wide.iter().any(|unit| *unit == 0) || final_wide.iter().any(|unit| *unit == 0) {
        return Err(CodexRuntimeError::AtomicFinalizeFailed);
    }
    staging_wide.push(0);
    final_wide.push(0);

    // Deliberately omit the Windows replace-destination flag.  Windows then
    // fails when the destination already exists instead of replacing an
    // unknown file.
    let published = unsafe {
        MoveFileExW(
            staging_wide.as_ptr(),
            final_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        ) != 0
    };
    published
        .then_some(())
        .ok_or(CodexRuntimeError::AtomicFinalizeFailed)
}

#[cfg(not(windows))]
fn publish_staged_file_no_replace(
    staging: &Path,
    final_path: &Path,
) -> Result<(), CodexRuntimeError> {
    let _ = (staging, final_path);
    Err(CodexRuntimeError::UnsupportedPlatform)
}

fn existing_runtime_is_exact(
    executable: &Path,
    descriptor: TrustedCodexRuntimeDescriptor,
) -> Result<bool, CodexRuntimeError> {
    match fs::symlink_metadata(executable) {
        Ok(_) => {
            verify_runtime_file(executable, descriptor)
                .map_err(|_| CodexRuntimeError::RuntimeIdentityMismatch)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CodexRuntimeError::RuntimeIdentityMismatch),
    }
}

fn reuse_exact_runtime_after_failed_publish(
    executable: &Path,
    descriptor: TrustedCodexRuntimeDescriptor,
) -> Result<(), CodexRuntimeError> {
    match existing_runtime_is_exact(executable, descriptor)? {
        true => Ok(()),
        false => Err(CodexRuntimeError::AtomicFinalizeFailed),
    }
}

fn verify_runtime_file(path: &Path, descriptor: TrustedCodexRuntimeDescriptor) -> Result<(), ()> {
    reject_reparse_components(path, CodexRuntimeError::RuntimeIdentityMismatch).map_err(|_| ())?;
    let identity = measure_file(path)?;
    if identity.size == descriptor.asset_size() && identity.sha256 == descriptor.asset_sha256() {
        Ok(())
    } else {
        Err(())
    }
}

fn measure_file(path: &Path) -> Result<FileIdentity, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file() {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(|_| ())?;
        if bytes_read == 0 {
            break;
        }
        total = total.checked_add(bytes_read as u64).ok_or(())?;
        hasher.update(&buffer[..bytes_read]);
    }
    let final_metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !final_metadata.is_file() || final_metadata.len() != total {
        return Err(());
    }
    Ok(FileIdentity {
        size: total,
        sha256: digest_hex(hasher.finalize()),
    })
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn path_components_lower(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect()
}

fn path_equal_case_insensitive(left: &Path, right: &Path) -> bool {
    path_components_lower(left) == path_components_lower(right)
}

fn path_is_within_case_insensitive(root: &Path, candidate: &Path) -> bool {
    let root_components = path_components_lower(root);
    let candidate_components = path_components_lower(candidate);
    candidate_components.len() > root_components.len()
        && candidate_components
            .iter()
            .take(root_components.len())
            .eq(root_components.iter())
}

struct StagingPathGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingPathGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Read,
        path::{Path, PathBuf},
        time::Duration,
    };

    use tempfile::TempDir;

    fn fixture_descriptor(bytes: &[u8]) -> TrustedCodexRuntimeDescriptor {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = Box::leak(digest_hex(hasher.finalize()).into_boxed_str());
        TrustedCodexRuntimeDescriptor {
            repository: super::super::CODEX_UPSTREAM_REPOSITORY,
            release: super::super::CODEX_UPSTREAM_RELEASE,
            upstream_commit: super::super::CODEX_UPSTREAM_COMMIT,
            protocol_schema_hash: super::super::CODEX_PROTOCOL_SCHEMA_HASH,
            client_contract_version: super::super::CODEX_CLIENT_CONTRACT_VERSION,
            target_os: "windows",
            target_arch: "x86_64",
            asset_name: "fixture-codex-app-server.exe",
            asset_id: 7,
            asset_size: bytes.len() as u64,
            asset_sha256: digest,
        }
    }

    #[cfg(windows)]
    fn fixture_root() -> (TempDir, PathBuf, TrustedCodexRuntimeProvisioner) {
        let root = tempfile::tempdir().expect("fixture temp root");
        let app_data = root.path().join("digital-life-app-data");
        let descriptor = fixture_descriptor(b"trusted");
        let provisioner = TrustedCodexRuntimeProvisioner::new_for_test(&app_data, descriptor)
            .expect("fixture app-data root validates");
        (root, app_data, provisioner)
    }

    #[cfg(windows)]
    fn source_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let source = root.join(name);
        fs::write(&source, bytes).expect("write fixture source");
        source
    }

    #[test]
    fn trusted_descriptor_is_exact_and_not_overridable() {
        let descriptor = TrustedCodexRuntimeDescriptor::pinned();
        assert_eq!(
            descriptor.repository(),
            "https://github.com/openai/codex.git"
        );
        assert_eq!(descriptor.release(), "rust-v0.152.0");
        assert_eq!(
            descriptor.upstream_commit(),
            "316795b3cf2a45e90d121d9f46499d4658b2645c"
        );
        assert_eq!(
            descriptor.protocol_schema_hash(),
            "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669"
        );
        assert_eq!(
            descriptor.client_contract_version(),
            "d29-b.codex-app-server.v2"
        );
        assert_eq!(descriptor.target_os(), "windows");
        assert_eq!(descriptor.target_arch(), "x86_64");
        assert_eq!(
            descriptor.asset_name(),
            "codex-app-server-x86_64-pc-windows-msvc.exe"
        );
        assert_eq!(descriptor.asset_id(), 538_792_479);
        assert_eq!(descriptor.asset_size(), 227_369_264);
        assert_eq!(
            descriptor.asset_sha256(),
            "cb8e6cd9996b0647ccecd37d324438c8625738deca754faa74d98e4d7398a98c"
        );
        assert_eq!(descriptor, TrustedCodexRuntimeDescriptor::pinned());
    }

    #[cfg(windows)]
    #[test]
    fn wrong_asset_size_rejected() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"wrong-size");
        let result = provisioner.provision_from_verified_source_file(&source);
        assert_eq!(result.unwrap_err(), CodexRuntimeError::SourceSizeMismatch);
        assert!(!provisioner.layout().executable().exists());
    }

    #[cfg(windows)]
    #[test]
    fn wrong_asset_hash_rejected() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"changed");
        let result = provisioner.provision_from_verified_source_file(&source);
        assert_eq!(result.unwrap_err(), CodexRuntimeError::SourceHashMismatch);
        assert!(!provisioner.layout().executable().exists());
    }

    #[cfg(windows)]
    #[test]
    fn tampered_final_runtime_rejected() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("trusted fixture publishes");
        fs::write(runtime.executable(), b"tamper!").expect("tamper final fixture");
        let result = provisioner.provision_from_verified_source_file(&source);
        assert_eq!(
            result.unwrap_err(),
            CodexRuntimeError::RuntimeIdentityMismatch
        );
        assert_eq!(fs::read(runtime.executable()).unwrap(), b"tamper!");
    }

    #[cfg(windows)]
    #[test]
    fn matching_existing_runtime_reused() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let first = provisioner
            .provision_from_verified_source_file(&source)
            .expect("first fixture publish");
        assert!(!first.was_reused());
        let second = provisioner
            .provision_from_verified_source_file(&source)
            .expect("exact fixture reuse");
        assert!(second.was_reused());
        assert_eq!(first.executable(), second.executable());
    }

    #[cfg(windows)]
    #[test]
    fn staging_failure_never_publishes_trusted_binary() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        provisioner
            .layout()
            .ensure_directories()
            .expect("runtime directories prepare");
        let staging = provisioner
            .layout()
            .trusted_runtime_root()
            .join("forced-staging-directory");
        fs::create_dir(&staging).expect("reserve staging path as directory");
        assert_eq!(
            provisioner
                .provision_from_source_file_with_staging_path(&source, &staging)
                .unwrap_err(),
            CodexRuntimeError::StagingFailed
        );
        assert!(!provisioner.layout().executable().exists());
        assert!(staging.is_dir());
        fs::remove_dir(&staging).expect("remove reserved staging directory");
    }

    #[cfg(windows)]
    #[test]
    fn atomic_publish_never_replaces_existing_mismatched_final() {
        let root = tempfile::tempdir().expect("fixture temp root");
        let app_data = root.path().join("digital-life-app-data");
        let descriptor = fixture_descriptor(b"trusted");
        let provisioner = TrustedCodexRuntimeProvisioner::new_for_test(&app_data, descriptor)
            .expect("fixture app-data root validates");
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        provisioner
            .layout()
            .ensure_directories()
            .expect("runtime directories prepare");
        let staging = provisioner
            .layout()
            .trusted_runtime_root()
            .join("verified-candidate.staging");
        copy_and_verify_source(&source, &staging, descriptor)
            .expect("verified staging candidate created");
        let final_path = provisioner.layout().executable().to_path_buf();
        let original_final = b"existing-unknown-final";
        fs::write(&final_path, original_final).expect("create mismatched final");
        let publish_result;
        {
            let _staging_guard = StagingPathGuard::new(staging.clone());
            publish_result = publish_staged_file_no_replace(&staging, &final_path);
        }
        assert_eq!(
            publish_result.unwrap_err(),
            CodexRuntimeError::AtomicFinalizeFailed
        );
        assert_eq!(fs::read(&final_path).expect("read final"), original_final);
        assert!(!staging.exists(), "failed publish must clean staging");
        assert_eq!(
            reuse_exact_runtime_after_failed_publish(&final_path, descriptor).unwrap_err(),
            CodexRuntimeError::RuntimeIdentityMismatch
        );
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_exact_final_is_reused_without_replacement() {
        let root = tempfile::tempdir().expect("fixture temp root");
        let app_data = root.path().join("digital-life-app-data");
        let descriptor = fixture_descriptor(b"trusted");
        let provisioner = TrustedCodexRuntimeProvisioner::new_for_test(&app_data, descriptor)
            .expect("fixture app-data root validates");
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        provisioner
            .layout()
            .ensure_directories()
            .expect("runtime directories prepare");
        let staging = provisioner
            .layout()
            .trusted_runtime_root()
            .join("verified-candidate.staging");
        copy_and_verify_source(&source, &staging, descriptor)
            .expect("verified staging candidate created");
        let final_path = provisioner.layout().executable().to_path_buf();
        fs::write(&final_path, b"trusted").expect("create exact concurrent final");
        let final_before = fs::read(&final_path).expect("read exact final");
        let publish_result;
        {
            let _staging_guard = StagingPathGuard::new(staging.clone());
            publish_result = publish_staged_file_no_replace(&staging, &final_path);
        }
        assert_eq!(
            publish_result.unwrap_err(),
            CodexRuntimeError::AtomicFinalizeFailed
        );
        reuse_exact_runtime_after_failed_publish(&final_path, descriptor)
            .expect("exact concurrent final is reusable");
        assert_eq!(fs::read(&final_path).expect("read final"), final_before);
        assert!(!staging.exists(), "reused final must clean staging");
    }

    #[cfg(windows)]
    #[test]
    fn source_filename_cannot_choose_destination() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "attacker-selected.exe", b"trusted");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("source bytes publish to fixed destination");
        assert_eq!(
            runtime
                .executable()
                .file_name()
                .and_then(|name| name.to_str()),
            Some(FINAL_EXECUTABLE_NAME)
        );
        assert!(!provisioner
            .layout()
            .trusted_runtime_root()
            .join("attacker-selected.exe")
            .exists());
    }

    #[cfg(windows)]
    #[test]
    fn runtime_cannot_escape_private_root() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("trusted fixture publishes");
        assert!(path_is_within_case_insensitive(
            runtime.trusted_runtime_root(),
            runtime.executable()
        ));
        assert!(!path_is_within_case_insensitive(
            runtime.trusted_runtime_root(),
            &root.path().join("escaped.exe")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_or_junction_runtime_path_rejected() {
        let (root, app_data, provisioner) = fixture_root();
        let target = root.path().join("junction-target");
        fs::create_dir_all(&target).expect("junction target");
        let runtime_link = app_data.join("runtime");
        let status = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&runtime_link)
            .arg(&target)
            .status()
            .expect("mklink is available on Windows");
        assert!(status.success(), "junction creation must succeed");
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        assert_eq!(
            provisioner
                .provision_from_verified_source_file(&source)
                .unwrap_err(),
            CodexRuntimeError::RuntimePathRejected
        );
        let _ = fs::remove_dir(&runtime_link);
    }

    #[cfg(windows)]
    #[test]
    fn unc_runtime_root_rejected() {
        let descriptor = fixture_descriptor(b"trusted");
        assert_eq!(
            TrustedCodexRuntimeProvisioner::new_for_test(
                Path::new(r"\\server\share\digital-life"),
                descriptor
            )
            .unwrap_err(),
            CodexRuntimeError::RuntimePathRejected
        );
    }

    #[cfg(windows)]
    #[test]
    fn global_codex_path_not_consulted() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let path_before = std::env::var_os("PATH");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("provisioning uses only the candidate source");
        assert_eq!(std::env::var_os("PATH"), path_before);
        assert!(path_is_within_case_insensitive(
            provisioner.layout().app_data_root(),
            runtime.executable()
        ));
        let production = include_str!("mod.rs");
        assert!(!production.contains("var_os(\"PATH\")"));
        assert!(!production.contains("which::"));
    }

    #[cfg(windows)]
    fn environment_entries(private_home: &Path) -> Vec<String> {
        let block = super::super::windows_environment_block(
            super::super::CodexUpstreamPin::pinned(),
            Some(private_home),
        );
        block
            .split(|unit| *unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    #[cfg(windows)]
    #[test]
    fn user_codex_home_not_inherited() {
        let entries = environment_entries(Path::new(r"C:\digital-life-private\codex-home"));
        assert!(entries
            .iter()
            .any(|entry| entry.starts_with("CODEX_HOME=C:\\digital-life-private")));
        assert!(!entries.iter().any(|entry| entry.starts_with("HOME=")));
        assert!(!entries
            .iter()
            .any(|entry| entry.starts_with("USERPROFILE=")));
        assert!(!entries.iter().any(|entry| entry.contains(r"\.codex")));
    }

    #[cfg(windows)]
    #[test]
    fn user_openai_key_not_inherited() {
        let entries = environment_entries(Path::new(r"C:\digital-life-private\codex-home"));
        assert!(!entries
            .iter()
            .any(|entry| entry.starts_with("OPENAI_API_KEY=")));
        assert!(!entries
            .iter()
            .any(|entry| entry.starts_with("CODEX_API_KEY=")));
    }

    #[cfg(windows)]
    #[test]
    fn runtime_identity_reverified_before_spawn() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("trusted fixture publishes");
        verify_runtime_identity_before_spawn(
            runtime.executable(),
            runtime.trusted_runtime_root(),
            runtime.descriptor(),
        )
        .expect("exact identity passes immediately before spawn");
        fs::write(runtime.executable(), b"tamper!").expect("tamper final fixture");
        assert_eq!(
            verify_runtime_identity_before_spawn(
                runtime.executable(),
                runtime.trusted_runtime_root(),
                runtime.descriptor(),
            )
            .unwrap_err(),
            CodexRuntimeError::RuntimeIdentityMismatch
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_mismatch_prevents_process_creation() {
        let (root, _app_data, provisioner) = fixture_root();
        let source = source_file(root.path(), "candidate.bin", b"trusted");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("trusted fixture publishes");
        fs::write(runtime.executable(), b"tamper!").expect("tamper final fixture");

        let isolated_directory = tempfile::tempdir().expect("isolated process root");
        fs::write(
            isolated_directory.path().join(".d29-dedicated-root"),
            b"d29",
        )
        .expect("mark isolated process root");
        let isolated_root =
            IsolatedExecutionRoot::from_dedicated_test_root(isolated_directory.path())
                .expect("isolated process root validates");
        assert_eq!(
            super::super::CodexRuntimeAdapter::pinned()
                .spawn_trusted_runtime(&runtime, isolated_root)
                .unwrap_err(),
            CodexRuntimeError::RuntimeIdentityMismatch
        );
    }

    #[test]
    fn unsupported_platform_or_arch_fails_closed() {
        let descriptor = TrustedCodexRuntimeDescriptor::pinned();
        assert_eq!(
            ensure_supported_platform_for(&descriptor, "linux", "x86_64").unwrap_err(),
            CodexRuntimeError::UnsupportedPlatform
        );
        assert_eq!(
            ensure_supported_platform_for(&descriptor, "windows", "aarch64").unwrap_err(),
            CodexRuntimeError::UnsupportedPlatform
        );
    }

    #[cfg(windows)]
    fn independent_sha256(path: &Path) -> (u64, String) {
        let mut file = File::open(path).expect("official source file opens");
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let bytes_read = file.read(&mut buffer).expect("official source reads");
            if bytes_read == 0 {
                break;
            }
            size += bytes_read as u64;
            hasher.update(&buffer[..bytes_read]);
        }
        (size, digest_hex(hasher.finalize()))
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires exact official pinned D29-C App Server fixture"]
    fn official_pinned_app_server_initialize_smoke() {
        let source = std::env::var_os("DIGITAL_LIFE_D29_C_OFFICIAL_APP_SERVER_FIXTURE")
            .expect("DIGITAL_LIFE_D29_C_OFFICIAL_APP_SERVER_FIXTURE must be set");
        let source = PathBuf::from(source);
        let descriptor = TrustedCodexRuntimeDescriptor::pinned();
        let (size, digest) = independent_sha256(&source);
        assert_eq!(
            size,
            descriptor.asset_size(),
            "official asset size mismatch"
        );
        assert_eq!(
            digest,
            descriptor.asset_sha256(),
            "official asset SHA-256 mismatch"
        );

        let app_data = tempfile::tempdir().expect("official smoke app-data root");
        let provisioner = TrustedCodexRuntimeProvisioner::new(app_data.path())
            .expect("official smoke app-data root validates");
        let runtime = provisioner
            .provision_from_verified_source_file(&source)
            .expect("official asset provisions into private runtime");
        let isolated_directory = tempfile::tempdir().expect("official smoke isolated root");
        fs::write(
            isolated_directory.path().join(".d29-dedicated-root"),
            b"d29",
        )
        .expect("mark official smoke isolated root");
        let isolated_root =
            IsolatedExecutionRoot::from_dedicated_test_root(isolated_directory.path())
                .expect("official smoke isolated root validates");
        let process = super::super::CodexRuntimeAdapter::pinned()
            .spawn_trusted_runtime(&runtime, isolated_root)
            .expect("official pinned App Server spawns");
        let mut client = super::super::CodexProtocolClient::new(process);
        let initialize = client
            .initialize(Duration::from_secs(30))
            .expect("official pinned App Server initializes");
        assert!(!initialize.platform_os.is_empty());
        assert!(!initialize.user_agent.is_empty());
        client
            .shutdown()
            .expect("official pinned App Server shuts down cleanly");
    }
}
