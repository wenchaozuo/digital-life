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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const D32_FIXTURE_MANIFEST_ENV: &str = "D32_FIXTURE_MANIFEST_PATH";
pub(crate) const D32_FIXTURE_SCHEMA_VERSION: u32 = 3;
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildEnvironment {
    original_userprofile: String,
    codex_home: String,
    userprofile: String,
    cargo_home: String,
    rustup_home: String,
    rustup_toolchain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReapDocument {
    process_ids: Vec<u32>,
    verified_at_utc: String,
    residual_identities: Vec<ProcessIdentityDocument>,
    native_cleanup: Option<NativeCleanupDocument>,
    kill_output: Vec<String>,
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

fn invalid(message: impl Into<String>) -> String {
    format!("FIXTURE_MANIFEST_INVALID: {}", message.into())
}

fn canonical(path: &Path, label: &str) -> Result<PathBuf, String> {
    std::fs::canonicalize(path)
        .map_err(|error| invalid(format!("{label} cannot be canonicalized: {error}")))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
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

fn current_candidate_sha(repo_root: &Path) -> Result<String, String> {
    let root = repo_root
        .to_str()
        .ok_or_else(|| invalid("repository root is not valid UTF-8"))?;
    let output = Command::new("git")
        .args(["-C", root, "rev-parse", "--verify", "HEAD"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|error| invalid(format!("cannot resolve current candidate SHA: {error}")))?;
    if !output.status.success() {
        return Err(invalid("current candidate SHA command failed"));
    }
    let sha = String::from_utf8(output.stdout)
        .map_err(|_| invalid("current candidate SHA was not UTF-8"))?
        .trim()
        .to_string();
    validate_candidate_sha(&sha, "current candidate SHA")?;
    Ok(sha)
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentity, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

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
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("artifact metadata could not be read: {error}")))?;
    Ok(FileIdentity {
        volume_serial: 0,
        file_index: 0,
        length: metadata.len(),
    })
}

fn hash_artifact(path: &Path) -> Result<FileDigest, String> {
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

fn validate_manifest_common(manifest: &FixtureManifest, repo_root: &Path) -> Result<(), String> {
    if manifest.schema_version != D32_FIXTURE_SCHEMA_VERSION {
        return Err(invalid(format!(
            "schema_version={} expected {}",
            manifest.schema_version, D32_FIXTURE_SCHEMA_VERSION
        )));
    }
    validate_candidate_sha(&manifest.candidate_sha, "candidate_sha")?;
    let head = current_candidate_sha(repo_root)?;
    if manifest.candidate_sha != head {
        return Err(invalid(format!(
            "candidate_sha does not match current HEAD {head}"
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
    let manifest_path = std::env::var_os(D32_FIXTURE_MANIFEST_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("{D32_FIXTURE_MANIFEST_ENV} is not set")))?;
    if !manifest_path.is_absolute() {
        return Err(invalid("fixture manifest path must be absolute"));
    }
    let manifest_path = canonical(&manifest_path, "fixture manifest")?;
    let manifest = parse_manifest(&manifest_path)?;
    validate_manifest_common(&manifest, repo_root)?;
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
    fn producer_consumer_round_trip_covers_all_five_fixture_records() {
        let produced = producer_manifest_value();
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
        assert!(serialized["fixtures"][0]
            .get("captured_descendant_pids")
            .is_none());
        let reparsed: FixtureManifest = serde_json::from_value(serialized)
            .expect("the serialized manifest must remain consumable");
        assert_eq!(reparsed.fixtures.len(), 5);
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
