//! Test-only Codex state sentinels.
//!
//! Real Codex state is deliberately out of scope for Vita tests.  These
//! helpers create an owned root containing harmless sentinel files and provide
//! a metadata-plus-content snapshot for canary assertions.  No environment
//! variable or ambient Codex directory is consulted.

use std::collections::hash_map::DefaultHasher;
use std::ffi::OsString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

use tempfile::{Builder, TempDir};

const SENTINEL_FILES: [(&str, &[u8]); 3] = [
    ("config.toml", b"# digital-life synthetic Codex sentinel\n"),
    ("auth.json", b"{\"digital_life_synthetic\":true}\n"),
    (
        ".codex-global-state.json",
        b"{\"digital_life_synthetic\":true}\n",
    ),
];

static PROCESS_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Serializes test-only process-environment mutations and snapshots.
///
/// The lock deliberately lives in this test-only module so production code
/// cannot acquire or depend on it.  Poison is recovered because a test panic
/// must not make every later canary permanently unusable.
pub(crate) struct ProcessEnvLockGuard {
    _guard: MutexGuard<'static, ()>,
}

pub(crate) fn lock_process_env() -> ProcessEnvLockGuard {
    let guard = PROCESS_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ProcessEnvLockGuard { _guard: guard }
}

/// Test-only environment mutation guard.
///
/// It snapshots each named key while holding the common process lock, applies
/// the requested values, and restores the original values on every exit path,
/// including unwinding.  Keeping the lock as a field makes the restore happen
/// while no other test can observe a partially restored environment.
pub(crate) struct ProcessEnvSnapshotGuard {
    previous: Vec<(String, Option<OsString>)>,
    _lock: ProcessEnvLockGuard,
}

impl ProcessEnvSnapshotGuard {
    pub(crate) fn install(entries: &[(&str, &str)]) -> Self {
        Self::install_with_removals(entries, &[])
    }

    pub(crate) fn install_with_removals(entries: &[(&str, &str)], removals: &[&str]) -> Self {
        let lock = lock_process_env();
        let mut previous = Vec::new();
        for key in entries
            .iter()
            .map(|(key, _)| *key)
            .chain(removals.iter().copied())
        {
            if previous.iter().any(|(seen, _)| seen == key) {
                continue;
            }
            previous.push((key.to_string(), std::env::var_os(key)));
        }
        for (key, value) in entries {
            std::env::set_var(key, value);
        }
        for key in removals {
            std::env::remove_var(key);
        }
        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for ProcessEnvSnapshotGuard {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// A test-owned Codex-like root.  It is never derived from USERPROFILE and is
/// kept alive by the caller for the duration of the canary.
pub(crate) struct SyntheticCodexRoot {
    root: TempDir,
    codex_home: PathBuf,
}

impl SyntheticCodexRoot {
    pub(crate) fn new() -> io::Result<Self> {
        let root = Builder::new()
            .prefix("digital-life-synthetic-codex-")
            .tempdir()?;
        let codex_home = root.path().join(".codex");
        seed_synthetic_codex_state(&codex_home)?;
        Ok(Self { root, codex_home })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.codex_home
    }

    pub(crate) fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub(crate) fn mutate(&self, file_name: &str) -> io::Result<()> {
        let path = self.codex_home.join(file_name);
        fs::write(path, b"digital-life synthetic mutation\n")
    }
}

/// Seeds all files that the canaries claim to protect.  The values are
/// intentionally non-sensitive and valid enough to remain inert if a test
/// accidentally points a parser at the fixture.
pub(crate) fn seed_synthetic_codex_state(root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    for (file_name, contents) in SENTINEL_FILES {
        fs::write(root.join(file_name), contents)?;
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum CodexFileState {
    Absent,
    Present {
        size: u64,
        modified: Option<SystemTime>,
        readonly: bool,
        is_file: bool,
        is_symlink: bool,
        contents: Vec<u8>,
    },
    Unavailable,
}

impl std::fmt::Debug for CodexFileState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Present {
                size,
                modified,
                readonly,
                is_file,
                is_symlink,
                ..
            } => formatter
                .debug_struct("Present")
                .field("size", size)
                .field("modified", modified)
                .field("readonly", readonly)
                .field("is_file", is_file)
                .field("is_symlink", is_symlink)
                .field("contents", &"<redacted>")
                .finish(),
            Self::Unavailable => formatter.write_str("Unavailable"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CodexState {
    pub(crate) config: CodexFileState,
    pub(crate) auth: CodexFileState,
    pub(crate) global_state: CodexFileState,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CodexCanary {
    pub(crate) parent_environment_fingerprint: u64,
    pub(crate) codex_state: CodexState,
}

impl std::fmt::Debug for CodexCanary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CodexCanary(<environment-and-content-redacted>)")
    }
}

impl std::fmt::Debug for CodexState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CodexState(<metadata-and-content-redacted>)")
    }
}

/// Snapshot only the caller-supplied root.  In particular, this function does
/// not resolve USERPROFILE, CODEX_HOME, or any stock Codex path.
pub(crate) fn snapshot_codex_state(root: &Path) -> CodexState {
    CodexState {
        config: snapshot_codex_file(root, "config.toml"),
        auth: snapshot_codex_file(root, "auth.json"),
        global_state: snapshot_codex_file(root, ".codex-global-state.json"),
    }
}

pub(crate) fn snapshot_codex_canary(root: &Path) -> CodexCanary {
    CodexCanary {
        parent_environment_fingerprint: environment_fingerprint(),
        codex_state: snapshot_codex_state(root),
    }
}

pub(crate) fn environment_fingerprint() -> u64 {
    let mut environment = std::env::vars_os().collect::<Vec<_>>();
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = DefaultHasher::new();
    environment.hash(&mut hasher);
    hasher.finish()
}

fn snapshot_codex_file(root: &Path, file_name: &str) -> CodexFileState {
    let path = root.join(file_name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return CodexFileState::Absent,
        Err(_) => return CodexFileState::Unavailable,
    };
    let file_type = metadata.file_type();
    let contents = if file_type.is_file() && !file_type.is_symlink() {
        match fs::read(&path) {
            Ok(contents) => contents,
            Err(_) => return CodexFileState::Unavailable,
        }
    } else {
        Vec::new()
    };
    CodexFileState::Present {
        size: metadata.len(),
        modified: metadata.modified().ok(),
        readonly: metadata.permissions().readonly(),
        is_file: file_type.is_file(),
        is_symlink: file_type.is_symlink(),
        contents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn synthetic_root_snapshot_catches_content_and_metadata_mutation() {
        for file_name in ["config.toml", "auth.json", ".codex-global-state.json"] {
            let root = SyntheticCodexRoot::new().expect("synthetic Codex root");
            let before = snapshot_codex_state(root.path());
            assert!(matches!(before.config, CodexFileState::Present { .. }));
            assert!(matches!(before.auth, CodexFileState::Present { .. }));
            assert!(matches!(
                before.global_state,
                CodexFileState::Present { .. }
            ));

            root.mutate(file_name).expect("mutate synthetic sentinel");
            let after = snapshot_codex_state(root.path());
            assert_ne!(before, after, "{file_name} mutation must be observable");
        }
    }

    #[test]
    fn synthetic_snapshot_ignores_mutation_in_another_root() {
        let protected = SyntheticCodexRoot::new().expect("protected synthetic root");
        let concurrent = SyntheticCodexRoot::new().expect("concurrent synthetic root");
        let before = snapshot_codex_state(protected.path());
        concurrent
            .mutate("auth.json")
            .expect("mutate unrelated synthetic auth");
        assert_eq!(before, snapshot_codex_state(protected.path()));
    }

    #[test]
    fn synthetic_root_cleanup_is_owned_and_bounded() {
        let root = SyntheticCodexRoot::new().expect("synthetic Codex root");
        let root_path = root.root_path().to_path_buf();
        assert!(root_path.exists());
        drop(root);
        assert!(!root_path.exists(), "synthetic root must be cleaned up");
    }

    #[test]
    fn process_env_snapshot_restores_after_panic_and_unlocks() {
        const KEY: &str = "VITA_AGENT_TEST_PROCESS_ENV_PANIC_RESTORE_5032587";
        let baseline = std::env::var_os(KEY);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _environment = ProcessEnvSnapshotGuard::install(&[(KEY, "panic-sentinel")]);
            assert_eq!(
                std::env::var_os(KEY).as_deref(),
                Some("panic-sentinel".as_ref())
            );
            panic!("exercise test environment guard unwinding");
        }));
        assert!(result.is_err());
        assert_eq!(std::env::var_os(KEY), baseline);

        let _lock = lock_process_env();
    }

    #[test]
    fn process_env_lock_recovers_from_poison() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _lock = lock_process_env();
            panic!("exercise process environment lock poisoning");
        }));
        assert!(result.is_err());

        let _recovered = lock_process_env();
    }

    #[test]
    fn process_env_guard_serializes_parallel_mutations_and_restores_baseline() {
        const KEY: &str = "VITA_AGENT_TEST_PROCESS_ENV_STRESS_5032587";
        let baseline = std::env::var_os(KEY);
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));
        let handles = (0..workers)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..64 {
                        let _environment =
                            ProcessEnvSnapshotGuard::install(&[(KEY, "parallel-sentinel")]);
                        assert_eq!(
                            std::env::var_os(KEY).as_deref(),
                            Some("parallel-sentinel".as_ref())
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("parallel env worker should finish");
        }
        assert_eq!(std::env::var_os(KEY), baseline);
    }
}
