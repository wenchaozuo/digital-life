//! D29-D anonymous runtime profile for the pinned official Codex App Server.
//!
//! This module is intentionally private and below the execution-enclave module.
//! It records, from the exact pinned upstream source (`openai/codex` at
//! `316795b3cf2a45e90d121d9f46499d4658b2645c`, release `rust-v0.152.0`), every
//! credential / configuration / network-enabling input that the official App
//! Server can consult, and turns "the current runtime has no Codex credential"
//! into a fail-closed guarantee enforced before any anonymous spawn.
//!
//! [`AnonymousCodexRuntimeProfile`] is **not** a capability and it is **not**
//! a permission authority.  It never grants anything: it only rejects spawns
//! when the private runtime root could carry credential/config material.  The
//! child environment is independently rebuilt and audited at the spawn
//! boundary.  This profile never touches `~/.codex` or any user Codex home.

use std::{collections::BTreeMap, ffi::OsString, fmt, fs, path::Path};

/// A file name (or directory name) that the pinned upstream App Server treats
/// as credential or user-configuration material, and which therefore must not
/// be present in the private Codex home before an anonymous spawn.
///
/// Every entry is grounded in the pinned upstream source:
/// - `auth.json`          -> `codex-rs/login/src/auth/storage.rs` `get_auth_file`
/// - `.credentials.json`  -> `codex-rs/rmcp-client/src/oauth.rs` `FALLBACK_FILENAME`
///   (MCP OAuth fallback store, default `OAuthCredentialsStoreMode::Auto`)
/// - `config.toml`        -> `codex-rs/config/src/lib.rs` `CONFIG_TOML_FILE`
///   (base user layer plus profile layer `overrides.user_config_path`)
/// - `environments.toml`  -> `codex-rs/exec-server/src/environment_toml.rs`
///   `ENVIRONMENTS_TOML_FILE` (can select a remote exec server and credentials)
/// - `secrets/`           -> `codex-rs/secrets/src/local.rs` `secrets_dir` with
///   `codex_auth.age` / `mcp_oauth.age` / `local.age` (keyring-backed local
///   encrypted credential stores)
/// - `managed_config.toml`-> `codex-rs/config/src/loader/layer_io.rs`
///   `managed_config_default_path` (legacy managed config, non-Windows default;
///   on Windows it is ignored but present files are still rejected fail-closed)
/// - `AGENTS.md`          -> host instruction source (not a credential, but
///   caller-controlled instruction/config material; rejected fail-closed)
const FORBIDDEN_PRIVATE_HOME_ENTRIES: &[&str] = &[
    "auth.json",
    ".credentials.json",
    "config.toml",
    "environments.toml",
    "managed_config.toml",
    "requirements.toml",
    "session_index.jsonl",
    "secrets",
    "AGENTS.md",
];

/// Files/directories the pinned upstream App Server may legitimately create in
/// a private Codex home as normal runtime state (not credentials and not
/// durable conversation/rollout artifacts).
///
/// Grounded in the pinned upstream source:
/// - `installation_id`              -> `codex-rs/core/src/installation_id.rs`
///   `INSTALLATION_ID_FILENAME`
/// - `state_5.sqlite`               -> `codex-rs/state/src/sqlite.rs` `STATE_DB_FILENAME`
/// - `logs_2.sqlite`                -> `codex-rs/state/src/sqlite.rs` `LOGS_DB_FILENAME`
/// - `goals_1.sqlite`               -> `codex-rs/state/src/sqlite.rs` `GOALS_DB_FILENAME`
/// - `memories_1.sqlite`            -> `codex-rs/state/src/sqlite.rs` `MEMORIES_DB_FILENAME`
/// - `queue_1.sqlite`               -> `codex-rs/state/src/sqlite.rs` `QUEUE_DB_FILENAME`
/// - `thread_history_1.sqlite`      -> `codex-rs/state/src/sqlite.rs` `THREAD_HISTORY_DB_FILENAME`
/// - `models_cache.json`            -> `codex-rs/models-manager/src/manager.rs`
///   `MODEL_CACHE_FILE`
/// - `log/`                         -> `codex-rs/core/src/config/mod.rs` `log_dir`
/// - `sessions/`                    -> durable thread rollout store
///   (`codex-rs/rollout` `SESSIONS_SUBDIR`)
/// - `archived_sessions/`           -> `codex-rs/rollout` `ARCHIVED_SESSIONS_SUBDIR`
///
/// `sessions/` and `archived_sessions/` are *allowed* only in the sense that
/// the anonymous profile does not treat them as credentials; the ephemeral
/// proof in the official smoke asserts that no rollout/conversation artifact
/// appears there for an `ephemeral` thread (the pinned upstream
/// `session/session.rs` `thread_persistence_fut` returns `Ok(None)` when
/// `config.ephemeral` is true).
const ALLOWED_PRIVATE_HOME_ENTRIES: &[&str] = &[
    "installation_id",
    "state_5.sqlite",
    "logs_2.sqlite",
    "goals_1.sqlite",
    "memories_1.sqlite",
    "queue_1.sqlite",
    "thread_history_1.sqlite",
    "models_cache.json",
    "log",
    "sessions",
    "archived_sessions",
    ".tmp",
    "tmp",
];

/// Environment variables that the pinned upstream App Server can read and
/// that carry credentials or network-enabling configuration.  The D29-D child
/// environment is fully rebuilt by Digital Life, so none of these can be
/// inherited.  This list is used by exact child-environment audits; production
/// preflight deliberately does not inspect the parent environment.
///
/// Grounded in the pinned upstream source:
/// - `OPENAI_API_KEY` / `CODEX_API_KEY` -> `codex-rs/login/src/auth/manager.rs`
///   `OPENAI_API_KEY_ENV_VAR` / `CODEX_API_KEY_ENV_VAR`
/// - `CODEX_ACCESS_TOKEN`              -> same file `CODEX_ACCESS_TOKEN_ENV_VAR`
/// - `CODEX_EXEC_SERVER_URL`           -> `codex-rs/exec-server/src/environment_provider.rs`
///   `CODEX_EXEC_SERVER_URL_ENV_VAR`
/// - `CODEX_SQLITE_HOME`               -> `codex-rs/state/src/lib.rs` `SQLITE_HOME_ENV`
/// - `CODEX_REFRESH_TOKEN_URL_OVERRIDE` / `CODEX_REVOKE_TOKEN_URL_OVERRIDE` /
///   `CODEX_APP_SERVER_LOGIN_CLIENT_ID` -> `codex-rs/login/src/auth/manager.rs`
pub(super) const FORBIDDEN_CHILD_ENVIRONMENT_VARS: &[&str] = &[
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "CODEX_EXEC_SERVER_URL",
    "CODEX_SQLITE_HOME",
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "CODEX_REVOKE_TOKEN_URL_OVERRIDE",
    "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
];

/// `CODEX_HOME` is deliberately **not** in [`FORBIDDEN_CHILD_ENVIRONMENT_VARS`]:
/// D29-C already sets it to the private app-data home (see
/// `windows_environment_block`), and the anonymous profile validates that
/// private home.  Setting it again from the host is never allowed.

/// Outcome of the anonymous-runtime preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnonymousCodexRuntimeProfile {
    /// Every direct entry (file or directory) found in the private Codex home.
    private_home_entries: Vec<String>,
    /// Credential/config entries found that caused the profile to fail.
    violations: Vec<String>,
}

impl AnonymousCodexRuntimeProfile {
    /// Run the fail-closed preflight against only the private Codex home.
    /// `private_codex_home` must be the canonical private home that D29-C
    /// verified (inside the trusted runtime root).
    pub(super) fn preflight(private_codex_home: &Path) -> Self {
        let mut profile = Self {
            private_home_entries: Vec::new(),
            violations: Vec::new(),
        };
        profile.scan_private_home(private_codex_home);
        profile
    }

    /// Fail closed: the runtime may only be spawned anonymously when no
    /// credential/config material is present in its private Codex home.
    pub(super) fn is_anonymous(&self) -> bool {
        self.violations.is_empty()
    }

    pub(super) fn private_home_entries(&self) -> &[String] {
        &self.private_home_entries
    }

    pub(super) fn violations(&self) -> &[String] {
        &self.violations
    }

    fn scan_private_home(&mut self, private_codex_home: &Path) {
        let metadata = match fs::symlink_metadata(private_codex_home) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.violations.push(format!(
                    "private Codex home is unreadable: {private_codex_home:?}: {error}"
                ));
                return;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            self.violations.push(format!(
                "private Codex home is not a real directory: {private_codex_home:?}"
            ));
            return;
        }
        self.scan_directory(private_codex_home, "", true);
    }

    fn scan_directory(&mut self, directory: &Path, relative: &str, is_root: bool) {
        let mut entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) => {
                self.violations.push(format!(
                    "private Codex home entry directory is unreadable: {directory:?}: {error}"
                ));
                return;
            }
        };

        loop {
            let entry = match entries.next() {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    // An iterator error is security-relevant.  Silently
                    // dropping it would turn an incomplete scan into a false
                    // anonymous result.
                    self.violations.push(format!(
                        "private Codex home entry could not be inspected in {directory:?}: {error}"
                    ));
                    continue;
                }
                None => break,
            };

            let name = entry.file_name().to_string_lossy().into_owned();
            let child_relative = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            if is_root {
                self.private_home_entries.push(name.clone());
            }

            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    self.violations.push(format!(
                        "private Codex home entry could not be typed: {child_relative}: {error}"
                    ));
                    continue;
                }
            };
            if file_type.is_symlink() {
                self.violations.push(format!(
                    "reparse/symlink entry is forbidden: {child_relative}"
                ));
                continue;
            }

            if is_forbidden_entry(&name) {
                self.violations.push(format!(
                    "forbidden credential/config entry: {child_relative}"
                ));
            } else if is_root && !is_allowed_entry(&name) {
                self.violations.push(format!(
                    "unclassifiable private home entry: {child_relative}"
                ));
            }

            if !is_root && is_durable_thread_directory(relative) {
                self.violations.push(format!(
                    "durable thread directory is not empty: {child_relative}"
                ));
            }

            if file_type.is_dir() {
                self.scan_directory(&entry.path(), &child_relative, false);
            }
        }
    }
}

fn is_forbidden_entry(name: &str) -> bool {
    let normalized = normalize_entry_name(name);
    FORBIDDEN_PRIVATE_HOME_ENTRIES
        .iter()
        .any(|forbidden| forbidden.eq_ignore_ascii_case(&normalized))
        || normalized.ends_with(".config.toml")
}

fn is_allowed_entry(name: &str) -> bool {
    let normalized = normalize_entry_name(name);
    ALLOWED_PRIVATE_HOME_ENTRIES
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&normalized))
        || is_allowed_sqlite_sidecar(&normalized)
}

fn is_allowed_sqlite_sidecar(name: &str) -> bool {
    [
        "state_5.sqlite",
        "logs_2.sqlite",
        "goals_1.sqlite",
        "memories_1.sqlite",
        "queue_1.sqlite",
        "thread_history_1.sqlite",
    ]
    .iter()
    .any(|base| {
        name.strip_prefix(base)
            .is_some_and(|suffix| suffix == "-wal" || suffix == "-shm")
    })
}

fn is_durable_thread_directory(relative: &str) -> bool {
    matches!(
        normalize_entry_name(relative).as_str(),
        "sessions" | "archived_sessions"
    )
}

/// Windows is case-insensitive; normalize to lower-case for classification.
fn normalize_entry_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

impl fmt::Display for AnonymousCodexRuntimeProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "anonymous={} violations={:?}",
            self.is_anonymous(),
            self.violations
        )
    }
}

/// The child environment block for an anonymous spawn.  This is a *complete*
/// replacement environment: it never inherits the host environment, so
/// credential-bearing host variables cannot reach the child.
pub(super) fn anonymous_child_environment(
    private_codex_home: Option<&Path>,
    marker_entries: &[OsString],
) -> Vec<OsString> {
    let mut entries = Vec::new();
    if let Some(private_codex_home) = private_codex_home {
        let mut entry = OsString::from("CODEX_HOME=");
        entry.push(private_codex_home.as_os_str());
        entries.push(entry);
    }
    entries.extend(marker_entries.iter().cloned());
    entries
}

/// Compile-time fixed app-server overrides for the anonymous official smoke.
///
/// The pinned official binary accepts repeated `--config key=value` arguments
/// through its `CliConfigOverrides` parser.  These values are part of the
/// trusted launch specification, never caller-provided JSON:
/// - file-only CLI auth prevents Auto/Keyring from consulting the OS-global
///   Codex Auth keyring;
/// - file-only MCP OAuth prevents Auto/Keyring MCP credential lookup; and
/// - read-only sandbox prevents `thread/start` from persisting project trust
///   to the user config when a writable cwd is supplied.
pub(super) fn anonymous_codex_launch_arguments() -> Vec<OsString> {
    vec![
        OsString::from("--config"),
        OsString::from(r#"cli_auth_credentials_store="file""#),
        OsString::from("--config"),
        OsString::from(r#"mcp_oauth_credentials_store="file""#),
        OsString::from("--config"),
        OsString::from(r#"sandbox_mode="read-only""#),
    ]
}

/// Audit record of the exact environment the anonymous child would receive.
/// This is the "child exact environment re-report" required by the real smoke:
/// the child environment is fully constructed by Digital Life and never
/// inherits the host environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnonymousChildEnvironmentReport {
    entries: Vec<String>,
}

impl AnonymousChildEnvironmentReport {
    pub(super) fn from_entries(entries: &[OsString]) -> Self {
        Self {
            entries: entries
                .iter()
                .map(|entry| entry.to_string_lossy().into_owned())
                .collect(),
        }
    }

    pub(super) fn contains(&self, needle: &str) -> bool {
        self.entries.iter().any(|entry| entry.contains(needle))
    }

    pub(super) fn entries(&self) -> &[String] {
        &self.entries
    }
}

/// A deterministic before/after inventory of one runtime directory.  The
/// snapshot deliberately records directories as well as files so an empty
/// `sessions/` directory cannot be confused with a missing durable store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeFilesystemSnapshot {
    entries: BTreeMap<String, RuntimeFilesystemEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeFilesystemEntry {
    is_directory: bool,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeFilesystemDelta {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

impl RuntimeFilesystemSnapshot {
    pub(super) fn capture(root: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect snapshot root {root:?}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("snapshot root is not a real directory: {root:?}"));
        }

        let mut entries = BTreeMap::new();
        collect_snapshot_entries(root, "", &mut entries)?;
        Ok(Self { entries })
    }

    pub(super) fn delta_from(&self, before: &Self) -> RuntimeFilesystemDelta {
        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut removed = Vec::new();

        for (path, after_entry) in &self.entries {
            match before.entries.get(path) {
                None => added.push(path.clone()),
                Some(before_entry) if before_entry != after_entry => changed.push(path.clone()),
                Some(_) => {}
            }
        }
        for path in before.entries.keys() {
            if !self.entries.contains_key(path) {
                removed.push(path.clone());
            }
        }

        RuntimeFilesystemDelta {
            added,
            removed,
            changed,
        }
    }
}

impl RuntimeFilesystemDelta {
    pub(super) fn added(&self) -> &[String] {
        &self.added
    }

    pub(super) fn removed(&self) -> &[String] {
        &self.removed
    }

    pub(super) fn changed(&self) -> &[String] {
        &self.changed
    }

    pub(super) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    pub(super) fn durable_paths(&self) -> Vec<String> {
        self.added
            .iter()
            .chain(self.changed.iter())
            .filter(|path| is_durable_thread_artifact(path))
            .cloned()
            .collect()
    }
}

fn collect_snapshot_entries(
    directory: &Path,
    relative: &str,
    entries: &mut BTreeMap<String, RuntimeFilesystemEntry>,
) -> Result<(), String> {
    let mut directory_entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read snapshot directory {directory:?}: {error}"))?;
    loop {
        let entry = match directory_entries.next() {
            Some(Ok(entry)) => entry,
            Some(Err(error)) => {
                return Err(format!(
                    "cannot inspect snapshot directory {directory:?}: {error}"
                ));
            }
            None => break,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_relative = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot type snapshot entry {child_relative}: {error}"))?;
        if file_type.is_symlink() {
            return Err(format!(
                "snapshot contains a reparse/symlink entry: {child_relative}"
            ));
        }
        if file_type.is_dir() {
            entries.insert(
                child_relative.clone(),
                RuntimeFilesystemEntry {
                    is_directory: true,
                    size: 0,
                },
            );
            collect_snapshot_entries(&entry.path(), &child_relative, entries)?;
        } else if file_type.is_file() {
            let size = entry
                .metadata()
                .map_err(|error| format!("cannot stat snapshot entry {child_relative}: {error}"))?
                .len();
            entries.insert(
                child_relative,
                RuntimeFilesystemEntry {
                    is_directory: false,
                    size,
                },
            );
        } else {
            return Err(format!(
                "snapshot contains unsupported entry: {child_relative}"
            ));
        }
    }
    Ok(())
}

/// Returns true for the durable thread/session artifacts that D29-D must not
/// add or mutate during an ephemeral `thread/start`.
pub(super) fn is_durable_thread_artifact(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    normalized.starts_with("sessions/")
        || normalized.starts_with("archived_sessions/")
        || file_name == "session_index.jsonl"
        || file_name == "thread_history_1.sqlite"
        || file_name == "thread_history_1.sqlite-wal"
        || file_name == "thread_history_1.sqlite-shm"
        || (file_name.starts_with("rollout-")
            && (file_name.ends_with(".jsonl") || file_name.ends_with(".jsonl.zst")))
}
