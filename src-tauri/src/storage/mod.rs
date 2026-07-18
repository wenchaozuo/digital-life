mod candidate_extraction;
mod candidate_memory;
mod conversation;
pub(crate) mod deterministic_candidate_extraction;
mod location;
mod memory;
mod memory_management;
mod memory_retrieval;
mod memory_revision;
mod migration;
mod model_profile;
mod vector_sync_outbox;
mod vector_sync_settings;

use std::{
    fmt::Display,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use location::{ConfigSnapshot, StorageLocationResolver};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

pub const DATABASE_FILE_NAME: &str = "digital-life.sqlite3";
static UNIQUE_SUFFIX_COUNTER: AtomicU64 = AtomicU64::new(0);
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "001_initial", include_str!("migrations/001_initial.sql")),
    (
        2,
        "002_memory_core",
        include_str!("migrations/002_memory_core.sql"),
    ),
    (
        3,
        "003_model_profiles",
        include_str!("migrations/003_model_profiles.sql"),
    ),
    (
        4,
        "004_memory_vector_sync_outbox",
        include_str!("migrations/004_memory_vector_sync_outbox.sql"),
    ),
    (
        5,
        "005_memory_vector_sync_settings",
        include_str!("migrations/005_memory_vector_sync_settings.sql"),
    ),
    (
        6,
        "006_conversation_history",
        include_str!("migrations/006_conversation_history.sql"),
    ),
    (
        7,
        "007_memory_revisions",
        include_str!("migrations/007_memory_revisions.sql"),
    ),
    (
        8,
        "008_candidate_memory_storage",
        include_str!("migrations/008_candidate_memory_storage.sql"),
    ),
    (
        9,
        "009_candidate_evidence_uniqueness",
        include_str!("migrations/009_candidate_evidence_uniqueness.sql"),
    ),
    (
        10,
        "010_candidate_extraction_foundation",
        include_str!("migrations/010_candidate_extraction_foundation.sql"),
    ),
    (
        11,
        "011_candidate_extraction_model_profiles",
        include_str!("migrations/011_candidate_extraction_model_profiles.sql"),
    ),
];

#[derive(Clone, Debug, Serialize)]
pub struct StorageError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl StorageError {
    pub(crate) fn new(code: &str, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            recoverable,
        }
    }

    fn database(error: impl Display) -> Self {
        Self::new("DATABASE_ERROR", error.to_string(), true)
    }

    fn not_found(entity: &str) -> Self {
        Self::new("NOT_FOUND", format!("{entity} was not found."), true)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifeIdentityRecord {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub version: i64,
    pub body_id: String,
    pub persona_id: String,
    pub persona_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonaTemplateRecord {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub persona_json: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageLocationInfo {
    pub current_directory: String,
    pub is_default_directory: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageLocationValidation {
    pub current_directory: String,
    pub candidate_directory: String,
    pub is_valid: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageMigrationResult {
    pub success: bool,
    pub old_directory: String,
    pub new_directory: String,
    pub restart_required: bool,
    pub original_database_retained: bool,
    pub failed_stage: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

struct StorageState {
    connection: Connection,
    active_root: PathBuf,
    database_path: PathBuf,
}

pub struct StorageService {
    state: Mutex<StorageState>,
    location: StorageLocationResolver,
    #[cfg(test)]
    candidate_confirmation_panic_failpoint: Mutex<Option<candidate_memory::D4PanicFailpoint>>,
    #[cfg(test)]
    candidate_confirmation_d4_calls: Mutex<Vec<(String, String)>>,
    #[cfg(test)]
    candidate_confirmation_recovery_reads: AtomicU64,
}

impl StorageService {
    pub fn initialize(app: &AppHandle) -> Result<Self, StorageError> {
        let default_root = app.path().app_data_dir().map_err(StorageError::database)?;
        let project_root = std::env::current_dir().ok();
        Self::initialize_with_roots(default_root, project_root)
    }

    pub(crate) fn initialize_with_roots(
        default_root: PathBuf,
        project_root: Option<PathBuf>,
    ) -> Result<Self, StorageError> {
        let location = StorageLocationResolver::new(default_root, project_root);
        let active_root = location.resolve_active_root()?;
        fs::create_dir_all(&active_root).map_err(StorageError::database)?;
        let database_path = active_root.join(DATABASE_FILE_NAME);
        let connection = Self::open_connection(&database_path)?;

        Ok(Self {
            state: Mutex::new(StorageState {
                connection,
                active_root,
                database_path,
            }),
            location,
            #[cfg(test)]
            candidate_confirmation_panic_failpoint: Mutex::new(None),
            #[cfg(test)]
            candidate_confirmation_d4_calls: Mutex::new(Vec::new()),
            #[cfg(test)]
            candidate_confirmation_recovery_reads: AtomicU64::new(0),
        })
    }

    fn open_connection(database_path: &Path) -> Result<Connection, StorageError> {
        let mut connection = Connection::open(database_path).map_err(StorageError::database)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(StorageError::database)?;
        Self::migrate_schema(&mut connection)?;
        Ok(connection)
    }

    fn migrate_schema(connection: &mut Connection) -> Result<(), StorageError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .map_err(StorageError::database)?;

        for (version, name, sql) in MIGRATIONS {
            let applied: Option<i64> = connection
                .query_row(
                    "SELECT version FROM schema_migration WHERE version = ?1",
                    params![version],
                    |row| row.get(0),
                )
                .optional()
                .map_err(StorageError::database)?;

            if applied.is_none() {
                let transaction = connection.transaction().map_err(StorageError::database)?;
                transaction
                    .execute_batch(sql)
                    .map_err(StorageError::database)?;
                transaction
                    .execute(
                        "INSERT INTO schema_migration (version, name, applied_at)
                         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                        params![version, name],
                    )
                    .map_err(StorageError::database)?;
                transaction.commit().map_err(StorageError::database)?;
            }
        }

        Ok(())
    }

    fn state(&self) -> Result<MutexGuard<'_, StorageState>, StorageError> {
        self.state.lock().map_err(StorageError::database)
    }

    pub fn location_info(&self) -> Result<StorageLocationInfo, StorageError> {
        let state = self.state()?;
        Ok(StorageLocationInfo {
            current_directory: path_string(&state.active_root),
            is_default_directory: state.active_root == self.location.default_root(),
        })
    }

    /// Internal authoritative data-root accessor. The path is never serialized
    /// by vector-index runtime APIs.
    pub(crate) fn active_data_root(&self) -> Result<PathBuf, StorageError> {
        Ok(self.state()?.active_root.clone())
    }

    pub fn validate_location(&self, candidate: &str) -> StorageLocationValidation {
        let current_root = match self.state() {
            Ok(state) => state.active_root.clone(),
            Err(error) => {
                return StorageLocationValidation {
                    current_directory: String::new(),
                    candidate_directory: candidate.to_string(),
                    is_valid: false,
                    error_code: Some(error.code),
                    error_message: Some(error.message),
                }
            }
        };

        match self.location.validate_candidate(candidate, &current_root) {
            Ok(validated) => StorageLocationValidation {
                current_directory: path_string(&current_root),
                candidate_directory: path_string(&validated),
                is_valid: true,
                error_code: None,
                error_message: None,
            },
            Err(error) => StorageLocationValidation {
                current_directory: path_string(&current_root),
                candidate_directory: candidate.to_string(),
                is_valid: false,
                error_code: Some(error.code),
                error_message: Some(error.message),
            },
        }
    }

    pub fn migrate_location(&self, candidate: &str) -> StorageMigrationResult {
        let mut state = match self.state() {
            Ok(state) => state,
            Err(error) => return migration_failure("acquire_lock", "", candidate, error),
        };
        let old_root = state.active_root.clone();
        let target_root = match self.location.validate_candidate(candidate, &old_root) {
            Ok(path) => path,
            Err(error) => {
                return migration_failure(
                    "validate_candidate",
                    &path_string(&old_root),
                    candidate,
                    error,
                )
            }
        };
        let old_directory = path_string(&old_root);
        let new_directory = path_string(&target_root);
        let final_database = target_root.join(DATABASE_FILE_NAME);
        let temporary_database = target_root.join(format!(
            ".{DATABASE_FILE_NAME}.{}.migration",
            unique_suffix()
        ));

        if final_database.exists() {
            return migration_failure(
                "prepare_target",
                &old_directory,
                &new_directory,
                StorageError::new(
                    "MIGRATION_TARGET_EXISTS",
                    "The target directory already contains a digital-life.sqlite3 database.",
                    true,
                ),
            );
        }

        let current_life_id = match Self::current_life_id(&state.connection) {
            Ok(Some(id)) => id,
            Ok(None) => {
                return migration_failure(
                    "read_current_life",
                    &old_directory,
                    &new_directory,
                    StorageError::new(
                        "MIGRATION_CURRENT_LIFE_MISSING",
                        "The source database has no current_life_id to verify.",
                        false,
                    ),
                )
            }
            Err(error) => {
                return migration_failure(
                    "read_current_life",
                    &old_directory,
                    &new_directory,
                    error,
                )
            }
        };
        let schema_version = match Self::schema_version(&state.connection) {
            Ok(version) => version,
            Err(error) => {
                return migration_failure(
                    "read_schema_version",
                    &old_directory,
                    &new_directory,
                    error,
                )
            }
        };
        let config_snapshot = match self.location.capture_config() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return migration_failure("snapshot_config", &old_directory, &new_directory, error)
            }
        };

        if let Err(error) = state
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|error| {
                StorageError::new(
                    "MIGRATION_CHECKPOINT_FAILED",
                    format!("Cannot checkpoint the source database WAL: {error}"),
                    true,
                )
            })
        {
            return migration_failure("wal_checkpoint", &old_directory, &new_directory, error);
        }

        if let Err(error) = migration::backup_and_verify(
            &state.connection,
            &temporary_database,
            schema_version,
            &current_life_id,
        ) {
            return migration_failure("backup_and_verify", &old_directory, &new_directory, error);
        }

        if let Err(error) =
            migration::activate_temporary_database(&temporary_database, &final_database)
        {
            let _ = fs::remove_file(&temporary_database);
            return migration_failure("activate_database", &old_directory, &new_directory, error);
        }

        if let Err(error) = self.location.write_active_root(&target_root) {
            let error = match remove_database_artifacts(&final_database) {
                Ok(()) => error,
                Err(cleanup_error) => StorageError::new(
                    "MIGRATION_CLEANUP_FAILED",
                    format!(
                        "Configuration update failed: {} Cleanup also failed: {}",
                        error.message, cleanup_error.message
                    ),
                    false,
                ),
            };
            return migration_failure(
                "write_location_config",
                &old_directory,
                &new_directory,
                error,
            );
        }

        let target_connection =
            match Self::open_and_verify_existing(&final_database, schema_version, &current_life_id)
            {
                Ok(connection) => connection,
                Err(error) => {
                    let error = match rollback_after_activation(
                        &self.location,
                        &config_snapshot,
                        &final_database,
                    ) {
                        Ok(()) => error,
                        Err(rollback_error) => StorageError::new(
                            "MIGRATION_ROLLBACK_FAILED",
                            format!(
                                "Target reopen failed: {} Rollback also failed: {}",
                                error.message, rollback_error.message
                            ),
                            false,
                        ),
                    };
                    return migration_failure(
                        "reopen_target",
                        &old_directory,
                        &new_directory,
                        error,
                    );
                }
            };

        state.connection = target_connection;
        state.active_root = target_root;
        state.database_path = final_database;

        StorageMigrationResult {
            success: true,
            old_directory,
            new_directory,
            restart_required: false,
            original_database_retained: true,
            failed_stage: None,
            error_code: None,
            error_message: None,
        }
    }

    fn open_and_verify_existing(
        database_path: &Path,
        expected_schema_version: i64,
        expected_life_id: &str,
    ) -> Result<Connection, StorageError> {
        let connection = Connection::open(database_path).map_err(|error| {
            StorageError::new(
                "MIGRATION_REOPEN_FAILED",
                format!("Cannot reopen the migrated database: {error}"),
                true,
            )
        })?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(|error| {
                StorageError::new(
                    "MIGRATION_REOPEN_PRAGMA_FAILED",
                    format!("Cannot configure the migrated database: {error}"),
                    true,
                )
            })?;
        migration::verify_database(&connection, expected_schema_version, expected_life_id)?;
        Ok(connection)
    }

    fn schema_version(connection: &Connection) -> Result<i64, StorageError> {
        connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
                [],
                |row| row.get(0),
            )
            .map_err(StorageError::database)
    }

    fn current_life_id(connection: &Connection) -> Result<Option<String>, StorageError> {
        connection
            .query_row(
                "SELECT current_life_id FROM app_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::database)
    }

    pub fn save_persona(&self, persona: PersonaTemplateRecord) -> Result<(), StorageError> {
        let state = self.state()?;
        state
            .connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    version = excluded.version,
                    persona_json = excluded.persona_json",
                params![
                    persona.id,
                    persona.name,
                    persona.version,
                    persona.persona_json
                ],
            )
            .map_err(StorageError::database)?;
        Ok(())
    }

    pub fn get_persona(&self, id: &str) -> Result<Option<PersonaTemplateRecord>, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT id, name, version, persona_json FROM persona_template WHERE id = ?1",
                params![id],
                |row| {
                    Ok(PersonaTemplateRecord {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        version: row.get(2)?,
                        persona_json: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::database)
    }

    pub fn save_life(&self, life: LifeIdentityRecord) -> Result<(), StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction()
            .map_err(StorageError::database)?;
        transaction
            .execute(
                "INSERT INTO life_identity
                    (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    version = excluded.version,
                    body_id = excluded.body_id,
                    persona_id = excluded.persona_id,
                    persona_version = excluded.persona_version",
                params![
                    life.id,
                    life.name,
                    life.created_at,
                    life.version,
                    life.body_id,
                    life.persona_id,
                    life.persona_version
                ],
            )
            .map_err(StorageError::database)?;
        transaction
            .execute(
                "INSERT INTO app_state (singleton, current_life_id) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET current_life_id = excluded.current_life_id",
                params![life.id],
            )
            .map_err(StorageError::database)?;
        transaction.commit().map_err(StorageError::database)?;
        Ok(())
    }

    pub fn get_life(&self, id: &str) -> Result<Option<LifeIdentityRecord>, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT id, name, created_at, version, body_id, persona_id, persona_version
                 FROM life_identity WHERE id = ?1",
                params![id],
                Self::read_life,
            )
            .optional()
            .map_err(StorageError::database)
    }

    pub fn get_current_life(&self) -> Result<Option<LifeIdentityRecord>, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT life.id, life.name, life.created_at, life.version, life.body_id,
                        life.persona_id, life.persona_version
                 FROM app_state state
                 INNER JOIN life_identity life ON life.id = state.current_life_id
                 WHERE state.singleton = 1",
                [],
                Self::read_life,
            )
            .optional()
            .map_err(StorageError::database)
    }

    pub fn update_life_base_info(
        &self,
        id: &str,
        name: &str,
        body_id: &str,
    ) -> Result<LifeIdentityRecord, StorageError> {
        let state = self.state()?;
        let updated = state
            .connection
            .execute(
                "UPDATE life_identity
                 SET name = ?2, body_id = ?3, version = version + 1
                 WHERE id = ?1",
                params![id, name, body_id],
            )
            .map_err(StorageError::database)?;

        if updated == 0 {
            return Err(StorageError::not_found("Life identity"));
        }

        state
            .connection
            .query_row(
                "SELECT id, name, created_at, version, body_id, persona_id, persona_version
                 FROM life_identity WHERE id = ?1",
                params![id],
                Self::read_life,
            )
            .map_err(StorageError::database)
    }

    fn read_life(row: &rusqlite::Row<'_>) -> rusqlite::Result<LifeIdentityRecord> {
        Ok(LifeIdentityRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            created_at: row.get(2)?,
            version: row.get(3)?,
            body_id: row.get(4)?,
            persona_id: row.get(5)?,
            persona_version: row.get(6)?,
        })
    }
}

fn rollback_after_activation(
    location: &StorageLocationResolver,
    config_snapshot: &ConfigSnapshot,
    target_database: &Path,
) -> Result<(), StorageError> {
    location.restore_config(config_snapshot)?;
    remove_database_artifacts(target_database)
}

fn remove_database_artifacts(database_path: &Path) -> Result<(), StorageError> {
    let mut paths = vec![database_path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut value = database_path.as_os_str().to_os_string();
        value.push(suffix);
        paths.push(PathBuf::from(value));
    }

    for path in paths {
        if path.exists() {
            fs::remove_file(&path).map_err(|error| {
                StorageError::new(
                    "MIGRATION_CLEANUP_FAILED",
                    format!(
                        "Cannot remove incomplete migration artifact {}: {error}",
                        path.display()
                    ),
                    false,
                )
            })?;
        }
    }
    Ok(())
}

fn migration_failure(
    stage: &str,
    old_directory: &str,
    new_directory: &str,
    error: StorageError,
) -> StorageMigrationResult {
    StorageMigrationResult {
        success: false,
        old_directory: old_directory.to_string(),
        new_directory: new_directory.to_string(),
        restart_required: false,
        original_database_retained: true,
        failed_stage: Some(stage.to_string()),
        error_code: Some(error.code),
        error_message: Some(error.message),
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(crate) fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = UNIQUE_SUFFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}", std::process::id())
}

#[tauri::command]
pub fn initialize_storage(_storage: State<'_, StorageService>) -> Result<(), StorageError> {
    Ok(())
}

#[tauri::command]
pub fn get_storage_location(
    storage: State<'_, StorageService>,
) -> Result<StorageLocationInfo, StorageError> {
    storage.location_info()
}

#[tauri::command]
pub fn validate_storage_location(
    storage: State<'_, StorageService>,
    candidate_directory: String,
) -> StorageLocationValidation {
    storage.validate_location(&candidate_directory)
}

#[tauri::command]
pub fn migrate_storage_location(
    storage: State<'_, StorageService>,
    candidate_directory: String,
) -> StorageMigrationResult {
    storage.migrate_location(&candidate_directory)
}

#[tauri::command]
pub fn save_life_identity(
    storage: State<'_, StorageService>,
    identity: LifeIdentityRecord,
) -> Result<(), StorageError> {
    storage.save_life(identity)
}

#[tauri::command]
pub fn get_current_life_identity(
    storage: State<'_, StorageService>,
) -> Result<Option<LifeIdentityRecord>, StorageError> {
    storage.get_current_life()
}

#[tauri::command]
pub fn get_life_identity(
    storage: State<'_, StorageService>,
    id: String,
) -> Result<Option<LifeIdentityRecord>, StorageError> {
    storage.get_life(&id)
}

#[tauri::command]
pub fn update_life_identity_base_info(
    storage: State<'_, StorageService>,
    id: String,
    name: String,
    body_id: String,
) -> Result<LifeIdentityRecord, StorageError> {
    storage.update_life_base_info(&id, &name, &body_id)
}

#[tauri::command]
pub fn save_persona_template(
    storage: State<'_, StorageService>,
    persona: PersonaTemplateRecord,
) -> Result<(), StorageError> {
    storage.save_persona(persona)
}

#[tauri::command]
pub fn get_persona_template(
    storage: State<'_, StorageService>,
    id: String,
) -> Result<Option<PersonaTemplateRecord>, StorageError> {
    storage.get_persona(&id)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rusqlite::params;

    /// Minimal D-5A verification view for assertions about D-4 idempotency. It
    /// exposes counts only; no content, paths, vectors, or credentials leave the
    /// temporary test database.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct CandidateConfirmationArtifactCounts {
        pub memories: i64,
        pub revisions: i64,
        pub outbox_rows: i64,
        pub confirmation_audits: i64,
    }

    pub(crate) fn candidate_confirmation_artifact_counts(
        service: &StorageService,
        life_id: &str,
        candidate_id: &str,
        memory_id: &str,
    ) -> CandidateConfirmationArtifactCounts {
        let state = service.state().unwrap();
        let connection = &state.connection;
        let count = |sql: &str, values: &[&dyn rusqlite::ToSql]| {
            connection.query_row(sql, values, |row| row.get(0)).unwrap()
        };
        CandidateConfirmationArtifactCounts {
            memories: count(
                "SELECT COUNT(*) FROM memory_record WHERE life_id = ?1 AND id = ?2",
                &[&life_id, &memory_id],
            ),
            revisions: count(
                "SELECT COUNT(*) FROM memory_revision WHERE life_id = ?1 AND memory_id = ?2",
                &[&life_id, &memory_id],
            ),
            outbox_rows: count(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox WHERE life_id = ?1 AND memory_id = ?2",
                &[&life_id, &memory_id],
            ),
            confirmation_audits: count(
                "SELECT COUNT(*) FROM candidate_memory_audit
                 WHERE life_id = ?1 AND candidate_id = ?2 AND action = 'candidate_confirmed'",
                &[&life_id, &candidate_id],
            ),
        }
    }

    /// Test-only fixture: inserts a confirmed memory directly into `memory_record`
    /// and creates the initial `memory_revision` snapshot.
    ///
    /// This bypasses the deprecated `confirm()` path which now returns
    /// `CANDIDATE_CONFIRMATION_UNAVAILABLE`. Tests that need a confirmed memory
    /// for revision, outbox, retrieval, or management testing should use this
    /// fixture instead of calling `create_candidate` + `confirm`.
    ///
    /// Does NOT create an outbox entry unless `enqueue_outbox` is true.
    /// Does NOT call LanceDB, Embedding, or any model.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_confirmed_memory_fixture(
        service: &StorageService,
        life_id: &str,
        kind: &str,
        content: &str,
        summary: Option<&str>,
        importance: f64,
        confidence: f64,
        is_sensitive: bool,
        enqueue_outbox: bool,
    ) -> crate::memory::MemoryRecord {
        use crate::memory::{MemoryKind, MemorySourceType, MemoryStatus};

        let id = format!("confirmed-fixture-{}", unique_suffix());
        let now = "2026-07-13T00:00:00.000Z";
        let state = service.state().unwrap();
        let connection = &state.connection;

        connection
            .execute(
                "INSERT INTO memory_record (
                    id, life_id, kind, status, content, summary, source_type, source_ref,
                    source_created_at, importance, confidence, is_sensitive, created_at,
                    updated_at, confirmed_at, revision
                 ) VALUES (
                    ?1, ?2, ?3, 'confirmed', ?4, ?5, 'manual', 'fixture',
                    ?6, ?7, ?8, ?9, ?6, ?6, ?6, 1
                 )",
                params![
                    id,
                    life_id,
                    kind,
                    content,
                    summary,
                    now,
                    importance,
                    confidence,
                    is_sensitive as i32,
                ],
            )
            .unwrap();

        // Create the initial confirmed revision snapshot.
        connection
            .execute(
                "INSERT INTO memory_revision (
                    id, life_id, memory_id, revision, kind, content, summary,
                    is_sensitive, change_type, created_at
                 ) VALUES (
                    ?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, 'confirmed', ?8
                 )",
                params![
                    format!("memory-revision-{id}-1"),
                    life_id,
                    id,
                    kind,
                    content,
                    summary,
                    is_sensitive as i32,
                    now,
                ],
            )
            .unwrap();

        if enqueue_outbox {
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox (
                        life_id, memory_id, desired_action, state,
                        attempt_count, next_attempt_at, created_at, updated_at
                     ) VALUES (
                        ?1, ?2, 'upsert', 'pending', 0, NULL, ?3, ?3
                     )",
                    params![life_id, id, now],
                )
                .unwrap();
        }

        crate::memory::MemoryRecord {
            id,
            life_id: life_id.to_string(),
            kind: MemoryKind::parse(kind).unwrap(),
            status: MemoryStatus::Confirmed,
            content: content.to_string(),
            summary: summary.map(str::to_string),
            source_type: MemorySourceType::Manual,
            source_ref: Some("fixture".into()),
            source_created_at: now.to_string(),
            importance,
            confidence,
            is_sensitive,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            confirmed_at: Some(now.to_string()),
        }
    }

    pub(crate) fn insert_conversation_with_message(
        service: &StorageService,
        life_id: &str,
        suffix: &str,
    ) {
        use rusqlite::params;
        let state = service.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation (
                    id, life_id, title, revision, created_at, updated_at, last_message_at
                 ) VALUES (?1, ?2, 'Conv', 0, ?3, ?3, ?3)",
                params![
                    format!("conv-{suffix}"),
                    life_id,
                    "2026-07-14T00:00:00.000Z"
                ],
            )
            .unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation_message (
                    id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at
                 ) VALUES (?1, ?2, ?3, 'turn-1', 'user', 'Msg', 1, ?4)",
                params![
                    format!("msg-{suffix}"),
                    format!("conv-{suffix}"),
                    life_id,
                    "2026-07-14T00:00:00.000Z"
                ],
            )
            .unwrap();
    }

    pub(crate) fn count_table(service: &StorageService, table: &str) -> i64 {
        let state = service.state().unwrap();
        state
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    mod extraction_error_factory_visibility {
        use std::{future::Future, pin::Pin};

        use futures::executor::block_on;

        use super::super::candidate_extraction::{
            CandidateExtractionBatch, CandidateExtractionRequest, CandidateExtractor,
            ExtractionError, ExtractorDescriptor,
        };

        #[derive(Clone, Copy)]
        enum FailureKind {
            ProviderUnavailable,
            ProviderNonrecoverable,
            Contract,
        }

        struct SiblingExtractor {
            descriptor: ExtractorDescriptor,
            failure: FailureKind,
        }

        impl CandidateExtractor for SiblingExtractor {
            fn descriptor(&self) -> &ExtractorDescriptor {
                &self.descriptor
            }

            fn extract<'a>(
                &'a self,
                _request: CandidateExtractionRequest,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<CandidateExtractionBatch, ExtractionError>>
                        + Send
                        + 'a,
                >,
            > {
                let error = match self.failure {
                    FailureKind::ProviderUnavailable => ExtractionError::provider_unavailable(),
                    FailureKind::ProviderNonrecoverable => {
                        ExtractionError::provider_nonrecoverable()
                    }
                    FailureKind::Contract => ExtractionError::contract_failure(),
                };
                Box::pin(async move { Err(error) })
            }
        }

        fn request() -> CandidateExtractionRequest {
            CandidateExtractionRequest {
                run_id: "factory-visibility-run".into(),
                attempt_sequence: 1,
                life_id: "factory-visibility-life".into(),
                conversation_id: "factory-visibility-conversation".into(),
                conversation_revision: 1,
                policy_version: "candidate-extraction-safety-v1".into(),
                snapshot_hash: "0".repeat(64),
                messages: Vec::new(),
            }
        }

        #[test]
        fn sibling_candidate_extractor_can_call_all_restricted_factories() {
            for (failure, expected_code) in [
                (
                    FailureKind::ProviderUnavailable,
                    "CANDIDATE_EXTRACTION_EXTRACTOR_UNAVAILABLE",
                ),
                (
                    FailureKind::ProviderNonrecoverable,
                    "CANDIDATE_EXTRACTION_PROVIDER_ERROR",
                ),
                (
                    FailureKind::Contract,
                    "CANDIDATE_EXTRACTION_EXTRACTOR_CONTRACT_FAILURE",
                ),
            ] {
                let extractor = SiblingExtractor {
                    descriptor: ExtractorDescriptor {
                        extractor_id: "factory-visibility-extractor".into(),
                        extractor_version: "1".into(),
                    },
                    failure,
                };
                assert_eq!(extractor.descriptor().extractor_version, "1");
                let error = block_on(extractor.extract(request())).unwrap_err();
                assert_eq!(error.code(), expected_code);
            }
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-storage-{name}-{}", unique_suffix()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unique_suffix_is_distinct_for_parallel_storage_fixtures() {
        let barrier = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    unique_suffix()
                })
            })
            .collect();
        let suffixes: HashSet<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(suffixes.len(), 16);
    }

    fn seeded_service(root: &Path) -> StorageService {
        let default_root = root.join("default");
        let project_root = root.join("project");
        fs::create_dir_all(&project_root).unwrap();
        let service =
            StorageService::initialize_with_roots(default_root, Some(project_root)).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona-1".into(),
                name: "Custom Persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona-1\"}".into(),
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-1".into(),
                name: "Digital Life".into(),
                created_at: "2026-07-11T00:00:00.000Z".into(),
                version: 1,
                body_id: "default-png".into(),
                persona_id: "persona-1".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    #[test]
    fn migration_preserves_current_life_id() {
        let root = TestRoot::new("migration-success");
        let service = seeded_service(&root.0);
        let original_database = root.0.join("default").join(DATABASE_FILE_NAME);
        let target = root.0.join("custom");

        let result = service.migrate_location(target.to_str().unwrap());

        assert!(result.success, "{:?}", result.error_message);
        assert_eq!(service.get_current_life().unwrap().unwrap().id, "life-1");
        assert!(original_database.exists());
        assert!(target.join(DATABASE_FILE_NAME).exists());
        assert!(root
            .0
            .join("default")
            .join(location::LOCATION_CONFIG_FILE_NAME)
            .exists());
    }

    #[test]
    fn migration_failure_keeps_source_and_config_unchanged() {
        let root = TestRoot::new("migration-failure");
        let service = seeded_service(&root.0);
        let default_root = root.0.join("default");
        let original_database = default_root.join(DATABASE_FILE_NAME);
        let config_path = default_root.join(location::LOCATION_CONFIG_FILE_NAME);
        let target = root.0.join("occupied");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join(DATABASE_FILE_NAME), b"occupied").unwrap();

        let result = service.migrate_location(target.to_str().unwrap());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some("MIGRATION_TARGET_EXISTS")
        );
        assert!(!config_path.exists());
        assert!(original_database.exists());
        assert_eq!(service.get_current_life().unwrap().unwrap().id, "life-1");
    }
}
