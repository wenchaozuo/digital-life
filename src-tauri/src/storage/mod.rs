mod candidate_extraction;
mod candidate_memory;
mod connection;
mod conversation;
pub(crate) mod deterministic_candidate_extraction;
mod llm_candidate_extraction;
mod location;
mod memory;
mod memory_management;
mod memory_retrieval;
mod memory_revision;
mod migration;
mod model_profile;
mod upgrade_coordinator;
pub(crate) mod upgrade_gate;
mod vector_sync_outbox;
mod vector_sync_settings;
mod writer_fence_manifest;

#[cfg(test)]
pub(crate) use connection::open_authorized_test_connection;

pub(crate) use llm_candidate_extraction::{
    trigger_candidate_extraction, LlmCandidateExtractionCoordinator,
};
pub(crate) use vector_sync_outbox::{
    FencedAttemptReservation, FencedAttemptToken, FencedFailureDecision,
    FencedFailureFinalizeResult, FencedFinalizeResult, FencedVectorSyncClaim,
    MAX_VECTOR_SYNC_ATTEMPTS,
};

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
    (
        12,
        "012_fenced_vector_sync",
        include_str!("migrations/012_fenced_vector_sync.sql"),
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

    pub(crate) fn connection_open_failed() -> Self {
        Self::new(
            "CONNECTION_OPEN_FAILED",
            "The storage database could not be opened.",
            true,
        )
    }

    pub(crate) fn writer_capability_registration_failed() -> Self {
        Self::new(
            "WRITER_CAPABILITY_REGISTRATION_FAILED",
            "The storage connection could not register its writer capability.",
            false,
        )
    }

    pub(crate) fn connection_configuration_failed() -> Self {
        Self::new(
            "CONNECTION_CONFIGURATION_FAILED",
            "The storage connection could not be configured.",
            true,
        )
    }

    pub(crate) fn schema_version_read_failed() -> Self {
        Self::new(
            "SCHEMA_VERSION_READ_FAILED",
            "The storage schema version could not be read.",
            false,
        )
    }

    pub(crate) fn database_version_too_new() -> Self {
        Self::new(
            "DATABASE_VERSION_TOO_NEW",
            "The storage database was created by a newer application version.",
            false,
        )
    }

    pub(super) fn legacy_writer_detected() -> Self {
        Self::new(
            "LEGACY_WRITER_DETECTED",
            "A legacy writer still has the storage resources open.",
            true,
        )
    }

    pub(super) fn upgrade_exclusive_gate_unavailable() -> Self {
        Self::new(
            "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE",
            "The storage upgrade exclusive gate is unavailable.",
            true,
        )
    }

    pub(super) fn upgrade_process_inspection_failed() -> Self {
        Self::new(
            "UPGRADE_PROCESS_INSPECTION_FAILED",
            "The storage upgrade process inspection could not be completed.",
            true,
        )
    }

    pub(super) fn upgrade_quiescence_not_reached() -> Self {
        Self::new(
            "UPGRADE_QUIESCENCE_NOT_REACHED",
            "The storage upgrade could not obtain a quiet write window.",
            true,
        )
    }

    pub(super) fn migration_transaction_failed() -> Self {
        Self::new(
            "MIGRATION_TRANSACTION_FAILED",
            "The storage schema migration transaction could not be completed.",
            true,
        )
    }

    pub(super) fn migration_version_invariant_failed() -> Self {
        Self::new(
            "MIGRATION_VERSION_INVARIANT_FAILED",
            "The storage schema migration version invariant was not satisfied.",
            false,
        )
    }

    pub(super) fn migration_post_commit_verification_failed() -> Self {
        Self::new(
            "MIGRATION_POST_COMMIT_VERIFICATION_FAILED",
            "The committed storage schema upgrade could not be verified.",
            false,
        )
    }

    pub(super) fn attempt_claim_identity_schema_invalid() -> Self {
        Self::new(
            "ATTEMPT_CLAIM_IDENTITY_SCHEMA_INVALID",
            "The database attempt claim identity schema is invalid.",
            false,
        )
    }

    pub(super) fn writer_fence_manifest_missing() -> Self {
        Self::new(
            "WRITER_FENCE_MANIFEST_MISSING",
            "The required database writer fence manifest is missing.",
            false,
        )
    }

    pub(super) fn writer_fence_manifest_mismatch() -> Self {
        Self::new(
            "WRITER_FENCE_MANIFEST_MISMATCH",
            "The database writer fence manifest does not match this application.",
            false,
        )
    }

    pub(super) fn incompatible_database_writer() -> Self {
        Self::new(
            "INCOMPATIBLE_DATABASE_WRITER",
            "The database write was rejected because the writer is incompatible.",
            false,
        )
    }

    pub(super) fn unsupported_platform() -> Self {
        Self::new(
            "UNSUPPORTED_PLATFORM",
            "The storage upgrade coordinator is only available on Windows.",
            false,
        )
    }

    pub(super) fn from_upgrade_gate_error(error: upgrade_gate::UpgradeGateError) -> Self {
        match error {
            upgrade_gate::UpgradeGateError::UnsupportedPlatform => Self::unsupported_platform(),
            upgrade_gate::UpgradeGateError::UpgradeMutexNameDerivationFailed
            | upgrade_gate::UpgradeGateError::UpgradeExclusiveGateUnavailable => {
                Self::upgrade_exclusive_gate_unavailable()
            }
            upgrade_gate::UpgradeGateError::RestartManagerSessionFailed
            | upgrade_gate::UpgradeGateError::RestartManagerRegistrationFailed
            | upgrade_gate::UpgradeGateError::RestartManagerQueryFailed
            | upgrade_gate::UpgradeGateError::ProcessIdentityReadFailed
            | upgrade_gate::UpgradeGateError::ProcessVerificationFailed => {
                Self::upgrade_process_inspection_failed()
            }
            upgrade_gate::UpgradeGateError::LegacyWriterDetected => Self::legacy_writer_detected(),
        }
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

pub(crate) struct OutboxSyncHealthAggregate {
    pub pending_count: usize,
    pub retry_wait_count: usize,
    pub blocked_count: usize,
    pub processing_count: usize,
    pub failed_count: usize,
    pub migration_isolated_count: usize,
    pub expired_processing_count: usize,
    pub provider_result_unknown_count: usize,
    pub internal_invariant_count: usize,
    pub attempts_at_limit_count: usize,
    pub attempts_over_limit_count: usize,
    pub invalid_attempt_identity_count: usize,
    pub expired_processing_unmarked_count: usize,
    pub expired_processing_marked_count: usize,
    pub legacy_processing_unproven_count: usize,
    pub delete_replay_not_eligible_count: usize,
    pub attempts_at_limit_processing_count: usize,
    pub attempts_at_limit_blocked_count: usize,
    pub oldest_pending_epoch_ms: Option<i64>,
    pub oldest_retry_wait_epoch_ms: Option<i64>,
    pub oldest_blocked_epoch_ms: Option<i64>,
    pub sqlite_generation_item_count: usize,
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
        // The Windows Global mutex derives its identity from the authoritative
        // database path and rejects relative paths. Resolve the newly ensured
        // directory before deriving that path, while no SQLite handle exists.
        let active_root =
            fs::canonicalize(&active_root).map_err(|_| StorageError::connection_open_failed())?;
        let database_path = active_root.join(DATABASE_FILE_NAME);
        let connection = Self::open_connection(&database_path)?;

        let service = Self {
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
        };
        #[cfg(test)]
        upgrade_coordinator::record_storage_service_publish_for_test();
        Ok(service)
    }

    fn open_connection(database_path: &Path) -> Result<Connection, StorageError> {
        upgrade_coordinator::open_coordinated_storage_connection(database_path)
    }

    fn state(&self) -> Result<MutexGuard<'_, StorageState>, StorageError> {
        self.state.lock().map_err(StorageError::database)
    }

    pub(crate) fn inspect_outbox_sync_health(
        &self,
        generation_id: &str,
        max_attempts: u32,
        snapshot_now_millis: i64,
    ) -> Result<OutboxSyncHealthAggregate, StorageError> {
        let state = self.state()?;
        // Use strftime to convert the millis epoch to an ISO-8601 string for text comparison
        let (
            pending,
            rwait,
            blocked,
            processing,
            failed,
            expired,
            unknown,
            inv,
            att_limit,
            att_over_limit,
            invalid_identity,
            expired_unmarked,
            expired_marked,
            legacy_unproven,
            delete_not_eligible,
            att_limit_processing,
            att_limit_blocked,
            oldest_pending,
            oldest_retry,
            oldest_blocked,
        ) = state
            .connection
            .query_row(
                "SELECT
                COALESCE(SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='retry_wait' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='blocked' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='processing' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch') THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='blocked' AND last_error_code='PROVIDER_RESULT_UNKNOWN' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='blocked' AND last_error_code='INTERNAL_INVARIANT' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN attempt_count >= ?2 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN attempt_count > ?2 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN attempt_count < 0 OR attempt_count > ?2 OR fenced_claim_epoch < 0 OR last_marked_claim_epoch < 0 OR last_marked_claim_epoch > fenced_claim_epoch OR (last_marked_claim_epoch > 0 AND attempt_count = 0) OR (attempt_count > 0 AND claimed_generation_id IS NULL) THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch') AND fenced_claim_epoch > last_marked_claim_epoch THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch') AND fenced_claim_epoch = last_marked_claim_epoch AND fenced_claim_epoch > 0 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN state='processing' AND fenced_claim_epoch = 0 AND last_marked_claim_epoch = 0 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN desired_action='delete' AND (last_send_disposition IS NOT NULL OR attempt_count >= ?2 OR state NOT IN ('pending','retry_wait')) THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN attempt_count = ?2 AND state='processing' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN attempt_count = ?2 AND state='blocked' THEN 1 ELSE 0 END), 0),
                MIN(CASE WHEN state='pending' THEN ROUND((julianday(created_at) - 2440587.5) * 86400000) ELSE NULL END),
                MIN(CASE WHEN state='retry_wait' THEN ROUND((julianday(updated_at) - 2440587.5) * 86400000) ELSE NULL END),
                MIN(CASE WHEN state='blocked' THEN ROUND((julianday(updated_at) - 2440587.5) * 86400000) ELSE NULL END)
             FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL",
                rusqlite::params![snapshot_now_millis as f64, max_attempts],
                |row| Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                    row.get::<_, i64>(3)? as usize,
                    row.get::<_, i64>(4)? as usize,
                    row.get::<_, i64>(5)? as usize,
                    row.get::<_, i64>(6)? as usize,
                    row.get::<_, i64>(7)? as usize,
                    row.get::<_, i64>(8)? as usize,
                    row.get::<_, i64>(9)? as usize,
                    row.get::<_, i64>(10)? as usize,
                    row.get::<_, i64>(11)? as usize,
                    row.get::<_, i64>(12)? as usize,
                    row.get::<_, i64>(13)? as usize,
                    row.get::<_, i64>(14)? as usize,
                    row.get::<_, i64>(15)? as usize,
                    row.get::<_, i64>(16)? as usize,
                    row.get::<_, Option<f64>>(17)?,
                    row.get::<_, Option<f64>>(18)?,
                    row.get::<_, Option<f64>>(19)?,
                )),
            )
            .map_err(|_| {
                StorageError::new(
                    "VECTOR_SYNC_UNAVAILABLE",
                    "Vector sync health query failed.",
                    false,
                )
            })?;

        let migration_isolated_count: usize = state
            .connection
            .query_row(
                "SELECT COALESCE(SUM(CASE WHEN migration_disposition IS NOT NULL THEN 1 ELSE 0 END), 0)
                 FROM memory_vector_sync_outbox",
                [],
                |row| row.get::<_, i64>(0).map(|v| v as usize),
            )
            .map_err(|_| {
                StorageError::new(
                    "VECTOR_SYNC_UNAVAILABLE",
                    "Vector sync health query failed.",
                    false,
                )
            })?;

        let gen_items: usize = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item WHERE generation_id=?1",
                rusqlite::params![generation_id],
                |row| row.get::<_, i64>(0).map(|v| v as usize),
            )
            .map_err(|_| {
                StorageError::new(
                    "VECTOR_SYNC_UNAVAILABLE",
                    "Vector sync health query failed.",
                    false,
                )
            })?;

        Ok(OutboxSyncHealthAggregate {
            pending_count: pending,
            retry_wait_count: rwait,
            blocked_count: blocked,
            processing_count: processing,
            failed_count: failed,
            migration_isolated_count,
            expired_processing_count: expired,
            provider_result_unknown_count: unknown,
            internal_invariant_count: inv,
            attempts_at_limit_count: att_limit,
            attempts_over_limit_count: att_over_limit,
            invalid_attempt_identity_count: invalid_identity,
            expired_processing_unmarked_count: expired_unmarked,
            expired_processing_marked_count: expired_marked,
            legacy_processing_unproven_count: legacy_unproven,
            delete_replay_not_eligible_count: delete_not_eligible,
            attempts_at_limit_processing_count: att_limit_processing,
            attempts_at_limit_blocked_count: att_limit_blocked,
            oldest_pending_epoch_ms: oldest_pending.map(|v| v as i64),
            oldest_retry_wait_epoch_ms: oldest_retry.map(|v| v as i64),
            oldest_blocked_epoch_ms: oldest_blocked.map(|v| v as i64),
            sqlite_generation_item_count: gen_items,
        })
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
        let connection = Self::open_connection(database_path)?;
        migration::verify_database(&connection, expected_schema_version, expected_life_id)?;
        Ok(connection)
    }

    fn schema_version(connection: &Connection) -> Result<i64, StorageError> {
        connection::read_schema_version(connection)
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

    /// Stable identity of one external call made by a fake provider or fake
    /// vector store while a fenced worker processed one event. This is the
    /// test-only attribution ledger: it never reaches production logs and
    /// never records credentials, embeddings, or provider responses.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct RecordedExternalCall {
        pub operation: RecordedExternalOperation,
        pub life_id: String,
        pub memory_id: String,
        pub mutation_sequence: i64,
        pub desired_action: String,
        pub target_revision: Option<i64>,
        pub target_content_hash: Option<String>,
        pub claim_epoch: i64,
        pub generation_id: String,
    }

    /// The three external boundaries the worker can cross.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum RecordedExternalOperation {
        ProviderEmbedding,
        LanceUpsert,
        LanceDelete,
    }

    /// Concurrent, reopen-safe call ledger shared between a fake provider and
    /// a fake vector store. Each fake appends exactly one record per external
    /// call, and the identity is taken from the claim the worker is processing
    /// at that moment, so a later assertion can attribute every call to a
    /// specific memory_id / mutation_sequence / claim_epoch / generation.
    #[derive(Clone, Default)]
    pub(crate) struct ExternalCallRecorder {
        calls: std::sync::Arc<std::sync::Mutex<Vec<RecordedExternalCall>>>,
        current_claim: std::sync::Arc<std::sync::Mutex<Option<RecordedExternalCall>>>,
    }

    impl ExternalCallRecorder {
        /// Registers the claim the worker is currently processing. Called from
        /// a test-only claim observer at claim time, before any external call.
        pub(crate) fn set_current_claim(&self, claim: &crate::storage::FencedVectorSyncClaim) {
            *self.current_claim.lock().unwrap() = Some(RecordedExternalCall {
                operation: RecordedExternalOperation::ProviderEmbedding,
                life_id: claim.life_id().to_owned(),
                memory_id: claim.memory_id().to_owned(),
                mutation_sequence: claim.mutation_sequence(),
                desired_action: claim.action().as_str().to_owned(),
                target_revision: claim.target_revision(),
                target_content_hash: claim.target_content_hash().map(str::to_owned),
                claim_epoch: claim.fenced_claim_epoch(),
                generation_id: claim.generation_id().to_owned(),
            });
        }

        /// Appends one provider-embedding call attributed to the current claim.
        pub(crate) fn record_provider_embedding(&self) {
            self.append(RecordedExternalOperation::ProviderEmbedding);
        }

        /// Appends one Lance upsert call attributed to the current claim.
        pub(crate) fn record_lance_upsert(&self) {
            self.append(RecordedExternalOperation::LanceUpsert);
        }

        /// Appends one Lance delete call attributed to the current claim.
        pub(crate) fn record_lance_delete(&self) {
            self.append(RecordedExternalOperation::LanceDelete);
        }

        fn append(&self, operation: RecordedExternalOperation) {
            let identity = self
                .current_claim
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| RecordedExternalCall {
                    operation,
                    life_id: String::new(),
                    memory_id: String::new(),
                    mutation_sequence: 0,
                    desired_action: String::new(),
                    target_revision: None,
                    target_content_hash: None,
                    claim_epoch: 0,
                    generation_id: String::new(),
                });
            let mut calls = self.calls.lock().unwrap();
            calls.push(RecordedExternalCall {
                operation,
                ..identity
            });
        }

        /// All recorded calls, oldest first.
        pub(crate) fn snapshot(&self) -> Vec<RecordedExternalCall> {
            self.calls.lock().unwrap().clone()
        }

        /// Number of recorded calls so far (for per-process_one slicing).
        pub(crate) fn len(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        /// Calls for one memory_id.
        pub(crate) fn calls_for(&self, memory_id: &str) -> Vec<RecordedExternalCall> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.memory_id == memory_id)
                .cloned()
                .collect()
        }

        /// (provider, lance upsert, lance delete) counts for one memory_id.
        pub(crate) fn counts_for(&self, memory_id: &str) -> (usize, usize, usize) {
            let mut provider = 0usize;
            let mut upserts = 0usize;
            let mut deletes = 0usize;
            for call in self.calls.lock().unwrap().iter() {
                if call.memory_id != memory_id {
                    continue;
                }
                match call.operation {
                    RecordedExternalOperation::ProviderEmbedding => provider += 1,
                    RecordedExternalOperation::LanceUpsert => upserts += 1,
                    RecordedExternalOperation::LanceDelete => deletes += 1,
                }
            }
            (provider, upserts, deletes)
        }

        /// (provider, lance upsert, lance delete) counts for one exact claim
        /// identity: the same memory_id, mutation_sequence, and claim_epoch.
        /// This is what distinguishes an old expired mutation from a new
        /// mutation that reuses the same outbox row.
        pub(crate) fn counts_for_identity(
            &self,
            memory_id: &str,
            mutation_sequence: i64,
            claim_epoch: i64,
        ) -> (usize, usize, usize) {
            let mut provider = 0usize;
            let mut upserts = 0usize;
            let mut deletes = 0usize;
            for call in self.calls.lock().unwrap().iter() {
                if call.memory_id != memory_id
                    || call.mutation_sequence != mutation_sequence
                    || call.claim_epoch != claim_epoch
                {
                    continue;
                }
                match call.operation {
                    RecordedExternalOperation::ProviderEmbedding => provider += 1,
                    RecordedExternalOperation::LanceUpsert => upserts += 1,
                    RecordedExternalOperation::LanceDelete => deletes += 1,
                }
            }
            (provider, upserts, deletes)
        }
    }

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

        drop(state);
        if enqueue_outbox {
            use crate::memory::vector_sync_outbox::{
                EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction,
                MemoryVectorSyncOutboxRepository,
            };
            <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
                service,
                EnqueueMemoryVectorSyncRequest {
                    life_id: life_id.to_string(),
                    memory_id: id.clone(),
                    desired_action: MemoryVectorSyncAction::Upsert,
                },
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
    fn attempt_claim_identity_schema_error_is_static_and_deidentified() {
        let error = StorageError::attempt_claim_identity_schema_invalid();
        assert_eq!(error.code, "ATTEMPT_CLAIM_IDENTITY_SCHEMA_INVALID");
        assert!(!error.message.contains("sqlite_schema"));
        assert!(!error.message.contains("CREATE TABLE"));
        assert!(!error.message.contains("\\\\"));
    }

    #[test]
    fn backup_preserves_schema_fourteen_attempt_identity_and_writer_fence() {
        let root = TestRoot::new("migration-authorized-reopen");
        let service = seeded_service(&root.0);
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute_batch(
                    "INSERT INTO memory_vector_sync_outbox
                     (life_id, memory_id, desired_action, state, attempt_count,
                      mutation_sequence, claimed_generation_id, last_send_disposition,
                      migration_disposition, fenced_claim_epoch, last_marked_claim_epoch)
                     VALUES ('life-1', 'backup-attempt-identity', 'delete', 'failed', 3,
                             9, 'backup-generation', 'possibly_sent',
                             'legacy_upsert_rebuild_required', 7, 6)",
                )
                .unwrap();
        }
        let target = root.0.join("custom");

        let result = service.migrate_location(target.to_str().unwrap());

        assert!(result.success, "{:?}", result.error_message);
        let state = service.state().unwrap();
        let epoch: i64 = state
            .connection
            .query_row("SELECT digital_life_writer_epoch()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(
            connection::read_schema_version(&state.connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        let writer_fence_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 18);
        migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
        assert_eq!(
            state
                .connection
                .query_row(
                    "SELECT attempt_count, claimed_generation_id, last_send_disposition,
                            migration_disposition, fenced_claim_epoch, last_marked_claim_epoch
                     FROM memory_vector_sync_outbox
                     WHERE life_id='life-1' AND memory_id='backup-attempt-identity'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .unwrap(),
            (
                3,
                Some("backup-generation".into()),
                Some("possibly_sent".into()),
                Some("legacy_upsert_rebuild_required".into()),
                7,
                6,
            )
        );
        assert_eq!(
            state.database_path,
            fs::canonicalize(target.join(DATABASE_FILE_NAME)).unwrap()
        );
    }

    /// B5: an Online Backup followed by a true restore (drop source, open the
    /// backup as an independent database) must preserve every outbox state,
    /// the schema-14 epochs, Health semantics, recovery behavior, and must not
    /// replay any external work.
    #[test]
    fn backup_restore_preserves_all_attempt_states_and_health() {
        use crate::vector_store::VectorStore;
        let root = TestRoot::new("backup-restore-full-loop");
        let service = seeded_service(&root.0);
        let (gen_id, gen_desc, gen_dim) = ("gen-backup-restore", "backup-desc", 3);
        service
            .register_building_vector_generation(gen_id, gen_desc, gen_dim)
            .unwrap();
        let memory_id = {
            // A legal confirmed memory for a claimable row.
            let record = crate::storage::test_support::insert_confirmed_memory_fixture(
                &service,
                "life-1",
                "fact",
                "backup restore fixture",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            record.id
        };
        {
            let state = service.state().unwrap();
            let conn = &state.connection;
            // 1. Upsert Unknown Send (marked, possibly_sent)
            conn.execute_batch(
                "INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code)
                 VALUES ('life-1','bs-unknown','upsert','blocked',2,1,1,'h-unknown',2,2,'gen-backup-restore','possibly_sent','PROVIDER_RESULT_UNKNOWN');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code)
                 VALUES ('life-1','bs-att5','upsert','blocked',5,2,1,'h-att5',3,3,'gen-backup-restore','possibly_sent','LANCE_PERMANENT');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code, lease_owner, lease_fence_epoch,
                    lease_expires_at, next_attempt_at, created_at, updated_at)
                 VALUES ('life-1','bs-over5','upsert','processing',6,3,1,'h-over5',3,3,'gen-backup-restore','definitely_not_sent','LANCE_PERMANENT','worker-over',30,'2000-01-01T00:00:00.000Z','2000-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code)
                 VALUES ('life-1','bs-invalid','upsert','blocked',1,4,1,'h-invalid',1,0,NULL,NULL,NULL);
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code, migration_disposition)
                 VALUES ('life-1','bs-migrated','upsert','blocked',1,5,1,'h-migrated',0,0,NULL,NULL,NULL,'legacy_upsert_rebuild_required');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code)
                 VALUES ('life-1','bs-del-marked','delete','pending',3,6,0,NULL,4,4,'gen-backup-restore',NULL,'LANCE_TRANSIENT');
                 -- unmarked durable expired processing: state=processing, expired lease,
                 -- fenced > marked, attempt 1..4, generation present (8th required class)
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    mutation_sequence, target_revision, target_content_hash,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code, lease_owner, lease_fence_epoch,
                    lease_expires_at, next_attempt_at, created_at, updated_at)
                 VALUES ('life-1','bs-unmarked','upsert','processing',2,7,1,'h-unmarked',3,1,'gen-backup-restore','definitely_not_sent',NULL,'worker-old',30,'2000-01-01T00:00:00.000Z','2000-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z');",
            )
            .unwrap();
            // The legal pending row (memory_id) is claimable and untouched.
        }
        // Capture the full source rows BEFORE the Online Backup migrates the
        // source service away from this database file.
        let source_lines = {
            let state = service.state().unwrap();
            full_outbox_row_lines(&state.connection)
        };

        // Health snapshot on the SOURCE before backup.
        let ctx = crate::vector_store::VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse(gen_id).unwrap(),
            gen_desc,
            gen_dim,
        )
        .unwrap();
        let clock = FixedHealthClockForTests::new(1_700_000_000_000);
        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let source_health = tauri::async_runtime::block_on(
            crate::memory::vector_sync_health::inspect_vector_sync_health(
                &service, &raw_vs, &ctx, &clock,
            ),
        )
        .unwrap();

        // Online Backup through migrate_location (source -> temp -> activate).
        let target = root.0.join("restored");
        let result = service.migrate_location(target.to_str().unwrap());
        assert!(result.success, "{:?}", result.error_message);

        // The source service now points at the restored DB; reopen the backup
        // target as an INDEPENDENT database.
        let restored = StorageService::initialize_with_roots(target.clone(), None).unwrap();

        // Schema 14 and writer fences preserved. Schema version 14 is the
        // current runtime schema; LAST_STATIC_MIGRATION_VERSION = 12 is only the
        // ceiling of the statically-replayed migration list.
        {
            let restored_conn = restored.state().unwrap();
            assert_eq!(
                connection::read_schema_version(&restored_conn.connection).unwrap(),
                connection::MAX_SUPPORTED_SCHEMA_VERSION,
                "restored schema version must be 14"
            );
            assert_eq!(
                super::migration::LAST_STATIC_MIGRATION_VERSION,
                12,
                "LAST_STATIC_MIGRATION_VERSION is 12"
            );
            let epoch_columns: Vec<String> = restored_conn
                .connection
                .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
                .unwrap()
                .query_map([], |row| row.get(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(
                epoch_columns.contains(&"fenced_claim_epoch".to_string()),
                "fenced_claim_epoch column must exist"
            );
            assert!(
                epoch_columns.contains(&"last_marked_claim_epoch".to_string()),
                "last_marked_claim_epoch column must exist"
            );
            let fence_count: i64 = restored_conn
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(fence_count, 18);
        }

        // All 8 outbox states preserved with full epoch evidence.
        type RestoredOutboxRow = (
            String,
            String,
            i64,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<RestoredOutboxRow> = {
            let conn = restored.state().unwrap();
            let mut stmt = conn.connection.prepare(
                "SELECT memory_id, state, attempt_count, fenced_claim_epoch, last_marked_claim_epoch,
                        claimed_generation_id, last_send_disposition, last_error_code
                 FROM memory_vector_sync_outbox ORDER BY memory_id",
            ).unwrap();
            stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        assert_eq!(rows.len(), 8, "all 7 fixtures + 1 legal pending row");
        let find = |mem: &str| -> &RestoredOutboxRow { rows.iter().find(|r| r.0 == mem).unwrap() };
        assert_eq!(find("bs-unknown").1, "blocked");
        assert_eq!(find("bs-unknown").2, 2);
        assert_eq!(find("bs-unknown").3, 2);
        assert_eq!(find("bs-unknown").4, 2);
        assert_eq!(find("bs-unknown").6.as_deref(), Some("possibly_sent"));
        assert_eq!(find("bs-att5").2, 5);
        assert_eq!(find("bs-over5").2, 6);
        assert_eq!(find("bs-invalid").3, 1);
        assert_eq!(find("bs-invalid").4, 0);
        assert_eq!(find("bs-migrated").7.as_deref(), None);
        assert_eq!(find("bs-del-marked").2, 3);
        assert_eq!(find("bs-del-marked").3, 4);
        assert_eq!(find("bs-del-marked").4, 4);
        // Unmarked durable expired-processing: state, epochs, generation preserved.
        assert_eq!(find("bs-unmarked").1, "processing");
        assert_eq!(find("bs-unmarked").2, 2);
        assert_eq!(find("bs-unmarked").3, 3, "fenced > marked");
        assert_eq!(find("bs-unmarked").4, 1, "marked preserved");
        assert_eq!(
            find("bs-unmarked").5.as_deref(),
            Some("gen-backup-restore"),
            "generation preserved for unmarked durable row"
        );
        assert_eq!(
            find("bs-unmarked").6.as_deref(),
            Some("definitely_not_sent")
        );

        // Full-field comparison (mutation clock, migration disposition, lease,
        // created/updated) between source and restored database.
        let restored_lines = {
            let state = restored.state().unwrap();
            full_outbox_row_lines(&state.connection)
        };
        assert_eq!(
            restored_lines, source_lines,
            "every outbox field must round-trip through Online Backup"
        );

        // Health on the RESTORED database matches source semantics.
        let raw_vs_r = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs_r.create_generation(&ctx)).unwrap();
        let restored_health = tauri::async_runtime::block_on(
            crate::memory::vector_sync_health::inspect_vector_sync_health(
                &restored, &raw_vs_r, &ctx, &clock,
            ),
        )
        .unwrap();
        assert_eq!(
            restored_health.provider_result_unknown_count,
            source_health.provider_result_unknown_count,
            "Unknown count preserved"
        );
        assert_eq!(
            restored_health.attempts_at_limit_count, source_health.attempts_at_limit_count,
            "at-limit count preserved"
        );
        assert_eq!(
            restored_health.attempts_over_limit_count, source_health.attempts_over_limit_count,
            "over-limit count preserved"
        );
        assert_eq!(
            restored_health.invalid_attempt_identity_count,
            source_health.invalid_attempt_identity_count,
            "invalid identity count preserved"
        );
        assert_eq!(
            restored_health.migration_isolated_count, source_health.migration_isolated_count,
            "migration-isolated count preserved"
        );
        assert_eq!(
            restored_health.expired_processing_unmarked_count,
            source_health.expired_processing_unmarked_count,
            "expired unmarked count preserved"
        );
        assert_eq!(
            restored_health.expired_processing_marked_count,
            source_health.expired_processing_marked_count,
            "expired marked count preserved"
        );
        assert_eq!(
            restored_health.legacy_processing_unproven_count,
            source_health.legacy_processing_unproven_count,
            "legacy count preserved"
        );
        assert_eq!(
            restored_health.delete_replay_not_eligible_count,
            source_health.delete_replay_not_eligible_count,
            "delete replay not eligible preserved"
        );
        assert_eq!(
            restored_health.expired_processing_count, source_health.expired_processing_count,
            "expired processing preserved"
        );

        // Recovery on the restored database converges by frozen rules.
        restored.test_expire_fenced_runtime_lease().unwrap();
        restored
            .test_recover_expired_fenced_processing_for_generation_binding(1_700_000_000_000)
            .unwrap();
        // Marked unknown upsert stays blocked; over-limit stays invariant.
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-unknown")
                .unwrap()
                .state,
            "blocked"
        );
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-unknown")
                .unwrap()
                .last_error_code
                .as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        // attempt=5 stays blocked.
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-att5")
                .unwrap()
                .state,
            "blocked",
            "attempt=5 blocked stays blocked"
        );
        // attempt>5 becomes INTERNAL_INVARIANT.
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-over5")
                .unwrap()
                .last_error_code
                .as_deref(),
            Some("INTERNAL_INVARIANT"),
            "attempt>5 converges to INTERNAL_INVARIANT"
        );
        // Invalid identity remains invalid and is reported by Health.
        let health_after_recovery = tauri::async_runtime::block_on(
            crate::memory::vector_sync_health::inspect_vector_sync_health(
                &restored, &raw_vs_r, &ctx, &clock,
            ),
        )
        .unwrap();
        assert!(
            health_after_recovery.invalid_attempt_identity_count >= 1,
            "invalid identity is still reported after recovery"
        );
        // Unmarked durable expired-processing recovers to pending, keeps its
        // attempt budget and generation, clears the old lease.
        let unmarked = restored
            .test_get_outbox_snapshot_detailed("life-1", "bs-unmarked")
            .unwrap();
        assert_eq!(
            unmarked.state, "pending",
            "unmarked durable recovers to pending"
        );
        assert_eq!(unmarked.attempt_count, 2, "attempt is not incremented");
        assert_eq!(
            unmarked.claimed_generation_id.as_deref(),
            Some("gen-backup-restore"),
            "generation preserved"
        );
        assert_eq!(
            unmarked.fenced_claim_epoch, 3,
            "fenced epoch preserved on unmarked durable"
        );
        assert_eq!(
            unmarked.last_marked_claim_epoch, 1,
            "marked epoch preserved on unmarked durable"
        );
        assert_eq!(unmarked.lease_owner, None, "old lease cleared");
        // Marked Delete count<5 is restored under the frozen rules (still a
        // delete row with spendable budget, not replayed).
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-del-marked")
                .unwrap()
                .state,
            "pending"
        );
        // Migration-isolated rows do not participate in recovery.
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", "bs-migrated")
                .unwrap()
                .migration_disposition
                .as_deref(),
            Some("legacy_upsert_rebuild_required")
        );

        // A legal pending row can be claimed with a fresh epoch without
        // consuming an extra Attempt.
        let claim = restored
            .claim_one_fenced_vector_sync(gen_id, gen_desc, gen_dim, "worker-restored")
            .unwrap()
            .expect("legal pending row is claimable after restore");
        assert_eq!(claim.memory_id(), memory_id.as_str());
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", &memory_id)
                .unwrap()
                .attempt_count,
            0,
            "claim does not increment attempt"
        );
        assert_eq!(
            restored
                .test_get_outbox_snapshot_detailed("life-1", &memory_id)
                .unwrap()
                .fenced_claim_epoch,
            claim.fenced_claim_epoch()
        );

        // 6.7 Formal worker no-replay on the restored database: the Unknown,
        // at-limit, invalid-identity, and migration-isolated rows must never
        // reach the provider or Lance through the real worker entry, and no
        // token may be reconstructed from the restored rows. Every external
        // call is recorded with the claim identity (memory_id,
        // mutation_sequence, claim_epoch, generation) the worker was holding,
        // so the zero-call proof is per-row, not a global total.
        {
            use crate::memory::vector_sync_worker::{
                FencedVectorSyncSingleEventConsumer, FencedVectorSyncSingleEventResult,
            };
            use crate::storage::test_support::ExternalCallRecorder;

            struct RestoredRecordingProvider<'a> {
                inner: &'a dyn crate::embedding::EmbeddingProvider,
                recorder: &'a ExternalCallRecorder,
            }
            impl crate::embedding::EmbeddingProvider for RestoredRecordingProvider<'_> {
                fn model_info(&self) -> crate::embedding::EmbeddingModelInfo {
                    self.inner.model_info()
                }
                fn model_name(&self) -> &str {
                    self.inner.model_name()
                }
                fn vector_dimension(&self) -> Option<usize> {
                    self.inner.vector_dimension()
                }
                fn max_batch_size(&self) -> usize {
                    self.inner.max_batch_size()
                }
                fn embed<'a>(
                    &'a self,
                    request: crate::embedding::EmbeddingRequest,
                ) -> crate::embedding::EmbeddingFuture<
                    'a,
                    Result<crate::embedding::EmbeddingBatch, crate::embedding::EmbeddingError>,
                > {
                    self.recorder.record_provider_embedding();
                    self.inner.embed(request)
                }
            }

            struct RestoredRecordingVectorStore<'a> {
                inner: &'a dyn crate::vector_store::VectorStore,
                recorder: &'a ExternalCallRecorder,
            }
            impl crate::vector_store::VectorStore for RestoredRecordingVectorStore<'_> {
                fn upsert<'a>(
                    &'a self,
                    record: crate::vector_store::VectorRecord,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.inner.upsert(record)
                }
                fn upsert_batch<'a>(
                    &'a self,
                    records: Vec<crate::vector_store::VectorRecord>,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.inner.upsert_batch(records)
                }
                fn search<'a>(
                    &'a self,
                    query: crate::vector_store::VectorSearchQuery,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<
                        Vec<crate::vector_store::VectorSearchHit>,
                        crate::vector_store::VectorStoreError,
                    >,
                > {
                    self.inner.search(query)
                }
                fn delete<'a>(
                    &'a self,
                    life_id: &'a str,
                    memory_id: &'a str,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<usize, crate::vector_store::VectorStoreError>,
                > {
                    self.inner.delete(life_id, memory_id)
                }
                fn delete_from_space<'a>(
                    &'a self,
                    life_id: &'a str,
                    memory_id: &'a str,
                    space: &'a crate::vector_store::VectorSpace,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<usize, crate::vector_store::VectorStoreError>,
                > {
                    self.inner.delete_from_space(life_id, memory_id, space)
                }
                fn delete_by_life<'a>(
                    &'a self,
                    life_id: &'a str,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<usize, crate::vector_store::VectorStoreError>,
                > {
                    self.inner.delete_by_life(life_id)
                }
                fn clear_space<'a>(
                    &'a self,
                    life_id: &'a str,
                    space: &'a crate::vector_store::VectorSpace,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<usize, crate::vector_store::VectorStoreError>,
                > {
                    self.inner.clear_space(life_id, space)
                }
                fn count<'a>(
                    &'a self,
                    life_id: &'a str,
                    space: Option<&'a crate::vector_store::VectorSpace>,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<usize, crate::vector_store::VectorStoreError>,
                > {
                    self.inner.count(life_id, space)
                }
                fn health_check<'a>(
                    &'a self,
                    life_id: &'a str,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.inner.health_check(life_id)
                }
                fn create_generation<'a>(
                    &'a self,
                    context: &'a crate::vector_store::VectorGenerationContext,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.inner.create_generation(context)
                }
                fn upsert_generation<'a>(
                    &'a self,
                    context: &'a crate::vector_store::VectorGenerationContext,
                    record: crate::vector_store::GenerationVectorRecord,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.recorder.record_lance_upsert();
                    self.inner.upsert_generation(context, record)
                }
                fn delete_generation_memory<'a>(
                    &'a self,
                    context: &'a crate::vector_store::VectorGenerationContext,
                    life_id: &'a str,
                    memory_id: &'a str,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<(), crate::vector_store::VectorStoreError>,
                > {
                    self.recorder.record_lance_delete();
                    self.inner
                        .delete_generation_memory(context, life_id, memory_id)
                }
                fn get_generation_metadata<'a>(
                    &'a self,
                    context: &'a crate::vector_store::VectorGenerationContext,
                    life_id: &'a str,
                    memory_id: &'a str,
                ) -> crate::vector_store::VectorStoreFuture<
                    'a,
                    Result<
                        Option<crate::vector_store::VectorMetadataSample>,
                        crate::vector_store::VectorStoreError,
                    >,
                > {
                    self.inner
                        .get_generation_metadata(context, life_id, memory_id)
                }
            }

            let recorder = ExternalCallRecorder::default();
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(gen_dim);
            let provider = RestoredRecordingProvider {
                inner: &raw_provider,
                recorder: &recorder,
            };
            let raw_vs_worker = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs_worker.create_generation(&ctx)).unwrap();
            let vectors = RestoredRecordingVectorStore {
                inner: &raw_vs_worker,
                recorder: &recorder,
            };
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &restored,
                &provider,
                &vectors,
                ctx.clone(),
            );
            // The claim observer feeds the recorder so every external call is
            // attributed to the exact claim (memory_id, mutation_sequence,
            // claim_epoch, generation) the worker is processing.
            let recorder_for_observer = recorder.clone();
            consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
                recorder_for_observer.set_current_claim(claim);
            })));

            // Drain the worker to exhaustion, attributing every new call slice
            // to the memory the worker just processed. Legitimate pending work
            // may be processed; the protected rows must never be claimed.
            restored.test_expire_fenced_runtime_lease().unwrap();
            let mut processed: Vec<(String, String, FencedVectorSyncSingleEventResult)> =
                Vec::new();
            loop {
                let before = recorder.len();
                let result =
                    tauri::async_runtime::block_on(consumer.process_one("worker-restored"))
                        .unwrap();
                let new_calls = recorder.snapshot();
                let new_calls = &new_calls[before..];
                if result == FencedVectorSyncSingleEventResult::NoEligibleEvent {
                    assert!(
                        new_calls.is_empty(),
                        "NoEligibleEvent must not produce external calls"
                    );
                    break;
                }
                // A row that the worker legitimately refuses (Stale target,
                // lost lease, blocked) must not produce external calls. That is
                // itself correct no-replay evidence; it is only attributed to a
                // memory when the worker actually crossed an external boundary.
                if new_calls.is_empty() {
                    continue;
                }
                let first = &new_calls[0];
                assert!(
                    new_calls
                        .iter()
                        .all(|call| call.memory_id == first.memory_id
                            && call.mutation_sequence == first.mutation_sequence
                            && call.claim_epoch == first.claim_epoch
                            && call.generation_id == first.generation_id),
                    "all calls in one process_one slice share the claim identity"
                );
                processed.push((
                    first.memory_id.clone(),
                    first.mutation_sequence.to_string(),
                    result,
                ));
            }
            consumer.set_claim_observer_for_test(None);

            // 6.7 per-row zero-call proof for the five forbidden rows.
            for protected in [
                "bs-unknown",
                "bs-att5",
                "bs-over5",
                "bs-invalid",
                "bs-migrated",
            ] {
                let (provider_count, upsert_count, delete_count) = recorder.counts_for(protected);
                assert_eq!(
                    (provider_count, upsert_count, delete_count),
                    (0, 0, 0),
                    "{protected}: {provider_count} / {upsert_count} / {delete_count} must be 0/0/0"
                );
                let snap = restored
                    .test_get_outbox_snapshot_detailed("life-1", protected)
                    .unwrap();
                assert_eq!(
                    snap.state, "blocked",
                    "protected row {protected} must stay blocked"
                );
                assert_eq!(
                    snap.attempt_count,
                    match protected {
                        "bs-unknown" => 2,
                        "bs-att5" => 5,
                        "bs-over5" => 6,
                        "bs-invalid" | "bs-migrated" => 1,
                        _ => unreachable!(),
                    },
                    "protected row {protected} attempt untouched by the formal worker"
                );
            }
            // Invalid identity stays reported by Health and is never claimed.
            let health_after_worker = tauri::async_runtime::block_on(
                crate::memory::vector_sync_health::inspect_vector_sync_health(
                    &restored, &raw_vs_r, &ctx, &clock,
                ),
            )
            .unwrap();
            assert!(
                health_after_worker.invalid_attempt_identity_count >= 1,
                "invalid identity remains reported"
            );
            // Migration-isolated row keeps its disposition.
            assert_eq!(
                restored
                    .test_get_outbox_snapshot_detailed("life-1", "bs-migrated")
                    .unwrap()
                    .migration_disposition
                    .as_deref(),
                Some("legacy_upsert_rebuild_required")
            );

            // 5.1 Legitimate rows: any external calls must belong to a legal
            // row's current mutation identity, and never to a forbidden row.
            assert!(
                !processed.is_empty(),
                "the drain must process at least one legitimate row"
            );
            for (memory_id, mutation_sequence, result) in &processed {
                assert!(
                    ![
                        "bs-unknown",
                        "bs-att5",
                        "bs-over5",
                        "bs-invalid",
                        "bs-migrated"
                    ]
                    .contains(&memory_id.as_str()),
                    "a forbidden row must never be processed: {memory_id}"
                );
                let calls = recorder.calls_for(memory_id);
                assert!(!calls.is_empty(), "processed row {memory_id} has records");
                assert!(
                    calls.iter().all(|call| {
                        call.mutation_sequence.to_string() == *mutation_sequence
                            && call.generation_id == gen_id
                            && call.claim_epoch > 0
                    }),
                    "row {memory_id} calls carry its current mutation and a new claim epoch"
                );
                let (p, u, d) = recorder.counts_for(memory_id);
                match result {
                    FencedVectorSyncSingleEventResult::CompletedUpsert => {
                        assert_eq!((p, u, d), (1, 1, 0), "row {memory_id} upsert attribution");
                    }
                    FencedVectorSyncSingleEventResult::CompletedDelete => {
                        assert_eq!((p, u, d), (1, 0, 1), "row {memory_id} delete attribution");
                    }
                    other => {
                        panic!(
                            "unexpected processed result for row {memory_id}: {}",
                            stable_result_name(*other)
                        );
                    }
                }
            }
        }
    }

    /// Stable variant name for a worker result, so a failed attribution
    /// assertion never depends on a Debug impl.
    fn stable_result_name(
        result: crate::memory::vector_sync_worker::FencedVectorSyncSingleEventResult,
    ) -> &'static str {
        use crate::memory::vector_sync_worker::FencedVectorSyncSingleEventResult;
        match result {
            FencedVectorSyncSingleEventResult::NoEligibleEvent => "NoEligibleEvent",
            FencedVectorSyncSingleEventResult::CompletedUpsert => "CompletedUpsert",
            FencedVectorSyncSingleEventResult::CompletedDelete => "CompletedDelete",
            FencedVectorSyncSingleEventResult::Stale => "Stale",
            FencedVectorSyncSingleEventResult::RetryWait => "RetryWait",
            FencedVectorSyncSingleEventResult::Blocked => "Blocked",
            FencedVectorSyncSingleEventResult::Failed => "Failed",
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded => "LostLeaseOrSuperseded",
            FencedVectorSyncSingleEventResult::NoProgressForTest => "NoProgressForTest",
        }
    }

    /// Serializes every outbox field into one line per row so a source and a
    /// restored database can be compared field-for-field.
    fn full_outbox_row_lines(conn: &rusqlite::Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare(
                "SELECT memory_id, desired_action, state, attempt_count, mutation_sequence,
                        target_revision, target_content_hash, claimed_generation_id,
                        last_send_disposition, last_error_code, next_attempt_at,
                        lease_owner, lease_fence_epoch, lease_expires_at,
                        migration_disposition, created_at, updated_at
                 FROM memory_vector_sync_outbox ORDER BY memory_id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            let values: Vec<String> = (0..17)
                .map(|i| {
                    let value: rusqlite::types::Value = r.get(i).unwrap();
                    format!("{value:?}")
                })
                .collect();
            Ok(values.join("|"))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    /// Minimal fixed clock for health tests in the storage module.
    struct FixedHealthClockForTests {
        now_millis: i64,
    }

    impl FixedHealthClockForTests {
        fn new(now_millis: i64) -> Self {
            Self { now_millis }
        }
    }

    impl crate::memory::vector_sync_health::HealthClock for FixedHealthClockForTests {
        fn now_utc_millis(
            &self,
        ) -> Result<i64, crate::memory::vector_sync_health::VectorSyncHealthError> {
            Ok(self.now_millis)
        }
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
