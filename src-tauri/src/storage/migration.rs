use std::{fs, path::Path, time::Duration};

use rusqlite::{backup::Backup, Connection, OptionalExtension};

use super::StorageError;

pub fn backup_and_verify(
    source: &Connection,
    temporary_database: &Path,
    expected_schema_version: i64,
    expected_life_id: &str,
) -> Result<(), StorageError> {
    if temporary_database.exists() {
        fs::remove_file(temporary_database).map_err(|error| {
            StorageError::new(
                "MIGRATION_TEMP_CLEANUP_FAILED",
                format!("Cannot remove a stale temporary database: {error}"),
                true,
            )
        })?;
    }

    let result = (|| -> Result<(), StorageError> {
        let mut target = Connection::open(temporary_database).map_err(|error| {
            StorageError::new(
                "MIGRATION_TARGET_OPEN_FAILED",
                format!("Cannot open the temporary target database: {error}"),
                true,
            )
        })?;

        {
            let backup = Backup::new(source, &mut target).map_err(|error| {
                StorageError::new(
                    "MIGRATION_BACKUP_INIT_FAILED",
                    format!("Cannot initialize SQLite Online Backup: {error}"),
                    true,
                )
            })?;
            backup
                .run_to_completion(32, Duration::from_millis(10), None)
                .map_err(|error| {
                    StorageError::new(
                        "MIGRATION_BACKUP_FAILED",
                        format!("SQLite Online Backup failed: {error}"),
                        true,
                    )
                })?;
        }

        target
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|error| {
                StorageError::new(
                    "MIGRATION_TARGET_PRAGMA_FAILED",
                    format!("Cannot enable target database validation: {error}"),
                    true,
                )
            })?;
        verify_database(&target, expected_schema_version, expected_life_id)
    })();

    if result.is_err() {
        let _ = fs::remove_file(temporary_database);
    }
    result
}

pub fn verify_database(
    connection: &Connection,
    expected_schema_version: i64,
    expected_life_id: &str,
) -> Result<(), StorageError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_INTEGRITY_CHECK_FAILED",
                format!("Cannot run target integrity_check: {error}"),
                true,
            )
        })?;
    if integrity != "ok" {
        return Err(StorageError::new(
            "MIGRATION_INTEGRITY_INVALID",
            format!("Target integrity_check returned: {integrity}"),
            true,
        ));
    }

    let schema_version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_SCHEMA_CHECK_FAILED",
                format!("Cannot read the target schema version: {error}"),
                true,
            )
        })?;
    if schema_version != expected_schema_version {
        return Err(StorageError::new(
            "MIGRATION_SCHEMA_MISMATCH",
            format!(
                "Target schema version {schema_version} does not match source version {expected_schema_version}."
            ),
            true,
        ));
    }

    let current_life_id: Option<String> = connection
        .query_row(
            "SELECT current_life_id FROM app_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_CURRENT_LIFE_CHECK_FAILED",
                format!("Cannot read current_life_id from the target database: {error}"),
                true,
            )
        })?;
    if current_life_id.as_deref() != Some(expected_life_id) {
        return Err(StorageError::new(
            "MIGRATION_CURRENT_LIFE_MISMATCH",
            "The target database current_life_id does not match the source database.",
            true,
        ));
    }

    let life_exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [expected_life_id],
            |row| row.get(0),
        )
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_LIFE_CHECK_FAILED",
                format!("Cannot read the current LifeIdentity from the target database: {error}"),
                true,
            )
        })?;
    if life_exists != 1 {
        return Err(StorageError::new(
            "MIGRATION_LIFE_MISSING",
            "The current LifeIdentity is missing from the target database.",
            true,
        ));
    }

    Ok(())
}

pub fn activate_temporary_database(
    temporary_database: &Path,
    final_database: &Path,
) -> Result<(), StorageError> {
    if final_database.exists() {
        return Err(StorageError::new(
            "MIGRATION_TARGET_EXISTS",
            "The target directory already contains a digital-life.sqlite3 database.",
            true,
        ));
    }

    fs::rename(temporary_database, final_database).map_err(|error| {
        StorageError::new(
            "MIGRATION_ACTIVATION_FAILED",
            format!("Cannot atomically activate the target database: {error}"),
            true,
        )
    })
}
