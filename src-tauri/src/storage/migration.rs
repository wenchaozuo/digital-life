use std::{fs, path::Path, time::Duration};

use rusqlite::{backup::Backup, params, Connection, OptionalExtension, Transaction};

use super::{connection, writer_fence_manifest, StorageError, MIGRATIONS};

/// The only H1-A3 extension result for the future writer-fence schema phase.
/// H1-B must replace this fixed `NotRegistered` state through the repository's
/// static migration registry; callers cannot supply SQL or callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WriterFenceSchemaUpgrade {
    NotRegistered,
}

/// Applies every pending registered migration in a caller-owned transaction.
///
/// This function never creates a nested transaction, commits, configures WAL,
/// invokes Restart Manager, or installs the future writer-fence Trigger schema.
pub(super) fn apply_pending_migrations_in_transaction(
    transaction: &Transaction<'_>,
    from_version: i64,
    target_version: i64,
) -> Result<(), StorageError> {
    if target_version != connection::MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    apply_migrations_from_static_registry(transaction, from_version, target_version, MIGRATIONS)
}

/// Fixed H1-B extension location. It is deliberately registered as absent in
/// H1-A3 and has no capability to execute caller-provided SQL.
pub(super) fn apply_writer_fence_schema_upgrade_if_registered(
    _transaction: &Transaction<'_>,
) -> Result<WriterFenceSchemaUpgrade, StorageError> {
    debug_assert_eq!(
        writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION,
        connection::MAX_SUPPORTED_SCHEMA_VERSION + 1
    );
    debug_assert_eq!(
        writer_fence_manifest::writer_fence_trigger_specs().len(),
        18
    );
    Ok(WriterFenceSchemaUpgrade::NotRegistered)
}

/// Performs schema-only post-commit verification for the authoritative
/// database. Backup verification has additional LifeIdentity requirements and
/// therefore remains a separate operation below.
pub(super) fn verify_schema_after_upgrade(
    connection: &Connection,
    expected_schema_version: i64,
) -> Result<(), StorageError> {
    #[cfg(test)]
    if POST_COMMIT_VERIFICATION_FAILURE_FOR_TEST.with(|fail_next| fail_next.replace(false)) {
        return Err(StorageError::migration_post_commit_verification_failed());
    }

    let found_version = connection::read_schema_version(connection)
        .map_err(|_| StorageError::migration_post_commit_verification_failed())?;
    if found_version != expected_schema_version {
        return Err(StorageError::migration_version_invariant_failed());
    }

    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| StorageError::migration_post_commit_verification_failed())?;
    if integrity != "ok" {
        return Err(StorageError::migration_post_commit_verification_failed());
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static POST_COMMIT_VERIFICATION_FAILURE_FOR_TEST: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(super) fn fail_next_post_commit_verification_for_test() {
    POST_COMMIT_VERIFICATION_FAILURE_FOR_TEST.with(|fail_next| fail_next.set(true));
}

fn apply_migrations_from_static_registry(
    transaction: &Transaction<'_>,
    from_version: i64,
    target_version: i64,
    registered_migrations: &[(i64, &str, &str)],
) -> Result<(), StorageError> {
    validate_migration_registry(registered_migrations, target_version)?;
    if from_version < 0 || from_version > target_version {
        return Err(StorageError::migration_version_invariant_failed());
    }

    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migration (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );",
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_applied_migration_history(transaction, from_version, registered_migrations)?;

    for (version, name, sql) in registered_migrations {
        if *version <= from_version {
            continue;
        }

        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
        transaction
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at)
                 VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![version, name],
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

fn validate_migration_registry(
    registered_migrations: &[(i64, &str, &str)],
    target_version: i64,
) -> Result<(), StorageError> {
    if target_version <= 0 || registered_migrations.len() != target_version as usize {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for (index, (version, _name, sql)) in registered_migrations.iter().enumerate() {
        let expected_version = i64::try_from(index + 1)
            .map_err(|_| StorageError::migration_version_invariant_failed())?;
        if *version != expected_version || name_is_invalid(sql) {
            return Err(StorageError::migration_version_invariant_failed());
        }
    }
    Ok(())
}

fn name_is_invalid(sql: &str) -> bool {
    sql.trim().is_empty()
}

fn validate_applied_migration_history(
    transaction: &Transaction<'_>,
    from_version: i64,
    registered_migrations: &[(i64, &str, &str)],
) -> Result<(), StorageError> {
    let mut statement = transaction
        .prepare("SELECT version, name FROM schema_migration ORDER BY version ASC")
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let applied = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StorageError::migration_transaction_failed())?;

    let expected = registered_migrations
        .iter()
        .take(
            usize::try_from(from_version)
                .map_err(|_| StorageError::migration_version_invariant_failed())?,
        )
        .map(|(version, name, _)| (*version, (*name).to_string()))
        .collect::<Vec<_>>();
    if applied != expected {
        return Err(StorageError::migration_version_invariant_failed());
    }
    Ok(())
}

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
        let mut target = connection::open_authorized_storage_connection(temporary_database)?;

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

#[cfg(test)]
mod transaction_tests {
    use rusqlite::{Connection, TransactionBehavior};

    use super::*;

    const TEST_MIGRATIONS: &[(i64, &str, &str)] = &[
        (
            1,
            "one",
            "CREATE TABLE migration_test_one (id INTEGER PRIMARY KEY)",
        ),
        (
            2,
            "two",
            "CREATE TABLE migration_test_two (id INTEGER PRIMARY KEY)",
        ),
    ];

    fn transaction_connection() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn schema_version(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn migration_transaction_registry_is_unique_and_strictly_incrementing() {
        validate_migration_registry(MIGRATIONS, connection::MAX_SUPPORTED_SCHEMA_VERSION).unwrap();
        let missing = [(1, "one", "SELECT 1"), (3, "three", "SELECT 1")];
        let duplicate = [(1, "one", "SELECT 1"), (1, "again", "SELECT 1")];
        let reversed = [(2, "two", "SELECT 1"), (1, "one", "SELECT 1")];
        for registry in [&missing[..], &duplicate[..], &reversed[..]] {
            let error = validate_migration_registry(registry, 2).unwrap_err();
            assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        }
    }

    #[test]
    fn migration_transaction_rejects_targets_outside_the_h1_a3_contract() {
        let mut connection = transaction_connection();
        let transaction = connection.transaction().unwrap();
        for target in [0, connection::MAX_SUPPORTED_SCHEMA_VERSION - 1, 13] {
            let error =
                apply_pending_migrations_in_transaction(&transaction, 0, target).unwrap_err();
            assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        }
    }

    #[test]
    fn migration_transaction_skips_already_applied_versions_and_uses_the_caller_transaction() {
        let mut connection = transaction_connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 0, 2, TEST_MIGRATIONS).unwrap();
        transaction.commit().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 2, 2, TEST_MIGRATIONS).unwrap();
        assert_eq!(
            transaction
                .query_row("SELECT COUNT(*) FROM schema_migration", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(transaction);
        assert_eq!(schema_version(&connection), 2);
    }

    #[test]
    fn migration_transaction_rejects_an_applied_history_gap() {
        let mut connection = transaction_connection();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL); INSERT INTO schema_migration (version, name, applied_at) VALUES (2, 'two', '2026-01-01T00:00:00Z');").unwrap();
        let transaction = connection.transaction().unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 2, 2, TEST_MIGRATIONS).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
    }

    #[test]
    fn migration_transaction_rolls_back_every_ddl_and_version_row_when_a_migration_fails() {
        let migrations = [
            (1, "one", "CREATE TABLE atomic_one (id INTEGER PRIMARY KEY)"),
            (2, "bad", "SELECT intentionally_invalid_sql"),
        ];
        let mut connection = transaction_connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 0, 2, &migrations).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        let object_count: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('atomic_one', 'schema_migration')", [], |row| row.get(0)).unwrap();
        assert_eq!(object_count, 0);
    }

    #[test]
    fn migration_transaction_rolls_back_ddl_when_the_version_row_insert_fails() {
        let migrations = [(
            1,
            "one",
            "CREATE TABLE version_insert_atomic (id INTEGER PRIMARY KEY)",
        )];
        let mut connection = transaction_connection();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL); CREATE TRIGGER reject_schema_migration_insert BEFORE INSERT ON schema_migration BEGIN SELECT RAISE(ABORT, 'reject'); END;").unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 0, 1, &migrations).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        let table_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'version_insert_atomic')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 0);
    }

    #[test]
    fn migration_transaction_does_not_commit_configure_wal_or_install_writer_fences() {
        let mut connection = transaction_connection();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 0, 2, TEST_MIGRATIONS).unwrap();
        let journal_mode: String = transaction
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_ne!(journal_mode, "wal");
        let writer_fence_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 0);
        drop(transaction);
        let table_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'migration_test_one')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 0);
    }

    #[test]
    fn migration_transaction_h1_b_extension_is_explicitly_not_registered() {
        let mut connection = transaction_connection();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap(),
            WriterFenceSchemaUpgrade::NotRegistered
        );
        drop(transaction);
    }
}
