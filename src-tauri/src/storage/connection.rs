use std::{path::Path, time::Duration};

use rusqlite::{functions::FunctionFlags, Connection, OptionalExtension};

use super::StorageError;

pub(super) const MAX_SUPPORTED_SCHEMA_VERSION: i64 = 19;

const WRITER_EPOCH_FUNCTION: &str = "digital_life_writer_epoch";
const WRITER_EPOCH: i64 = 1;
const STORAGE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Opens the authorized connection shape used by controlled paths that do not
/// participate in the authoritative database upgrade coordinator, such as a
/// temporary backup target.
///
/// Authoritative storage initialization must use the narrower before-WAL phase
/// through the upgrade coordinator, so it can keep WAL strictly after upgrade
/// validation.
pub(super) fn open_authorized_storage_connection(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    let connection = open_authorized_storage_connection_before_wal(database_path)?;
    configure_authorized_connection_wal(&connection)?;
    Ok(connection)
}

/// Opens an authorized connection without changing journal mode.
///
/// The writer capability, foreign-key enforcement, busy timeout, and schema
/// version guard are all established before this function returns.  The caller
/// must either complete the authoritative upgrade protocol and call
/// [`configure_authorized_connection_wal`] or drop the connection.
pub(super) fn open_authorized_storage_connection_before_wal(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    open_authorized_storage_connection_before_wal_with_function_name(
        database_path,
        WRITER_EPOCH_FUNCTION,
    )
}

/// Test-only access to the exact authorized before-WAL connection shape used
/// by the upgrade coordinator. It always registers the fixed writer epoch and
/// deliberately accepts no caller-controlled capability or bypass options.
#[cfg(test)]
pub(crate) fn open_authorized_test_connection(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    open_authorized_storage_connection_before_wal(database_path)
}

fn open_authorized_storage_connection_before_wal_with_function_name(
    database_path: &Path,
    writer_epoch_function_name: &str,
) -> Result<Connection, StorageError> {
    let connection =
        Connection::open(database_path).map_err(|_| StorageError::connection_open_failed())?;

    register_writer_capability(&connection, writer_epoch_function_name)?;
    configure_connection(&connection)?;

    let found_version = read_schema_version(&connection)?;
    if found_version > MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(StorageError::database_version_too_new());
    }

    Ok(connection)
}

/// Configures WAL only after the caller has completed any required schema
/// upgrade and post-commit verification.
pub(super) fn configure_authorized_connection_wal(
    connection: &Connection,
) -> Result<(), StorageError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| StorageError::connection_configuration_failed())?;
    Ok(())
}

fn register_writer_capability(
    connection: &Connection,
    writer_epoch_function_name: &str,
) -> Result<(), StorageError> {
    connection
        .create_scalar_function(
            writer_epoch_function_name,
            0,
            FunctionFlags::SQLITE_UTF8
                | FunctionFlags::SQLITE_DETERMINISTIC
                | FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(WRITER_EPOCH),
        )
        .map_err(|_| StorageError::writer_capability_registration_failed())
}

fn configure_connection(connection: &Connection) -> Result<(), StorageError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| StorageError::connection_configuration_failed())?;
    connection
        .busy_timeout(STORAGE_BUSY_TIMEOUT)
        .map_err(|_| StorageError::connection_configuration_failed())
}

/// Returns the largest valid migration version without creating or changing
/// the migration table. An absent or empty table is an uninitialized database.
pub(super) fn read_schema_version(connection: &Connection) -> Result<i64, StorageError> {
    let migration_object_type: Option<String> = connection
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name='schema_migration'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StorageError::schema_version_read_failed())?;
    match migration_object_type.as_deref() {
        None => return Ok(0),
        Some("table") => {}
        Some(_) => return Err(StorageError::schema_version_read_failed()),
    }

    let mut column_statement = connection
        .prepare("PRAGMA table_info(schema_migration)")
        .map_err(|_| StorageError::schema_version_read_failed())?;
    let columns = column_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|_| StorageError::schema_version_read_failed())?;
    let mut has_valid_version_column = false;
    let mut has_valid_name_column = false;
    let mut has_valid_applied_at_column = false;
    for column in columns {
        let (name, declared_type, not_null, primary_key_position) =
            column.map_err(|_| StorageError::schema_version_read_failed())?;
        if name == "version"
            && declared_type.eq_ignore_ascii_case("INTEGER")
            && primary_key_position == 1
        {
            has_valid_version_column = true;
        }
        if name == "name"
            && declared_type.eq_ignore_ascii_case("TEXT")
            && not_null == 1
            && primary_key_position == 0
        {
            has_valid_name_column = true;
        }
        if name == "applied_at"
            && declared_type.eq_ignore_ascii_case("TEXT")
            && not_null == 1
            && primary_key_position == 0
        {
            has_valid_applied_at_column = true;
        }
    }
    if !has_valid_version_column || !has_valid_name_column || !has_valid_applied_at_column {
        return Err(StorageError::schema_version_read_failed());
    }

    let mut statement = connection
        .prepare("SELECT version, typeof(version) FROM schema_migration")
        .map_err(|_| StorageError::schema_version_read_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| StorageError::schema_version_read_failed())?;

    let mut maximum = 0;
    for row in rows {
        let (version, value_type) = row.map_err(|_| StorageError::schema_version_read_failed())?;
        if value_type != "integer" || version <= 0 {
            return Err(StorageError::schema_version_read_failed());
        }
        maximum = maximum.max(version);
    }
    Ok(maximum)
}

#[cfg(test)]
pub(super) fn open_legacy_storage_connection_for_test(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    Connection::open(database_path).map_err(|_| StorageError::connection_open_failed())
}

#[cfg(test)]
fn open_authorized_storage_connection_with_invalid_registration_for_test(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    let invalid_name = "x".repeat(256);
    open_authorized_storage_connection_before_wal_with_function_name(database_path, &invalid_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_path(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(format!("{name}.sqlite3"));
        (root, path)
    }

    fn create_schema_migration_table(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
    }

    #[test]
    fn authorized_storage_connection_registers_writer_epoch() {
        let (_root, path) = database_path("authorized-writer-epoch");
        let connection = open_authorized_storage_connection(&path).unwrap();
        let epoch: i64 = connection
            .query_row("SELECT digital_life_writer_epoch()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(epoch, WRITER_EPOCH);
    }

    #[test]
    fn legacy_storage_connection_for_test_has_no_writer_epoch() {
        let (_root, path) = database_path("legacy-writer-epoch");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        assert!(connection
            .query_row("SELECT digital_life_writer_epoch()", [], |row| row
                .get::<_, i64>(0))
            .is_err());
    }

    #[test]
    fn schema_version_reader_treats_missing_or_empty_table_as_zero() {
        let (_root, path) = database_path("schema-version-zero");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        assert_eq!(read_schema_version(&connection).unwrap(), 0);

        create_schema_migration_table(&connection);
        assert_eq!(read_schema_version(&connection).unwrap(), 0);
    }

    #[test]
    fn authorized_storage_connection_allows_current_schema_version() {
        let (_root, path) = database_path("schema-version-current");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        create_schema_migration_table(&connection);
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, 'current', '2026-01-01T00:00:00Z')",
                [MAX_SUPPORTED_SCHEMA_VERSION],
            )
            .unwrap();
        drop(connection);

        let authorized = open_authorized_storage_connection(&path).unwrap();
        assert_eq!(
            read_schema_version(&authorized).unwrap(),
            MAX_SUPPORTED_SCHEMA_VERSION
        );
    }

    #[test]
    fn database_version_too_new_is_rejected_before_wal() {
        let (_root, path) = database_path("schema-version-future");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        create_schema_migration_table(&connection);
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, 'future', '2026-01-01T00:00:00Z')",
                [MAX_SUPPORTED_SCHEMA_VERSION + 1],
            )
            .unwrap();
        drop(connection);

        let error = open_authorized_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "DATABASE_VERSION_TOO_NEW");

        let legacy = open_legacy_storage_connection_for_test(&path).unwrap();
        let journal_mode: String = legacy
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "delete");
        assert_eq!(
            read_schema_version(&legacy).unwrap(),
            MAX_SUPPORTED_SCHEMA_VERSION + 1
        );
        assert!(!path.with_extension("sqlite3-wal").exists());
    }

    #[test]
    fn higher_database_version_is_rejected() {
        let (_root, path) = database_path("schema-version-999");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        create_schema_migration_table(&connection);
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at) VALUES (999, 'future', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        drop(connection);

        let error = open_authorized_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "DATABASE_VERSION_TOO_NEW");
    }

    #[test]
    fn non_integer_schema_version_fails_closed() {
        let (_root, path) = database_path("schema-version-non-integer");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE schema_migration (version TEXT NOT NULL);")
            .unwrap();
        drop(connection);

        let error = open_authorized_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "SCHEMA_VERSION_READ_FAILED");
    }

    #[test]
    fn schema_migration_view_fails_closed() {
        let (_root, path) = database_path("schema-version-view");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        connection
            .execute_batch("CREATE VIEW schema_migration AS SELECT 12 AS version;")
            .unwrap();
        drop(connection);

        let error = open_authorized_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "SCHEMA_VERSION_READ_FAILED");
    }

    #[test]
    fn malformed_schema_migration_table_fails_closed() {
        let (_root, path) = database_path("schema-version-malformed");
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE schema_migration (unexpected TEXT NOT NULL);")
            .unwrap();
        drop(connection);

        let error = open_authorized_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "SCHEMA_VERSION_READ_FAILED");
    }

    #[test]
    fn writer_capability_registration_failure_returns_no_authorized_connection() {
        let (_root, path) = database_path("writer-registration-failure");
        let error = open_authorized_storage_connection_with_invalid_registration_for_test(&path)
            .unwrap_err();
        assert_eq!(error.code, "WRITER_CAPABILITY_REGISTRATION_FAILED");

        let legacy = open_legacy_storage_connection_for_test(&path).unwrap();
        assert!(legacy
            .query_row("SELECT digital_life_writer_epoch()", [], |row| row
                .get::<_, i64>(0))
            .is_err());
    }

    #[test]
    fn storage_initialize_rejects_newer_schema_before_migration() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
        let connection = open_legacy_storage_connection_for_test(&path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        create_schema_migration_table(&connection);
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, 'future', '2026-01-01T00:00:00Z')",
                [MAX_SUPPORTED_SCHEMA_VERSION + 1],
            )
            .unwrap();
        drop(connection);

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a newer database must not initialize storage"),
            Err(error) => error,
        };
        assert_eq!(error.code, "DATABASE_VERSION_TOO_NEW");

        let legacy = open_legacy_storage_connection_for_test(&path).unwrap();
        let application_tables: i64 = legacy
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name IN ('app_state', 'memory_vector_sync_outbox')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let journal_mode: String = legacy
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(application_tables, 0);
        assert_eq!(journal_mode, "delete");
    }

    #[test]
    fn storage_initialize_allows_fresh_and_empty_migration_schemas() {
        let fresh_root = tempfile::tempdir().unwrap();
        let fresh_service = super::super::StorageService::initialize_with_roots(
            fresh_root.path().to_path_buf(),
            None,
        )
        .unwrap();
        let fresh_state = fresh_service.state().unwrap();
        assert_eq!(
            read_schema_version(&fresh_state.connection).unwrap(),
            MAX_SUPPORTED_SCHEMA_VERSION
        );
        let fresh_epoch: i64 = fresh_state
            .connection
            .query_row("SELECT digital_life_writer_epoch()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fresh_epoch, WRITER_EPOCH);
        drop(fresh_state);

        let empty_root = tempfile::tempdir().unwrap();
        let empty_path = empty_root.path().join(super::super::DATABASE_FILE_NAME);
        let empty_connection = open_legacy_storage_connection_for_test(&empty_path).unwrap();
        create_schema_migration_table(&empty_connection);
        drop(empty_connection);

        let empty_service = super::super::StorageService::initialize_with_roots(
            empty_root.path().to_path_buf(),
            None,
        )
        .unwrap();
        let empty_state = empty_service.state().unwrap();
        assert_eq!(
            read_schema_version(&empty_state.connection).unwrap(),
            MAX_SUPPORTED_SCHEMA_VERSION
        );
    }
}
