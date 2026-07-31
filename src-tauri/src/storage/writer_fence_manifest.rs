//! Static future writer-fence Trigger manifest.
//!
//! H1-A3 defines and validates this manifest, but deliberately does not install
//! it in a production database. H1-B is the only future phase allowed to add a
//! registered schema upgrade for version 13.

use rusqlite::Connection;

use super::StorageError;

pub(super) const WRITER_FENCE_SCHEMA_VERSION: i64 = 13;
const WRITER_FENCE_TRIGGER_PREFIX: &str = "digital_life_writer_epoch_";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum WriterFenceOperation {
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WriterFenceTriggerSpec {
    pub(super) name: &'static str,
    pub(super) table: &'static str,
    pub(super) operation: WriterFenceOperation,
    pub(super) ddl: &'static str,
}

macro_rules! writer_fence_trigger_spec {
    ($name:literal, $table:literal, $operation:ident, $operation_sql:literal) => {
        WriterFenceTriggerSpec {
            name: $name,
            table: $table,
            operation: WriterFenceOperation::$operation,
            ddl: concat!(
                "CREATE TRIGGER ",
                $name,
                "\nBEFORE ",
                $operation_sql,
                " ON ",
                $table,
                "\nWHEN digital_life_writer_epoch() IS NOT 1\nBEGIN\n    SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');\nEND"
            ),
        }
    };
}

const WRITER_FENCE_TRIGGER_SPECS: &[WriterFenceTriggerSpec] = &[
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_insert",
        "memory_vector_sync_outbox",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_update",
        "memory_vector_sync_outbox",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_delete",
        "memory_vector_sync_outbox",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_insert",
        "memory_vector_sync_mutation_clock",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_update",
        "memory_vector_sync_mutation_clock",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_delete",
        "memory_vector_sync_mutation_clock",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_insert",
        "memory_vector_sync_runtime_lease",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_update",
        "memory_vector_sync_runtime_lease",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_delete",
        "memory_vector_sync_runtime_lease",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_insert",
        "memory_vector_generation",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_update",
        "memory_vector_generation",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_delete",
        "memory_vector_generation",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_insert",
        "memory_vector_generation_item",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_update",
        "memory_vector_generation_item",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_delete",
        "memory_vector_generation_item",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_insert",
        "memory_vector_sync_settings",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_update",
        "memory_vector_sync_settings",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_delete",
        "memory_vector_sync_settings",
        Delete,
        "DELETE"
    ),
];

pub(super) fn writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    WRITER_FENCE_TRIGGER_SPECS
}

/// Confirms that the reserved writer-fence Trigger namespace exactly matches
/// the static manifest. This never repairs or installs schema objects.
pub(super) fn validate_writer_fence_manifest(connection: &Connection) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema")
        .map_err(|_| StorageError::writer_fence_manifest_mismatch())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| StorageError::writer_fence_manifest_mismatch())?;

    let mut found = [false; 18];
    for row in rows {
        let (object_type, name, table, sql) =
            row.map_err(|_| StorageError::writer_fence_manifest_mismatch())?;
        if !name
            .to_ascii_lowercase()
            .starts_with(WRITER_FENCE_TRIGGER_PREFIX)
        {
            continue;
        }

        let Some((index, expected)) = WRITER_FENCE_TRIGGER_SPECS
            .iter()
            .enumerate()
            .find(|(_, expected)| expected.name == name)
        else {
            return Err(StorageError::writer_fence_manifest_mismatch());
        };

        if object_type != "trigger"
            || table.as_deref() != Some(expected.table)
            || sql.as_deref() != Some(expected.ddl)
        {
            return Err(StorageError::writer_fence_manifest_mismatch());
        }
        found[index] = true;
    }

    if found.iter().any(|present| !present) {
        return Err(StorageError::writer_fence_manifest_missing());
    }
    Ok(())
}

// Compile-time contracts retain the future validator and runtime classification
// without allowing H1-A3's production initialization to invoke either one.
const _: fn(&Connection) -> Result<(), StorageError> = validate_writer_fence_manifest;
const _: fn() -> StorageError = StorageError::incompatible_database_writer;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const PROTECTED_TABLES: [&str; 6] = [
        "memory_vector_sync_outbox",
        "memory_vector_sync_mutation_clock",
        "memory_vector_sync_runtime_lease",
        "memory_vector_generation",
        "memory_vector_generation_item",
        "memory_vector_sync_settings",
    ];

    fn manifest_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        for table in PROTECTED_TABLES {
            connection
                .execute_batch(&format!("CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))
                .unwrap();
        }
        connection
    }

    fn install_manifest(connection: &Connection) {
        for spec in writer_fence_trigger_specs() {
            connection.execute_batch(spec.ddl).unwrap();
        }
    }

    fn expect_error(result: Result<(), StorageError>, code: &str) {
        let error = result.expect_err("the static writer-fence manifest must reject the schema");
        assert_eq!(error.code, code);
    }

    fn replace_trigger(connection: &Connection, spec: WriterFenceTriggerSpec, ddl: &str) {
        connection
            .execute_batch(&format!("DROP TRIGGER {}", spec.name))
            .unwrap();
        connection.execute_batch(ddl).unwrap();
    }

    #[test]
    fn writer_fence_manifest_has_exactly_eighteen_static_specs() {
        assert_eq!(WRITER_FENCE_SCHEMA_VERSION, 13);
        assert_eq!(writer_fence_trigger_specs().len(), 18);
    }

    #[test]
    fn writer_fence_manifest_covers_every_protected_table_and_operation() {
        for table in PROTECTED_TABLES {
            let operations = writer_fence_trigger_specs()
                .iter()
                .filter(|spec| spec.table == table)
                .map(|spec| spec.operation)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                operations,
                BTreeSet::from([
                    WriterFenceOperation::Insert,
                    WriterFenceOperation::Update,
                    WriterFenceOperation::Delete,
                ])
            );
        }
    }

    #[test]
    fn writer_fence_manifest_names_and_exact_ddls_are_unique() {
        let names = writer_fence_trigger_specs()
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 18);
        for spec in writer_fence_trigger_specs() {
            assert!(spec.name.starts_with(WRITER_FENCE_TRIGGER_PREFIX));
            assert!(spec
                .ddl
                .starts_with(&format!("CREATE TRIGGER {}\nBEFORE ", spec.name)));
            assert!(spec.ddl.contains(&format!(" ON {}\n", spec.table)));
            assert!(spec.ddl.contains("digital_life_writer_epoch() IS NOT 1"));
            assert!(spec
                .ddl
                .contains("RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER')"));
            assert!(!spec.ddl.contains("IF NOT EXISTS"));
        }
    }

    #[test]
    fn writer_fence_manifest_validator_accepts_an_exact_manifest() {
        let connection = manifest_connection();
        install_manifest(&connection);
        validate_writer_fence_manifest(&connection).unwrap();
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_missing_trigger_without_repairing_it() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let missing = writer_fence_trigger_specs()[0];
        connection
            .execute_batch(&format!("DROP TRIGGER {}", missing.name))
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISSING",
        );
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                [missing.name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_renamed_reserved_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        connection
            .execute_batch(&format!("DROP TRIGGER {}", spec.name))
            .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER digital_life_writer_epoch_renamed_insert
                 BEFORE INSERT ON memory_vector_sync_outbox
                 WHEN digital_life_writer_epoch() IS NOT 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                 END",
            )
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_wrong_table() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_generation
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_operation() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE UPDATE ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_capability_function() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN another_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_epoch_value() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 2
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_abort_instead_of_rollback() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ABORT, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_null_sql() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema SET sql = NULL WHERE name = ?1",
                [spec.name],
            )
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_an_unregistered_reserved_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        connection
            .execute_batch(
                "CREATE TRIGGER digital_life_writer_epoch_unregistered_insert
                 BEFORE INSERT ON memory_vector_sync_outbox
                 WHEN digital_life_writer_epoch() IS NOT 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                 END",
            )
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_allows_an_unrelated_business_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        connection
            .execute_batch(
                "CREATE TRIGGER unrelated_business_trigger
                 BEFORE INSERT ON memory_vector_sync_outbox
                 BEGIN
                     SELECT 1;
                 END",
            )
            .unwrap();

        validate_writer_fence_manifest(&connection).unwrap();
    }

    #[test]
    fn incompatible_database_writer_error_is_static_and_deidentified() {
        let error = StorageError::incompatible_database_writer();
        assert_eq!(error.code, "INCOMPATIBLE_DATABASE_WRITER");
        assert!(!error.message.contains("CREATE TRIGGER"));
        assert!(!error.message.contains("\\\\"));
    }
}
