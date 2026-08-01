//! Static writer-fence Trigger manifest.
//!
//! H1-A3 defined and validated this manifest. H1-B installs its exact static
//! contents during the fixed schema-13 transaction.

use rusqlite::{Connection, Transaction};

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

/// Installs the fixed manifest into the caller-owned schema transaction. The
/// manifest remains the sole authority for names, tables, operations, and DDL.
pub(super) fn install_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in WRITER_FENCE_TRIGGER_SPECS.iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(index + 1) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
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
thread_local! {
    static FAIL_TRIGGER_INSTALL_AT: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_trigger_install_at_for_test(index: usize) {
    FAIL_TRIGGER_INSTALL_AT.with(|fail_at| fail_at.set(Some(index)));
}

#[cfg(test)]
fn should_fail_trigger_install_at_for_test(index: usize) -> bool {
    FAIL_TRIGGER_INSTALL_AT.with(|fail_at| {
        if fail_at.get() == Some(index) {
            fail_at.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
    };

    use rusqlite::{functions::FunctionFlags, Connection, Error};

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

    fn initialized_fenced_database() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let storage =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let path = storage.test_database_main_path().unwrap();
        drop(storage);
        (root, path)
    }

    fn seed_protected_rows(connection: &Connection) {
        connection
            .execute_batch(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('writer-fence-persona', 'Writer Fence', 1, '{}');
                 INSERT INTO life_identity
                     (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES
                     ('writer-fence-life', 'Writer Fence', '2026-01-01T00:00:00.000Z', 1,
                      'writer-fence-body', 'writer-fence-persona', 1),
                     ('writer-fence-life-alt', 'Writer Fence Alt', '2026-01-01T00:00:00.000Z', 1,
                      'writer-fence-body-alt', 'writer-fence-persona', 1);
                 INSERT INTO memory_vector_sync_outbox
                     (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence)
                 VALUES ('writer-fence-life', 'outbox-seed', 'delete', 'pending', 2, 4);
                 UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=4 WHERE singleton=1;
                 INSERT INTO memory_vector_sync_runtime_lease
                     (lease_name, owner_id, fence_epoch, expires_at)
                 VALUES ('memory-vector-single-event-consumer', 'seed-owner', 4,
                         '2026-02-01T00:00:00.000Z');
                 INSERT INTO memory_vector_generation
                     (generation_id, descriptor_hash, dimension, state)
                 VALUES ('generation-seed', 'seed-descriptor', 3, 'building');
                 INSERT INTO memory_vector_generation_item
                     (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('generation-seed', 'writer-fence-life', 'item-seed', 1, 'seed-hash');
                 INSERT INTO memory_vector_sync_settings (life_id, enabled)
                 VALUES ('writer-fence-life', 1);",
            )
            .unwrap();
    }

    fn authorized_connection(path: &Path) -> Connection {
        super::super::connection::open_authorized_test_connection(path).unwrap()
    }

    fn protected_insert(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence)
                 VALUES ('writer-fence-life', 'outbox-insert', 'delete', 'pending', 0, 5)",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_mutation_clock (singleton, last_sequence)
                 VALUES (1, 5)",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_runtime_lease
                 (lease_name, owner_id, fence_epoch, expires_at)
                 VALUES ('memory-vector-single-event-consumer', 'insert-owner', 5,
                         '2026-03-01T00:00:00.000Z')",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "INSERT INTO memory_vector_generation
                 (generation_id, descriptor_hash, dimension, state)
                 VALUES ('generation-insert', 'insert-descriptor', 3, 'building')",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "INSERT INTO memory_vector_generation_item
                 (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('generation-seed', 'writer-fence-life', 'item-insert', 1, 'insert-hash')",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "INSERT INTO memory_vector_sync_settings (life_id, enabled)
                 VALUES ('writer-fence-life-alt', 1)",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
    }

    fn protected_update(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "UPDATE memory_vector_sync_outbox
                 SET updated_at='2026-04-01T00:00:00.000Z'
                 WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=last_sequence+1 WHERE singleton=1",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "UPDATE memory_vector_sync_runtime_lease SET owner_id='updated-owner'
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "UPDATE memory_vector_generation SET descriptor_hash='updated-descriptor'
                 WHERE generation_id='generation-seed'",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "UPDATE memory_vector_generation_item SET content_hash='updated-hash'
                 WHERE generation_id='generation-seed' AND life_id='writer-fence-life'
                   AND memory_id='item-seed'",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "UPDATE memory_vector_sync_settings SET enabled=0 WHERE life_id='writer-fence-life'",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
    }

    fn protected_delete(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "DELETE FROM memory_vector_sync_outbox
                 WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "DELETE FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "DELETE FROM memory_vector_sync_runtime_lease
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "DELETE FROM memory_vector_generation WHERE generation_id='generation-seed'",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "DELETE FROM memory_vector_generation_item
                 WHERE generation_id='generation-seed' AND life_id='writer-fence-life'
                   AND memory_id='item-seed'",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "DELETE FROM memory_vector_sync_settings WHERE life_id='writer-fence-life'",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
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

    #[test]
    fn writer_fence_authorized_fixture_permits_all_eighteen_operations() {
        let (_root, path) = initialized_fenced_database();
        let connection = authorized_connection(&path);
        seed_protected_rows(&connection);

        for table in PROTECTED_TABLES {
            assert_eq!(
                protected_insert(&connection, table).unwrap(),
                1,
                "{table} insert"
            );
            assert_eq!(
                protected_update(&connection, table).unwrap(),
                1,
                "{table} update"
            );
        }
        for table in [
            "memory_vector_sync_outbox",
            "memory_vector_sync_mutation_clock",
            "memory_vector_sync_runtime_lease",
            "memory_vector_generation_item",
            "memory_vector_generation",
            "memory_vector_sync_settings",
        ] {
            assert_eq!(
                protected_delete(&connection, table).unwrap(),
                1,
                "{table} delete"
            );
        }
    }

    #[test]
    fn writer_fence_raw_legacy_connection_rejects_all_eighteen_operations() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let raw = Connection::open(&path).unwrap();

        for table in PROTECTED_TABLES {
            assert!(
                protected_insert(&raw, table).is_err(),
                "{table} insert must fail"
            );
            assert!(
                protected_update(&raw, table).is_err(),
                "{table} update must fail"
            );
            assert!(
                protected_delete(&raw, table).is_err(),
                "{table} delete must fail"
            );
        }
    }

    #[test]
    fn writer_fence_epoch_zero_connection_is_rejected_with_the_static_code() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let epoch_zero = Connection::open(&path).unwrap();
        epoch_zero
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();

        let error = protected_update(&epoch_zero, "memory_vector_sync_outbox").unwrap_err();
        match error {
            Error::SqliteFailure(_, Some(message)) => {
                assert_eq!(message, "INCOMPATIBLE_DATABASE_WRITER");
            }
            other => panic!("epoch-zero writer must receive the static trigger error: {other}"),
        }
    }
}
