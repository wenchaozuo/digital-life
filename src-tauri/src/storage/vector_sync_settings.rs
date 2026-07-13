use rusqlite::{params, OptionalExtension};

use crate::memory::vector_sync_worker::{
    MemoryVectorSyncSettings, MemoryVectorSyncSettingsRepository, MemoryVectorSyncWorkerError,
    MemoryVectorSyncWorkerErrorCode,
};

use super::StorageService;

impl MemoryVectorSyncSettingsRepository for StorageService {
    fn get_vector_sync_settings(
        &self,
        life_id: &str,
    ) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError> {
        validate_life(life_id)?;
        let state = self.state().map_err(|_| storage_error())?;
        let exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                params![life_id],
                |row| row.get(0),
            )
            .map_err(|_| storage_error())?;
        if !exists {
            return Err(invalid_request());
        }
        let stored: Option<(bool, String)> = state
            .connection
            .query_row(
                "SELECT enabled, updated_at FROM memory_vector_sync_settings WHERE life_id = ?1",
                params![life_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| storage_error())?;
        Ok(match stored {
            Some((enabled, updated_at)) => MemoryVectorSyncSettings {
                life_id: life_id.to_string(),
                enabled,
                updated_at: Some(updated_at),
            },
            None => MemoryVectorSyncSettings {
                life_id: life_id.to_string(),
                enabled: false,
                updated_at: None,
            },
        })
    }

    fn set_vector_sync_enabled(
        &self,
        life_id: &str,
        enabled: bool,
    ) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError> {
        validate_life(life_id)?;
        let state = self.state().map_err(|_| storage_error())?;
        let changed = state
            .connection
            .execute(
                "INSERT INTO memory_vector_sync_settings (life_id, enabled)
                 SELECT id, ?2 FROM life_identity WHERE id = ?1
                 ON CONFLICT(life_id) DO UPDATE SET enabled = excluded.enabled,
                   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                params![life_id, enabled],
            )
            .map_err(|_| storage_error())?;
        if changed != 1 {
            return Err(invalid_request());
        }
        drop(state);
        self.get_vector_sync_settings(life_id)
    }
}

fn validate_life(life_id: &str) -> Result<(), MemoryVectorSyncWorkerError> {
    if life_id.trim().is_empty() || life_id.chars().any(char::is_control) {
        Err(invalid_request())
    } else {
        Ok(())
    }
}

fn invalid_request() -> MemoryVectorSyncWorkerError {
    MemoryVectorSyncWorkerError {
        code: MemoryVectorSyncWorkerErrorCode::InvalidRequest,
        message: "The vector sync settings request is invalid.".into(),
        recoverable: false,
        failure_class: None,
    }
}

fn storage_error() -> MemoryVectorSyncWorkerError {
    MemoryVectorSyncWorkerError {
        code: MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable,
        message: "The vector sync settings storage is unavailable.".into(),
        recoverable: true,
        failure_class: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};

    #[test]
    fn migration_004_upgrades_to_005_and_settings_default_disabled() {
        let root = tempfile::tempdir().unwrap();
        let data_root = root.path().join("data");
        std::fs::create_dir_all(&data_root).unwrap();
        let connection =
            rusqlite::Connection::open(data_root.join(super::super::DATABASE_FILE_NAME)).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(4) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-01-01T00:00:00Z')",
                    params![version, name],
                )
                .unwrap();
        }
        drop(connection);
        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona\"}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        let settings = storage.get_vector_sync_settings("life").unwrap();
        assert!(!settings.enabled);
        assert!(settings.updated_at.is_none());
        let enabled = storage.set_vector_sync_enabled("life", true).unwrap();
        assert!(enabled.enabled);
        assert!(enabled.updated_at.is_some());
        assert_eq!(
            storage
                .state()
                .unwrap()
                .connection
                .query_row("SELECT MAX(version) FROM schema_migration", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            8
        );
        drop(storage);
        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let migration_count: i64 = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 5",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
    }
}
