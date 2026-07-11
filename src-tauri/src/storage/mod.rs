use std::{fmt::Display, fs, path::PathBuf, sync::Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

const MIGRATIONS: &[(i64, &str, &str)] = &[(
    1,
    "001_initial",
    include_str!("migrations/001_initial.sql"),
)];

#[derive(Debug, Serialize)]
pub struct StorageError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl StorageError {
    fn database(error: impl Display) -> Self {
        Self {
            code: "DATABASE_ERROR".to_string(),
            message: error.to_string(),
            recoverable: true,
        }
    }

    fn not_found(entity: &str) -> Self {
        Self {
            code: "NOT_FOUND".to_string(),
            message: format!("{entity} was not found."),
            recoverable: true,
        }
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

pub struct StorageService {
    connection: Mutex<Connection>,
    #[allow(dead_code)]
    database_path: PathBuf,
}

impl StorageService {
    pub fn initialize(app: &AppHandle) -> Result<Self, StorageError> {
        let app_data_dir = app.path().app_data_dir().map_err(StorageError::database)?;
        fs::create_dir_all(&app_data_dir).map_err(StorageError::database)?;

        let database_path = app_data_dir.join("digital-life.sqlite3");
        let mut connection = Connection::open(&database_path).map_err(StorageError::database)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(StorageError::database)?;
        Self::migrate(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            database_path,
        })
    }

    fn migrate(connection: &mut Connection) -> Result<(), StorageError> {
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
                transaction.execute_batch(sql).map_err(StorageError::database)?;
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

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
        self.connection.lock().map_err(StorageError::database)
    }

    pub fn save_persona(&self, persona: PersonaTemplateRecord) -> Result<(), StorageError> {
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    version = excluded.version,
                    persona_json = excluded.persona_json",
                params![persona.id, persona.name, persona.version, persona.persona_json],
            )
            .map_err(StorageError::database)?;
        Ok(())
    }

    pub fn get_persona(&self, id: &str) -> Result<Option<PersonaTemplateRecord>, StorageError> {
        let connection = self.connection()?;
        connection
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
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StorageError::database)?;
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
        let connection = self.connection()?;
        connection
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
        let connection = self.connection()?;
        connection
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
        let connection = self.connection()?;
        let updated = connection
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

        connection
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

#[tauri::command]
pub fn initialize_storage(_storage: State<'_, StorageService>) -> Result<(), StorageError> {
    Ok(())
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
