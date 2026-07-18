use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::model::profile::{
    ActiveModelProfile, DeleteModelProfileResult, ModelProfile, ModelProfileError,
    ModelProfileRepository, ModelProviderKind, ModelPurpose,
};

use super::StorageService;

const PROFILE_COLUMNS: &str = "id, purpose, provider_kind, display_name, base_url, model_name, \
    temperature, max_tokens, embedding_dimension, created_at, updated_at";

struct StoredModelProfile {
    id: String,
    purpose: String,
    provider_kind: String,
    display_name: String,
    base_url: String,
    model_name: String,
    temperature: Option<f64>,
    max_tokens: Option<i64>,
    embedding_dimension: Option<i64>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<StoredModelProfile> for ModelProfile {
    type Error = ModelProfileError;

    fn try_from(value: StoredModelProfile) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            purpose: ModelPurpose::parse(&value.purpose)?,
            provider_kind: ModelProviderKind::parse(&value.provider_kind)?,
            display_name: value.display_name,
            base_url: value.base_url,
            model_name: value.model_name,
            temperature: value.temperature,
            max_tokens: value
                .max_tokens
                .map(u32::try_from)
                .transpose()
                .map_err(|_| ModelProfileError::database())?,
            embedding_dimension: value
                .embedding_dimension
                .map(u32::try_from)
                .transpose()
                .map_err(|_| ModelProfileError::database())?,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl ModelProfileRepository for StorageService {
    fn create_profile(&self, profile: &ModelProfile) -> Result<ModelProfile, ModelProfileError> {
        let state = self.state().map_err(|_| ModelProfileError::database())?;
        state
            .connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 )",
                params![
                    profile.id,
                    profile.purpose.as_str(),
                    profile.provider_kind.as_str(),
                    profile.display_name,
                    profile.base_url,
                    profile.model_name,
                    profile.temperature,
                    profile.max_tokens,
                    profile.embedding_dimension,
                ],
            )
            .map_err(|_| ModelProfileError::database())?;
        load_profile(&state.connection, &profile.id)?.ok_or_else(ModelProfileError::database)
    }

    fn get_profile(&self, profile_id: &str) -> Result<Option<ModelProfile>, ModelProfileError> {
        let state = self.state().map_err(|_| ModelProfileError::database())?;
        load_profile(&state.connection, profile_id)
    }

    fn list_profiles(
        &self,
        purpose: Option<ModelPurpose>,
    ) -> Result<Vec<ModelProfile>, ModelProfileError> {
        let state = self.state().map_err(|_| ModelProfileError::database())?;
        let sql = format!(
            "SELECT {PROFILE_COLUMNS} FROM model_profile
             WHERE (?1 IS NULL OR purpose = ?1)
             ORDER BY display_name COLLATE NOCASE ASC, id ASC"
        );
        let mut statement = state
            .connection
            .prepare(&sql)
            .map_err(|_| ModelProfileError::database())?;
        let rows = statement
            .query_map(params![purpose.map(ModelPurpose::as_str)], read_profile)
            .map_err(|_| ModelProfileError::database())?;
        rows.map(|row| row.map_err(|_| ModelProfileError::database())?.try_into())
            .collect()
    }

    fn update_profile(&self, profile: &ModelProfile) -> Result<ModelProfile, ModelProfileError> {
        let state = self.state().map_err(|_| ModelProfileError::database())?;
        let updated = state
            .connection
            .execute(
                "UPDATE model_profile SET
                    provider_kind = ?3,
                    display_name = ?4,
                    base_url = ?5,
                    model_name = ?6,
                    temperature = ?7,
                    max_tokens = ?8,
                    embedding_dimension = ?9,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND purpose = ?2",
                params![
                    profile.id,
                    profile.purpose.as_str(),
                    profile.provider_kind.as_str(),
                    profile.display_name,
                    profile.base_url,
                    profile.model_name,
                    profile.temperature,
                    profile.max_tokens,
                    profile.embedding_dimension,
                ],
            )
            .map_err(|_| ModelProfileError::database())?;
        if updated == 0 {
            return Err(ModelProfileError::not_found());
        }
        load_profile(&state.connection, &profile.id)?.ok_or_else(ModelProfileError::database)
    }

    fn delete_profile(
        &self,
        profile_id: &str,
    ) -> Result<DeleteModelProfileResult, ModelProfileError> {
        let mut state = self.state().map_err(|_| ModelProfileError::database())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| ModelProfileError::database())?;
        let active_mapping_cleared: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM active_model_profile WHERE profile_id = ?1)",
                params![profile_id],
                |row| row.get(0),
            )
            .map_err(|_| ModelProfileError::database())?;
        let deleted = transaction
            .execute(
                "DELETE FROM model_profile WHERE id = ?1",
                params![profile_id],
            )
            .map_err(|_| ModelProfileError::database())?;
        if deleted == 0 {
            return Err(ModelProfileError::not_found());
        }
        transaction
            .commit()
            .map_err(|_| ModelProfileError::database())?;
        Ok(DeleteModelProfileResult {
            profile_id: profile_id.to_string(),
            deleted: true,
            active_mapping_cleared,
        })
    }

    fn set_active_profile(
        &self,
        purpose: ModelPurpose,
        profile_id: &str,
    ) -> Result<ActiveModelProfile, ModelProfileError> {
        let mut state = self.state().map_err(|_| ModelProfileError::database())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| ModelProfileError::database())?;
        let stored_purpose: Option<String> = transaction
            .query_row(
                "SELECT purpose FROM model_profile WHERE id = ?1",
                params![profile_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ModelProfileError::database())?;
        let stored_purpose = stored_purpose.ok_or_else(ModelProfileError::not_found)?;
        if ModelPurpose::parse(&stored_purpose)? != purpose {
            return Err(ModelProfileError::purpose_mismatch());
        }
        transaction
            .execute(
                "INSERT INTO active_model_profile (purpose, profile_id)
                 VALUES (?1, ?2)
                 ON CONFLICT(purpose) DO UPDATE SET profile_id = excluded.profile_id",
                params![purpose.as_str(), profile_id],
            )
            .map_err(|_| ModelProfileError::database())?;
        transaction
            .commit()
            .map_err(|_| ModelProfileError::database())?;
        Ok(ActiveModelProfile {
            purpose,
            profile_id: profile_id.to_string(),
        })
    }

    fn get_active_profile(
        &self,
        purpose: ModelPurpose,
    ) -> Result<Option<ActiveModelProfile>, ModelProfileError> {
        let state = self.state().map_err(|_| ModelProfileError::database())?;
        state
            .connection
            .query_row(
                "SELECT purpose, profile_id FROM active_model_profile WHERE purpose = ?1",
                params![purpose.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| ModelProfileError::database())?
            .map(|(stored_purpose, profile_id)| {
                Ok(ActiveModelProfile {
                    purpose: ModelPurpose::parse(&stored_purpose)?,
                    profile_id,
                })
            })
            .transpose()
    }
}

fn load_profile(
    connection: &Connection,
    profile_id: &str,
) -> Result<Option<ModelProfile>, ModelProfileError> {
    let sql = format!("SELECT {PROFILE_COLUMNS} FROM model_profile WHERE id = ?1");
    connection
        .query_row(&sql, params![profile_id], read_profile)
        .optional()
        .map_err(|_| ModelProfileError::database())?
        .map(TryInto::try_into)
        .transpose()
}

fn read_profile(row: &Row<'_>) -> rusqlite::Result<StoredModelProfile> {
    Ok(StoredModelProfile {
        id: row.get(0)?,
        purpose: row.get(1)?,
        provider_kind: row.get(2)?,
        display_name: row.get(3)?,
        base_url: row.get(4)?,
        model_name: row.get(5)?,
        temperature: row.get(6)?,
        max_tokens: row.get(7)?,
        embedding_dimension: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, path::PathBuf};

    use rusqlite::{params, Connection};

    use crate::{
        model::profile::{
            delete_model_profile_with_store, CreateModelProfileRequest, ListModelProfilesRequest,
            ModelProfileErrorCode, ModelProfileService, SetActiveModelProfileRequest,
            UpdateModelProfileRequest,
        },
        secrets::{
            InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStatus, SecretStore,
            SecretStoreError, SecretValue,
        },
        storage::{unique_suffix, DATABASE_FILE_NAME},
    };

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-model-profile-{name}-{}",
                unique_suffix()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn service(root: &TestRoot) -> StorageService {
        StorageService::initialize_with_roots(root.0.join("data"), None).unwrap()
    }

    fn chat_request(name: &str) -> CreateModelProfileRequest {
        CreateModelProfileRequest {
            purpose: ModelPurpose::Chat,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: name.into(),
            base_url: "https://chat.example.invalid/v1/".into(),
            model_name: "chat-model".into(),
            temperature: Some(0.7),
            max_tokens: Some(4096),
            embedding_dimension: None,
        }
    }

    fn embedding_request(name: &str) -> CreateModelProfileRequest {
        CreateModelProfileRequest {
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: name.into(),
            base_url: "https://embedding.example.invalid/v1".into(),
            model_name: "embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(1536),
        }
    }

    fn candidate_request(name: &str) -> CreateModelProfileRequest {
        CreateModelProfileRequest {
            purpose: ModelPurpose::CandidateExtraction,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: name.into(),
            base_url: "https://candidate.example.invalid/v1".into(),
            model_name: "candidate-model".into(),
            temperature: Some(0.0),
            max_tokens: Some(4096),
            embedding_dimension: None,
        }
    }

    fn create_schema_10(data_root: &Path) -> Connection {
        fs::create_dir_all(data_root).unwrap();
        let database_path = data_root.join(DATABASE_FILE_NAME);
        let mut connection = Connection::open(database_path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(10) {
            let transaction = connection.transaction().unwrap();
            transaction.execute_batch(sql).unwrap();
            transaction
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-07-18T00:00:00.000Z')",
                    params![version, name],
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        connection
    }

    #[derive(Debug, PartialEq)]
    struct ProfileRow {
        id: String,
        purpose: String,
        provider_kind: String,
        display_name: String,
        base_url: String,
        model_name: String,
        temperature: Option<f64>,
        max_tokens: Option<i64>,
        embedding_dimension: Option<i64>,
        created_at: String,
        updated_at: String,
    }

    fn profile_rows(connection: &Connection) -> Vec<ProfileRow> {
        let mut statement = connection
            .prepare(
                "SELECT id, purpose, provider_kind, display_name, base_url, model_name,
                        temperature, max_tokens, embedding_dimension, created_at, updated_at
                 FROM model_profile ORDER BY id",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok(ProfileRow {
                    id: row.get(0)?,
                    purpose: row.get(1)?,
                    provider_kind: row.get(2)?,
                    display_name: row.get(3)?,
                    base_url: row.get(4)?,
                    model_name: row.get(5)?,
                    temperature: row.get(6)?,
                    max_tokens: row.get(7)?,
                    embedding_dimension: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn active_rows(connection: &Connection) -> Vec<(String, String)> {
        let mut statement = connection
            .prepare("SELECT purpose, profile_id FROM active_model_profile ORDER BY purpose")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn foreign_key_violations(connection: &Connection) -> Vec<String> {
        let mut statement = connection.prepare("PRAGMA foreign_key_check").unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn assert_storage_files_do_not_contain(data_root: &Path, needle: &[u8]) {
        assert!(!needle.is_empty());
        for entry in fs::read_dir(data_root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes.windows(needle.len()).any(|window| window == needle));
            }
        }
    }

    struct UnavailableSecretStore;

    impl SecretStore for UnavailableSecretStore {
        fn set_secret(
            &self,
            _identifier: &SecretIdentifier,
            _value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            Err(SecretStoreError::unavailable())
        }

        fn get_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            Err(SecretStoreError::unavailable())
        }

        fn has_secret(&self, _identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            Err(SecretStoreError::unavailable())
        }

        fn delete_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            Err(SecretStoreError::unavailable())
        }
    }

    #[test]
    fn migration_002_upgrades_to_003_without_default_profiles_or_secret_columns() {
        let root = TestRoot::new("upgrade-v2");
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        connection
            .execute_batch(include_str!("migrations/001_initial.sql"))
            .unwrap();
        connection
            .execute_batch(include_str!("migrations/002_memory_core.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at) VALUES
                    (1, '001_initial', '2026-07-13T00:00:00.000Z'),
                    (2, '002_memory_core', '2026-07-13T00:00:00.000Z')",
                [],
            )
            .unwrap();
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let profile_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM model_profile", [], |row| row.get(0))
            .unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("PRAGMA table_info(model_profile)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(version, 11);
        assert_eq!(profile_count, 0);
        assert!(!columns.iter().any(|column| {
            let column = column.to_ascii_lowercase();
            column.contains("api_key")
                || column.contains("authorization")
                || column.contains("secret")
        }));
    }

    #[test]
    fn migration_003_is_idempotent() {
        let root = TestRoot::new("idempotent");
        let data_root = root.0.join("data");
        drop(StorageService::initialize_with_roots(data_root.clone(), None).unwrap());
        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 3",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn migration_011_fresh_database_enforces_candidate_schema_and_repeats_safely() {
        let root = TestRoot::new("migration-011-fresh");
        let data_root = root.0.join("data");
        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let state = storage.state().unwrap();

        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let migration_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 11
                 AND name = '011_candidate_extraction_model_profiles'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 11);
        assert_eq!(migration_count, 1);

        state
            .connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'candidate-sql', 'candidate_extraction', 'openai_compatible',
                    'Candidate SQL', 'https://candidate.example.invalid/v1', 'candidate-model',
                    0.0, 4096, NULL, '2026-07-18T01:00:00.000Z',
                    '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();
        state
            .connection
            .execute(
                "INSERT INTO active_model_profile (purpose, profile_id)
                 VALUES ('candidate_extraction', 'candidate-sql')",
                [],
            )
            .unwrap();

        for (id, temperature, max_tokens, embedding_dimension) in [
            ("candidate-no-temperature", None, Some(1_i64), None),
            ("candidate-wrong-temperature", Some(0.1), Some(1), None),
            ("candidate-no-max", Some(0.0), None, None),
            ("candidate-zero-max", Some(0.0), Some(0), None),
            ("candidate-large-max", Some(0.0), Some(4097), None),
            ("candidate-real-max", Some(0.0), Some(1), Some(1)),
        ] {
            let result = state.connection.execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    ?1, 'candidate_extraction', 'openai_compatible', 'Invalid Candidate',
                    'https://candidate.example.invalid/v1', 'candidate-model', ?2, ?3, ?4,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                params![id, temperature, max_tokens, embedding_dimension],
            );
            assert!(result.is_err());
        }

        let indexes: Vec<(String, bool, String)> = state
            .connection
            .prepare("PRAGMA index_list(model_profile)")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(1)?, row.get::<_, i64>(2)? == 1, row.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(indexes.iter().any(|(name, unique, origin)| {
            name == "idx_model_profile_purpose" && !unique && origin == "c"
        }));
        assert!(indexes
            .iter()
            .any(|(_, unique, origin)| *unique && origin == "u"));
        assert!(indexes
            .iter()
            .any(|(_, unique, origin)| *unique && origin == "pk"));

        let foreign_keys: Vec<(String, String, String, String)> = state
            .connection
            .prepare("PRAGMA foreign_key_list(active_model_profile)")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(2)?, row.get(3)?, row.get(4)?, row.get(6)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(foreign_keys.len(), 2);
        assert!(foreign_keys.iter().all(|(table, _, _, on_delete)| {
            table == "model_profile" && on_delete == "CASCADE"
        }));
        assert!(foreign_keys
            .iter()
            .any(|(_, from, to, _)| { from == "profile_id" && to == "id" }));
        assert!(foreign_keys
            .iter()
            .any(|(_, from, to, _)| from == "purpose" && to == "purpose"));
        assert!(foreign_key_violations(&state.connection).is_empty());

        let profiles_before = profile_rows(&state.connection);
        let active_before = active_rows(&state.connection);
        drop(state);
        drop(storage);

        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = reopened.state().unwrap();
        let repeated_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 11",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repeated_count, 1);
        assert_eq!(profile_rows(&state.connection), profiles_before);
        assert_eq!(active_rows(&state.connection), active_before);
        assert!(foreign_key_violations(&state.connection).is_empty());
    }

    #[test]
    fn migration_011_upgrades_real_schema_10_without_changing_existing_profiles() {
        let root = TestRoot::new("migration-011-upgrade");
        let data_root = root.0.join("data");
        let connection = create_schema_10(&data_root);
        connection
            .execute_batch(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES
                    ('legacy-chat', 'chat', 'openai_compatible', 'Legacy Chat',
                     'https://legacy-chat.example.invalid/v1', 'legacy-chat-model',
                     0.7, 8192, NULL, '2026-07-17T01:02:03.004Z',
                     '2026-07-17T05:06:07.008Z'),
                    ('legacy-embedding', 'embedding', 'openai_compatible', 'Legacy Embedding',
                     'https://legacy-embedding.example.invalid/v1', 'legacy-embedding-model',
                     NULL, NULL, 1536, '2026-07-17T09:10:11.012Z',
                     '2026-07-17T13:14:15.016Z');
                 INSERT INTO active_model_profile (purpose, profile_id) VALUES
                    ('chat', 'legacy-chat'),
                    ('embedding', 'legacy-embedding');",
            )
            .unwrap();
        let profiles_before = profile_rows(&connection);
        let active_before = active_rows(&connection);
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        assert_eq!(profile_rows(&state.connection), profiles_before);
        assert_eq!(active_rows(&state.connection), active_before);
        assert!(foreign_key_violations(&state.connection).is_empty());
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 11);
    }

    #[test]
    fn migration_011_failure_rolls_back_schema_and_migration_record() {
        let root = TestRoot::new("migration-011-rollback");
        let data_root = root.0.join("data");
        let connection = create_schema_10(&data_root);
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'corrupt-candidate', 'candidate_extraction', 'openai_compatible',
                    'Corrupt Candidate', 'https://candidate.example.invalid/v1',
                    'candidate-model', 0.5, 4096, NULL,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 );
                 PRAGMA ignore_check_constraints = OFF;",
            )
            .unwrap();
        drop(connection);

        assert!(StorageService::initialize_with_roots(data_root.clone(), None).is_err());
        let connection = Connection::open(data_root.join(DATABASE_FILE_NAME)).unwrap();
        let version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let migration_11_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 11",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let staging_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN ('model_profile_011', 'active_model_profile_011')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let table_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'model_profile'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let corrupt_row_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM model_profile WHERE id = 'corrupt-candidate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 10);
        assert_eq!(migration_11_count, 0);
        assert_eq!(staging_table_count, 0);
        assert!(!table_sql.contains("candidate_extraction"));
        assert_eq!(corrupt_row_count, 1);
    }

    #[test]
    fn creates_gets_lists_and_updates_chat_and_embedding_profiles() {
        let root = TestRoot::new("crud");
        let storage = service(&root);
        let profiles = ModelProfileService::new(&storage);
        let chat = profiles.create(chat_request("Chat")).unwrap();
        let embedding = profiles.create(embedding_request("Embedding")).unwrap();
        assert_eq!(profiles.get(&chat.id).unwrap(), chat);
        assert_eq!(profiles.get(&embedding.id).unwrap(), embedding);
        assert_eq!(
            profiles
                .list(ListModelProfilesRequest {
                    purpose: Some(ModelPurpose::Chat),
                })
                .unwrap(),
            vec![chat.clone()]
        );
        assert_eq!(
            profiles
                .list(ListModelProfilesRequest {
                    purpose: Some(ModelPurpose::Embedding),
                })
                .unwrap(),
            vec![embedding]
        );

        let updated = profiles
            .update(UpdateModelProfileRequest {
                profile_id: chat.id.clone(),
                purpose: ModelPurpose::Chat,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Updated Chat".into(),
                base_url: "https://updated.example.invalid/v1/".into(),
                model_name: "updated-model".into(),
                temperature: Some(1.0),
                max_tokens: Some(8192),
                embedding_dimension: None,
            })
            .unwrap();
        assert_eq!(updated.display_name, "Updated Chat");
        assert_eq!(updated.base_url, "https://updated.example.invalid/v1");
        assert_eq!(updated.created_at, chat.created_at);
    }

    #[test]
    fn candidate_profile_crud_and_active_mapping_are_isolated() {
        let root = TestRoot::new("candidate-crud-active");
        let storage = service(&root);
        let profiles = ModelProfileService::new(&storage);
        let chat = profiles.create(chat_request("Chat")).unwrap();
        let embedding = profiles.create(embedding_request("Embedding")).unwrap();
        let candidate = profiles
            .create(candidate_request("Candidate Extraction"))
            .unwrap();

        assert_eq!(profiles.get(&candidate.id).unwrap(), candidate);
        assert_eq!(
            profiles
                .list(ListModelProfilesRequest {
                    purpose: Some(ModelPurpose::CandidateExtraction),
                })
                .unwrap(),
            vec![candidate.clone()]
        );

        let candidate = profiles
            .update(UpdateModelProfileRequest {
                profile_id: candidate.id.clone(),
                purpose: ModelPurpose::CandidateExtraction,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Updated Candidate".into(),
                base_url: "https://updated-candidate.example.invalid/v1/".into(),
                model_name: "updated-candidate-model".into(),
                temperature: Some(0.0),
                max_tokens: Some(1),
                embedding_dimension: None,
            })
            .unwrap();
        assert_eq!(candidate.display_name, "Updated Candidate");
        assert_eq!(candidate.max_tokens, Some(1));

        for (purpose, profile_id) in [
            (ModelPurpose::Chat, chat.id.as_str()),
            (ModelPurpose::Embedding, embedding.id.as_str()),
            (ModelPurpose::CandidateExtraction, candidate.id.as_str()),
        ] {
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose,
                    profile_id: profile_id.to_string(),
                })
                .unwrap();
        }
        assert_eq!(
            profiles
                .get_active(ModelPurpose::CandidateExtraction)
                .unwrap()
                .unwrap()
                .profile_id,
            candidate.id
        );
        assert_eq!(
            profiles
                .get_active(ModelPurpose::Chat)
                .unwrap()
                .unwrap()
                .profile_id,
            chat.id
        );
        assert_eq!(
            profiles
                .get_active(ModelPurpose::Embedding)
                .unwrap()
                .unwrap()
                .profile_id,
            embedding.id
        );
        assert_eq!(
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::CandidateExtraction,
                    profile_id: chat.id.clone(),
                })
                .unwrap_err()
                .code,
            ModelProfileErrorCode::PurposeMismatch
        );
        assert_eq!(
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: candidate.id.clone(),
                })
                .unwrap_err()
                .code,
            ModelProfileErrorCode::PurposeMismatch
        );

        let duplicate_id = ModelProfile {
            id: chat.id.clone(),
            purpose: ModelPurpose::CandidateExtraction,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Duplicate".into(),
            base_url: "https://candidate.example.invalid/v1".into(),
            model_name: "candidate-model".into(),
            temperature: Some(0.0),
            max_tokens: Some(1),
            embedding_dimension: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        assert_eq!(
            storage.create_profile(&duplicate_id).unwrap_err().code,
            ModelProfileErrorCode::DatabaseError
        );

        let secrets = InMemorySecretStore::new();
        let deleted = delete_model_profile_with_store(&storage, &secrets, &candidate.id).unwrap();
        assert!(deleted.deleted);
        assert!(deleted.active_mapping_cleared);
        assert!(profiles
            .get_active(ModelPurpose::CandidateExtraction)
            .unwrap()
            .is_none());
        assert!(profiles.get_active(ModelPurpose::Chat).unwrap().is_some());
        assert!(profiles
            .get_active(ModelPurpose::Embedding)
            .unwrap()
            .is_some());
    }

    #[test]
    fn active_profiles_are_isolated_replaceable_and_purpose_checked() {
        let root = TestRoot::new("active");
        let storage = service(&root);
        let profiles = ModelProfileService::new(&storage);
        let chat_a = profiles.create(chat_request("Chat A")).unwrap();
        let chat_b = profiles.create(chat_request("Chat B")).unwrap();
        let embedding = profiles.create(embedding_request("Embedding")).unwrap();

        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: chat_a.id.clone(),
            })
            .unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: embedding.id.clone(),
            })
            .unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: chat_b.id.clone(),
            })
            .unwrap();
        assert_eq!(
            profiles
                .get_active(ModelPurpose::Chat)
                .unwrap()
                .unwrap()
                .profile_id,
            chat_b.id
        );
        assert_eq!(
            profiles
                .get_active(ModelPurpose::Embedding)
                .unwrap()
                .unwrap()
                .profile_id,
            embedding.id
        );
        assert_eq!(
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Embedding,
                    profile_id: chat_a.id,
                })
                .unwrap_err()
                .code,
            ModelProfileErrorCode::PurposeMismatch
        );
    }

    #[test]
    fn deleting_active_profile_clears_only_its_mapping_and_selects_no_default() {
        let root = TestRoot::new("delete-active");
        let storage = service(&root);
        let profiles = ModelProfileService::new(&storage);
        let chat = profiles.create(chat_request("Chat")).unwrap();
        let other = profiles.create(chat_request("Other")).unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: chat.id.clone(),
            })
            .unwrap();
        let secrets = InMemorySecretStore::new();
        let result = delete_model_profile_with_store(&storage, &secrets, &chat.id).unwrap();
        assert!(result.deleted);
        assert!(result.active_mapping_cleared);
        assert!(profiles.get_active(ModelPurpose::Chat).unwrap().is_none());
        assert_eq!(profiles.get(&other.id).unwrap(), other);
    }

    #[test]
    fn deletion_guard_protects_all_profile_purposes_and_fails_closed() {
        let root = TestRoot::new("credential-delete-guard");
        let data_root = root.0.join("data");
        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let profiles = ModelProfileService::new(&storage);
        let secrets = InMemorySecretStore::new();
        let placeholder = format!("placeholder-{}-{}", std::process::id(), unique_suffix());

        for (request, secret_purpose) in [
            (chat_request("Guarded Chat"), SecretPurpose::ChatModelApiKey),
            (
                embedding_request("Guarded Embedding"),
                SecretPurpose::EmbeddingModelApiKey,
            ),
            (
                candidate_request("Guarded Candidate"),
                SecretPurpose::CandidateExtractionModelApiKey,
            ),
        ] {
            let profile = profiles.create(request).unwrap();
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: profile.purpose,
                    profile_id: profile.id.clone(),
                })
                .unwrap();
            let identifier = SecretIdentifier::new(secret_purpose, profile.id.clone()).unwrap();
            secrets
                .set_secret(&identifier, SecretValue::new(placeholder.clone()).unwrap())
                .unwrap();

            let error =
                delete_model_profile_with_store(&storage, &secrets, &profile.id).unwrap_err();
            assert_eq!(error.code, ModelProfileErrorCode::CredentialDeleteRequired);
            assert!(error.recoverable);
            let error_json = serde_json::to_string(&error).unwrap();
            assert!(!error_json.contains(&placeholder));
            assert!(!error_json.contains("com.digitallife.app"));
            assert!(profiles.get(&profile.id).is_ok());
            assert!(secrets.has_secret(&identifier).unwrap());

            secrets.delete_secret(&identifier).unwrap();
            let deleted = delete_model_profile_with_store(&storage, &secrets, &profile.id).unwrap();
            assert!(deleted.deleted);
            assert!(deleted.active_mapping_cleared);
            assert_eq!(
                profiles.get(&profile.id).unwrap_err().code,
                ModelProfileErrorCode::ProfileNotFound
            );
            assert!(!secrets.has_secret(&identifier).unwrap());
        }

        let unavailable_profile = profiles.create(chat_request("Unavailable Store")).unwrap();
        let error = delete_model_profile_with_store(
            &storage,
            &UnavailableSecretStore,
            &unavailable_profile.id,
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            ModelProfileErrorCode::CredentialStoreUnavailable
        );
        assert!(error.recoverable);
        assert!(profiles.get(&unavailable_profile.id).is_ok());
        let error_json = serde_json::to_string(&error).unwrap();
        assert!(!error_json.contains("com.digitallife.app"));
        assert!(!error_json.contains(&placeholder));

        drop(storage);
        assert_storage_files_do_not_contain(&data_root, placeholder.as_bytes());
    }

    #[test]
    fn serialized_dto_contains_configuration_but_no_secret_fields() {
        let root = TestRoot::new("serialization");
        let storage = service(&root);
        let profile = ModelProfileService::new(&storage)
            .create(chat_request("Chat"))
            .unwrap();
        let json = serde_json::to_string(&profile)
            .unwrap()
            .to_ascii_lowercase();
        assert!(!json.contains("api_key"));
        assert!(!json.contains("apikey"));
        assert!(!json.contains("authorization"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("secret"));
    }
}
