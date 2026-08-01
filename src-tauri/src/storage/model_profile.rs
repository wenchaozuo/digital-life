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
        assert_eq!(version, 13);
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
        assert_eq!(version, 13);
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
        assert_eq!(version, 13);
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

    #[test]
    fn migration_011_preserves_rowid_with_model_profile_delete_holes() {
        let root = TestRoot::new("migration-011-rowid-profile-hole");
        let data_root = root.0.join("data");
        let connection = create_schema_10(&data_root);

        // 1. Insert 3 profiles in schema 10
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'profile-1', 'chat', 'openai_compatible', 'Profile 1',
                    'https://chat.example.invalid/v1', 'chat-model', 0.7, 4096, NULL,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'profile-2', 'chat', 'openai_compatible', 'Profile 2',
                    'https://chat.example.invalid/v1', 'chat-model', 0.7, 4096, NULL,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'profile-3', 'embedding', 'openai_compatible', 'Profile 3',
                    'https://embedding.example.invalid/v1', 'embedding-model', NULL, NULL, 1536,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();

        // 2. Verify rowids
        let rowids_before: Vec<(i64, String)> = connection
            .prepare("SELECT rowid, id FROM model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rowids_before,
            vec![
                (1, "profile-1".to_string()),
                (2, "profile-2".to_string()),
                (3, "profile-3".to_string())
            ]
        );

        // 3. Delete the first one to create a hole at rowid=1
        connection
            .execute("DELETE FROM model_profile WHERE id = 'profile-1'", [])
            .unwrap();

        // 4. Verify remaining rowids (they should still be 2 and 3, not renumbered)
        let rowids_after_delete: Vec<(i64, String)> = connection
            .prepare("SELECT rowid, id FROM model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rowids_after_delete,
            vec![(2, "profile-2".to_string()), (3, "profile-3".to_string())]
        );

        // Record other fields
        let details_before = profile_rows(&connection);

        drop(connection);

        // 5. Run migration 11 by initializing storage service
        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();

        // 6. Verify rowids after migration
        let rowids_after_migration: Vec<(i64, String)> = state
            .connection
            .prepare("SELECT rowid, id FROM model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        // They must remain exactly 2 and 3!
        assert_eq!(
            rowids_after_migration,
            vec![(2, "profile-2".to_string()), (3, "profile-3".to_string())]
        );

        // Verify other fields
        let details_after = profile_rows(&state.connection);
        assert_eq!(details_after, details_before);

        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 13);
    }

    #[test]
    fn migration_011_preserves_rowid_with_active_model_profile_delete_holes() {
        let root = TestRoot::new("migration-011-rowid-active-hole");
        let data_root = root.0.join("data");
        let connection = create_schema_10(&data_root);

        // 1. Create profiles for foreign keys
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'chat-prof', 'chat', 'openai_compatible', 'Chat Prof',
                    'https://chat.example.invalid/v1', 'chat-model', 0.7, 4096, NULL,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES (
                    'embed-prof', 'embedding', 'openai_compatible', 'Embed Prof',
                    'https://embedding.example.invalid/v1', 'embedding-model', NULL, NULL, 1536,
                    '2026-07-18T01:00:00.000Z', '2026-07-18T01:00:00.000Z'
                 )",
                [],
            )
            .unwrap();

        // 2. Create active mappings
        connection
            .execute(
                "INSERT INTO active_model_profile (purpose, profile_id) VALUES ('chat', 'chat-prof')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO active_model_profile (purpose, profile_id) VALUES ('embedding', 'embed-prof')",
                [],
            )
            .unwrap();

        let rowids_before: Vec<(i64, String, String)> = connection
            .prepare("SELECT rowid, purpose, profile_id FROM active_model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rowids_before,
            vec![
                (1, "chat".to_string(), "chat-prof".to_string()),
                (2, "embedding".to_string(), "embed-prof".to_string())
            ]
        );

        // 3. Delete the first active mapping
        connection
            .execute(
                "DELETE FROM active_model_profile WHERE purpose = 'chat'",
                [],
            )
            .unwrap();

        let rowids_after_delete: Vec<(i64, String, String)> = connection
            .prepare("SELECT rowid, purpose, profile_id FROM active_model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rowids_after_delete,
            vec![(2, "embedding".to_string(), "embed-prof".to_string())]
        );

        // 4. Re-create the chat mapping to ensure we have a rowid other than 1 and 2
        connection
            .execute(
                "INSERT INTO active_model_profile (purpose, profile_id) VALUES ('chat', 'chat-prof')",
                [],
            )
            .unwrap();

        let rowids_after_recreate: Vec<(i64, String, String)> = connection
            .prepare("SELECT rowid, purpose, profile_id FROM active_model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rowids_after_recreate,
            vec![
                (2, "embedding".to_string(), "embed-prof".to_string()),
                (3, "chat".to_string(), "chat-prof".to_string())
            ]
        );

        let details_before = active_rows(&connection);

        drop(connection);

        // 5. Run migration 11 by initializing storage service
        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();

        // 6. Verify rowids after migration
        let rowids_after_migration: Vec<(i64, String, String)> = state
            .connection
            .prepare("SELECT rowid, purpose, profile_id FROM active_model_profile ORDER BY rowid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        // They must remain exactly 2 and 3!
        assert_eq!(
            rowids_after_migration,
            vec![
                (2, "embedding".to_string(), "embed-prof".to_string()),
                (3, "chat".to_string(), "chat-prof".to_string())
            ]
        );

        // Verify other fields
        let details_after = active_rows(&state.connection);
        assert_eq!(details_after, details_before);

        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 13);
    }

    #[test]
    fn candidate_extraction_model_security_config_tests() {
        use crate::secrets::{
            delete_api_credential_with_store, has_api_credential_with_store,
            save_api_credential_with_store, ApiCredentialRequest, InMemorySecretStore,
            SaveApiCredentialRequest, SecretPurpose, SecretStoreErrorCode,
        };

        const TEST_KEY: &str = "test-placeholder-canary";

        let root = TestRoot::new("candidate-security-config");
        let storage = service(&root);
        let store = InMemorySecretStore::new();

        // 1. Create a candidate extraction profile
        let profiles = ModelProfileService::new(&storage);
        let candidate_profile = profiles.create(candidate_request("Candidate")).unwrap();
        let profile_id = &candidate_profile.id;

        // 1a. Create a chat profile and embedding profile for isolation testing
        let chat_profile = profiles.create(chat_request("Chat")).unwrap();
        let embed_profile = profiles.create(embedding_request("Embedding")).unwrap();

        // Check: Candidate Profile 无凭据时 has_secret=false
        let has_req = ApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
        };
        let status = has_api_credential_with_store(&storage, &store, has_req.clone()).unwrap();
        assert!(!status.exists);

        // Check: 保存空值被拒绝
        let save_empty_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: "   ".to_string(),
        };
        let save_empty_err =
            save_api_credential_with_store(&storage, &store, save_empty_req).unwrap_err();
        assert_eq!(save_empty_err.code, SecretStoreErrorCode::InvalidSecret);

        // Check: Profile 不存在被拒绝
        let save_non_existent = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: "non-existent-id".to_string(),
            api_key: "valid-key-123".to_string(),
        };
        let save_non_existent_err =
            save_api_credential_with_store(&storage, &store, save_non_existent).unwrap_err();
        assert_eq!(save_non_existent_err.code, SecretStoreErrorCode::NotFound);

        // Check: Chat Profile 不能通过 Candidate 命令保存 Candidate Key
        let save_chat_mismatch = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: chat_profile.id.clone(),
            api_key: "valid-key-123".to_string(),
        };
        let save_chat_mismatch_err =
            save_api_credential_with_store(&storage, &store, save_chat_mismatch).unwrap_err();
        assert_eq!(
            save_chat_mismatch_err.code,
            SecretStoreErrorCode::InvalidIdentifier
        );

        // Check: Embedding Profile 同样被拒绝
        let save_embed_mismatch = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: embed_profile.id.clone(),
            api_key: "valid-key-123".to_string(),
        };
        let save_embed_mismatch_err =
            save_api_credential_with_store(&storage, &store, save_embed_mismatch).unwrap_err();
        assert_eq!(
            save_embed_mismatch_err.code,
            SecretStoreErrorCode::InvalidIdentifier
        );

        // Check: 保存 placeholder 后为 true
        let save_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: TEST_KEY.to_string(),
        };
        let save_res = save_api_credential_with_store(&storage, &store, save_req).unwrap();
        assert!(save_res.exists || save_res.updated);

        let status2 = has_api_credential_with_store(&storage, &store, has_req.clone()).unwrap();
        assert!(status2.exists);

        // Check: 替换凭据后仍为 true
        let replace_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: "new-placeholder-key-canary".to_string(),
        };
        let replace_res = save_api_credential_with_store(&storage, &store, replace_req).unwrap();
        assert!(replace_res.exists || replace_res.updated);

        let status3 = has_api_credential_with_store(&storage, &store, has_req.clone()).unwrap();
        assert!(status3.exists);

        // Check: Candidate Key 不影响相同 ID 的其他 purpose (e.g. Chat/Embedding)
        let has_chat_mismatch = ApiCredentialRequest {
            purpose: SecretPurpose::ChatModelApiKey,
            profile_id: profile_id.clone(),
        };
        let has_chat_mismatch_err =
            has_api_credential_with_store(&storage, &store, has_chat_mismatch).unwrap_err();
        assert_eq!(
            has_chat_mismatch_err.code,
            SecretStoreErrorCode::InvalidIdentifier
        );

        // Check: Store unavailable 时查询、保存、删除均返回安全错误
        let has_unavailable_err =
            has_api_credential_with_store(&storage, &UnavailableSecretStore, has_req.clone())
                .unwrap_err();
        assert_eq!(
            has_unavailable_err.code,
            SecretStoreErrorCode::StoreUnavailable
        );

        let save_unavailable_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: TEST_KEY.to_string(),
        };
        let save_unavailable_err =
            save_api_credential_with_store(&storage, &UnavailableSecretStore, save_unavailable_req)
                .unwrap_err();
        assert_eq!(
            save_unavailable_err.code,
            SecretStoreErrorCode::StoreUnavailable
        );

        let delete_unavailable_err =
            delete_api_credential_with_store(&storage, &UnavailableSecretStore, has_req.clone())
                .unwrap_err();
        assert_eq!(
            delete_unavailable_err.code,
            SecretStoreErrorCode::StoreUnavailable
        );

        // Check: 错误不包含 placeholder、target 或底层错误
        let err_str = format!("{:?}", save_unavailable_err);
        assert!(!err_str.contains(TEST_KEY));
        assert!(!err_str.contains("Credential Manager"));

        // Check: SQLite 原始文件不包含 placeholder
        let db_bytes = std::fs::read(root.0.join("data").join(DATABASE_FILE_NAME)).unwrap();
        assert!(!db_bytes
            .windows(TEST_KEY.len())
            .any(|w| w == TEST_KEY.as_bytes()));

        // Check: 非空 Secret 的首尾字符不会被静默修改
        let key_with_spaces = "   test-canary-with-spaces   ".to_string();
        let save_spaces_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: key_with_spaces.clone(),
        };
        save_api_credential_with_store(&storage, &store, save_spaces_req).unwrap();
        let spaces_identifier = crate::secrets::SecretIdentifier::new(
            SecretPurpose::CandidateExtractionModelApiKey,
            profile_id,
        )
        .unwrap();
        assert_eq!(
            store
                .get_secret(&spaces_identifier)
                .unwrap()
                .expose_secret(),
            key_with_spaces
        );

        // Check: Candidate Profile 不能通过 Chat/Embedding purpose 错配写入
        let save_chat_mismatch_to_candidate = SaveApiCredentialRequest {
            purpose: SecretPurpose::ChatModelApiKey,
            profile_id: profile_id.clone(),
            api_key: "some-key".to_string(),
        };
        let save_chat_mismatch_to_candidate_err =
            save_api_credential_with_store(&storage, &store, save_chat_mismatch_to_candidate)
                .unwrap_err();
        assert_eq!(
            save_chat_mismatch_to_candidate_err.code,
            SecretStoreErrorCode::InvalidIdentifier
        );

        let save_embed_mismatch_to_candidate = SaveApiCredentialRequest {
            purpose: SecretPurpose::EmbeddingModelApiKey,
            profile_id: profile_id.clone(),
            api_key: "some-key".to_string(),
        };
        let save_embed_mismatch_to_candidate_err =
            save_api_credential_with_store(&storage, &store, save_embed_mismatch_to_candidate)
                .unwrap_err();
        assert_eq!(
            save_embed_mismatch_to_candidate_err.code,
            SecretStoreErrorCode::InvalidIdentifier
        );

        // Check: 相同 profile ID 的三个 purpose 凭据在 SecretStore 里互不影响
        let chat_id =
            crate::secrets::SecretIdentifier::new(SecretPurpose::ChatModelApiKey, "common-id")
                .unwrap();
        let embed_id =
            crate::secrets::SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, "common-id")
                .unwrap();
        let candidate_id = crate::secrets::SecretIdentifier::new(
            SecretPurpose::CandidateExtractionModelApiKey,
            "common-id",
        )
        .unwrap();

        store
            .set_secret(
                &chat_id,
                crate::secrets::SecretValue::new("chat-val".to_string()).unwrap(),
            )
            .unwrap();
        store
            .set_secret(
                &embed_id,
                crate::secrets::SecretValue::new("embed-val".to_string()).unwrap(),
            )
            .unwrap();
        store
            .set_secret(
                &candidate_id,
                crate::secrets::SecretValue::new("candidate-val".to_string()).unwrap(),
            )
            .unwrap();

        assert_eq!(
            store.get_secret(&chat_id).unwrap().expose_secret(),
            "chat-val"
        );
        assert_eq!(
            store.get_secret(&embed_id).unwrap().expose_secret(),
            "embed-val"
        );
        assert_eq!(
            store.get_secret(&candidate_id).unwrap().expose_secret(),
            "candidate-val"
        );

        store.delete_secret(&chat_id).unwrap();
        assert!(!store.has_secret(&chat_id).unwrap());
        assert!(store.has_secret(&embed_id).unwrap());
        assert!(store.has_secret(&candidate_id).unwrap());

        // Restore target key for profile deletion guard check
        let save_req = SaveApiCredentialRequest {
            purpose: SecretPurpose::CandidateExtractionModelApiKey,
            profile_id: profile_id.clone(),
            api_key: TEST_KEY.to_string(),
        };
        save_api_credential_with_store(&storage, &store, save_req).unwrap();

        // Check: 删除 Profile 有凭据时仍被 guard 拒绝
        let delete_profile_err =
            delete_model_profile_with_store(&storage, &store, profile_id).unwrap_err();
        assert_eq!(
            delete_profile_err.code,
            ModelProfileErrorCode::CredentialDeleteRequired
        );

        // Check: 删除后为 false
        let delete_key_res =
            delete_api_credential_with_store(&storage, &store, has_req.clone()).unwrap();
        assert!(delete_key_res.deleted);

        let status4 = has_api_credential_with_store(&storage, &store, has_req.clone()).unwrap();
        assert!(!status4.exists);

        // Check: 删除 Key 后可删除 Profile
        let delete_profile_res =
            delete_model_profile_with_store(&storage, &store, profile_id).unwrap();
        assert!(delete_profile_res.deleted);

        // Check: Active Candidate 切换不影响 Chat/Embedding
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: chat_profile.id.clone(),
            })
            .unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: embed_profile.id.clone(),
            })
            .unwrap();

        let new_candidate = profiles.create(candidate_request("New Candidate")).unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::CandidateExtraction,
                profile_id: new_candidate.id.clone(),
            })
            .unwrap();

        assert_eq!(
            profiles
                .get_active(ModelPurpose::Chat)
                .unwrap()
                .unwrap()
                .profile_id,
            chat_profile.id
        );
        assert_eq!(
            profiles
                .get_active(ModelPurpose::Embedding)
                .unwrap()
                .unwrap()
                .profile_id,
            embed_profile.id
        );
        assert_eq!(
            profiles
                .get_active(ModelPurpose::CandidateExtraction)
                .unwrap()
                .unwrap()
                .profile_id,
            new_candidate.id
        );
    }

    #[test]
    fn chat_and_embedding_model_security_config_tests() {
        use crate::secrets::{
            delete_api_credential_with_store, has_api_credential_with_store,
            save_api_credential_with_store, ApiCredentialRequest, InMemorySecretStore,
            SaveApiCredentialRequest, SecretPurpose, SecretStoreErrorCode,
        };

        let root = TestRoot::new("chat-embed-security");
        let storage = service(&root);
        let store = InMemorySecretStore::new();
        let profiles = ModelProfileService::new(&storage);

        let chat_profile = profiles.create(chat_request("Chat")).unwrap();
        let embed_profile = profiles.create(embedding_request("Embedding")).unwrap();

        // Check: save/has/del for Chat
        let chat_save = SaveApiCredentialRequest {
            purpose: SecretPurpose::ChatModelApiKey,
            profile_id: chat_profile.id.clone(),
            api_key: "chat-key".to_string(),
        };
        let chat_save_res = save_api_credential_with_store(&storage, &store, chat_save).unwrap();
        assert!(chat_save_res.exists || chat_save_res.updated);

        let chat_has = ApiCredentialRequest {
            purpose: SecretPurpose::ChatModelApiKey,
            profile_id: chat_profile.id.clone(),
        };
        assert!(
            has_api_credential_with_store(&storage, &store, chat_has.clone())
                .unwrap()
                .exists
        );

        let chat_del =
            delete_api_credential_with_store(&storage, &store, chat_has.clone()).unwrap();
        assert!(chat_del.deleted);
        assert!(
            !has_api_credential_with_store(&storage, &store, chat_has.clone())
                .unwrap()
                .exists
        );

        // Check: save/has/del for Embedding
        let embed_save = SaveApiCredentialRequest {
            purpose: SecretPurpose::EmbeddingModelApiKey,
            profile_id: embed_profile.id.clone(),
            api_key: "embed-key".to_string(),
        };
        let embed_save_res = save_api_credential_with_store(&storage, &store, embed_save).unwrap();
        assert!(embed_save_res.exists || embed_save_res.updated);

        let embed_has = ApiCredentialRequest {
            purpose: SecretPurpose::EmbeddingModelApiKey,
            profile_id: embed_profile.id.clone(),
        };
        assert!(
            has_api_credential_with_store(&storage, &store, embed_has.clone())
                .unwrap()
                .exists
        );

        let embed_del =
            delete_api_credential_with_store(&storage, &store, embed_has.clone()).unwrap();
        assert!(embed_del.deleted);
        assert!(
            !has_api_credential_with_store(&storage, &store, embed_has.clone())
                .unwrap()
                .exists
        );

        // Check: purpose mismatch
        let chat_embed_mismatch = SaveApiCredentialRequest {
            purpose: SecretPurpose::EmbeddingModelApiKey,
            profile_id: chat_profile.id.clone(),
            api_key: "wrong-key".to_string(),
        };
        let mismatch_err =
            save_api_credential_with_store(&storage, &store, chat_embed_mismatch).unwrap_err();
        assert_eq!(mismatch_err.code, SecretStoreErrorCode::InvalidIdentifier);
    }
}
