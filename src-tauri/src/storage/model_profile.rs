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
    use std::{fs, path::PathBuf};

    use rusqlite::Connection;

    use crate::{
        model::profile::{
            CreateModelProfileRequest, ListModelProfilesRequest, ModelProfileErrorCode,
            ModelProfileService, SetActiveModelProfileRequest, UpdateModelProfileRequest,
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
        assert_eq!(version, 4);
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
        let result = profiles.delete(&chat.id).unwrap();
        assert!(result.deleted);
        assert!(result.active_mapping_cleared);
        assert!(profiles.get_active(ModelPurpose::Chat).unwrap().is_none());
        assert_eq!(profiles.get(&other.id).unwrap(), other);
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
