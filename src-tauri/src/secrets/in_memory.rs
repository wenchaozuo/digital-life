use std::{collections::HashMap, sync::Mutex};

use super::{SecretIdentifier, SecretStatus, SecretStore, SecretStoreError, SecretValue};

/// Deterministic test store. Values remain only in zeroizing memory and the map
/// is cleared when the store is dropped.
pub(crate) struct InMemorySecretStore {
    values: Mutex<HashMap<SecretIdentifier, SecretValue>>,
}

impl InMemorySecretStore {
    pub(crate) fn new() -> Self {
        Self {
            values: Mutex::new(HashMap::new()),
        }
    }

    fn values(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<SecretIdentifier, SecretValue>>, SecretStoreError>
    {
        self.values.lock().map_err(|_| SecretStoreError::internal())
    }
}

impl SecretStore for InMemorySecretStore {
    fn set_secret(
        &self,
        identifier: &SecretIdentifier,
        value: SecretValue,
    ) -> Result<SecretStatus, SecretStoreError> {
        identifier.validate()?;
        self.values()?.insert(identifier.clone(), value);
        Ok(SecretStatus {
            exists: true,
            updated: true,
            deleted: false,
        })
    }

    fn get_secret(&self, identifier: &SecretIdentifier) -> Result<SecretValue, SecretStoreError> {
        identifier.validate()?;
        let values = self.values()?;
        let value = values
            .get(identifier)
            .ok_or_else(SecretStoreError::not_found)?;
        SecretValue::new(value.expose_secret().to_owned())
    }

    fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
        identifier.validate()?;
        Ok(self.values()?.contains_key(identifier))
    }

    fn delete_secret(
        &self,
        identifier: &SecretIdentifier,
    ) -> Result<SecretStatus, SecretStoreError> {
        identifier.validate()?;
        let deleted = self.values()?.remove(identifier).is_some();
        Ok(SecretStatus {
            exists: false,
            updated: false,
            deleted,
        })
    }
}

impl Drop for InMemorySecretStore {
    fn drop(&mut self) {
        if let Ok(values) = self.values.get_mut() {
            values.clear();
        }
    }
}
