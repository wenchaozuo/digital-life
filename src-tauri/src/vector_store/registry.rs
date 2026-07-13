//! Bounded, credential-free reuse of existing LanceDB connections.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::Serialize;

use super::LanceDbVectorStore;

pub const DEFAULT_MAX_CACHED_STORES: usize = 4;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LanceDbVectorStoreRegistryErrorCode {
    InvalidConfiguration,
    StoreUnavailable,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LanceDbVectorStoreRegistryError {
    pub code: LanceDbVectorStoreRegistryErrorCode,
    pub message: String,
    pub recoverable: bool,
}

struct CachedStore {
    canonical_root: PathBuf,
    store: Arc<LanceDbVectorStore>,
}

/// Registry for derived vector stores only. It retains neither profiles nor
/// credentials, and it never creates a missing index directory.
pub struct LanceDbVectorStoreRegistry {
    capacity: usize,
    stores: Mutex<VecDeque<CachedStore>>,
}

impl Default for LanceDbVectorStoreRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CACHED_STORES).expect("default registry capacity is valid")
    }
}

impl LanceDbVectorStoreRegistry {
    pub fn new(capacity: usize) -> Result<Self, LanceDbVectorStoreRegistryError> {
        if capacity == 0 {
            return Err(error(
                LanceDbVectorStoreRegistryErrorCode::InvalidConfiguration,
            ));
        }
        Ok(Self {
            capacity,
            stores: Mutex::new(VecDeque::new()),
        })
    }

    /// Returns `Ok(None)` when the derived index directory does not exist.
    /// It deliberately avoids `LanceDbVectorStore::open` in that case because
    /// opening initializes a directory.
    pub async fn existing_store(
        &self,
        data_root: &Path,
    ) -> Result<Option<Arc<LanceDbVectorStore>>, LanceDbVectorStoreRegistryError> {
        let index_root = data_root.join("vectors").join("lancedb");
        if !index_root.exists() {
            return Ok(None);
        }
        if !index_root.is_dir() {
            return Err(error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable));
        }
        let canonical_root = std::fs::canonicalize(&index_root)
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        if let Some(store) = self.lookup(&canonical_root)? {
            return Ok(Some(store));
        }

        let store = Arc::new(
            LanceDbVectorStore::open(&canonical_root)
                .await
                .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?,
        );
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        if let Some(position) = stores
            .iter()
            .position(|entry| entry.canonical_root == canonical_root)
        {
            let entry = stores
                .remove(position)
                .expect("position was derived from deque");
            let existing = Arc::clone(&entry.store);
            stores.push_front(entry);
            return Ok(Some(existing));
        }
        stores.push_front(CachedStore {
            canonical_root,
            store: Arc::clone(&store),
        });
        while stores.len() > self.capacity {
            stores.pop_back();
        }
        Ok(Some(store))
    }

    /// Opens the derived index for an explicitly authorized write operation.
    /// Unlike `existing_store`, this is allowed to initialize the fixed
    /// `<dataRoot>/vectors/lancedb` directory.
    pub async fn store_for_write(
        &self,
        data_root: &Path,
    ) -> Result<Arc<LanceDbVectorStore>, LanceDbVectorStoreRegistryError> {
        let index_root = data_root.join("vectors").join("lancedb");
        if index_root.exists() && !index_root.is_dir() {
            return Err(error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable));
        }
        if index_root.is_dir() {
            let canonical_root = std::fs::canonicalize(&index_root)
                .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
            if let Some(store) = self.lookup(&canonical_root)? {
                return Ok(store);
            }
        }
        let store = Arc::new(
            LanceDbVectorStore::open(&index_root)
                .await
                .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?,
        );
        let canonical_root = std::fs::canonicalize(&index_root)
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        if let Some(position) = stores
            .iter()
            .position(|entry| entry.canonical_root == canonical_root)
        {
            let entry = stores
                .remove(position)
                .expect("position was derived from deque");
            let existing = Arc::clone(&entry.store);
            stores.push_front(entry);
            return Ok(existing);
        }
        stores.push_front(CachedStore {
            canonical_root,
            store: Arc::clone(&store),
        });
        while stores.len() > self.capacity {
            stores.pop_back();
        }
        Ok(store)
    }

    fn lookup(
        &self,
        canonical_root: &Path,
    ) -> Result<Option<Arc<LanceDbVectorStore>>, LanceDbVectorStoreRegistryError> {
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        let Some(position) = stores
            .iter()
            .position(|entry| entry.canonical_root == canonical_root)
        else {
            return Ok(None);
        };
        let entry = stores
            .remove(position)
            .expect("position was derived from deque");
        let store = Arc::clone(&entry.store);
        stores.push_front(entry);
        Ok(Some(store))
    }

    #[cfg(test)]
    fn cached_count(&self) -> usize {
        self.stores
            .lock()
            .map(|stores| stores.len())
            .unwrap_or_default()
    }
}

fn error(code: LanceDbVectorStoreRegistryErrorCode) -> LanceDbVectorStoreRegistryError {
    let (message, recoverable) = match code {
        LanceDbVectorStoreRegistryErrorCode::InvalidConfiguration => {
            ("The vector store registry configuration is invalid.", false)
        }
        LanceDbVectorStoreRegistryErrorCode::StoreUnavailable => {
            ("The derived vector store is unavailable.", true)
        }
    };
    LanceDbVectorStoreRegistryError {
        code,
        message: message.to_string(),
        recoverable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_directory_is_not_created() {
        let temp = tempfile::tempdir().unwrap();
        let registry = LanceDbVectorStoreRegistry::default();
        let result = tauri::async_runtime::block_on(registry.existing_store(temp.path())).unwrap();
        assert!(result.is_none());
        assert!(!temp.path().join("vectors").exists());
    }

    #[test]
    fn non_directory_index_path_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let index = temp.path().join("vectors").join("lancedb");
        std::fs::create_dir_all(index.parent().unwrap()).unwrap();
        std::fs::write(&index, "not a database directory").unwrap();

        let registry = LanceDbVectorStoreRegistry::default();
        let error = match tauri::async_runtime::block_on(registry.existing_store(temp.path())) {
            Err(error) => error,
            Ok(_) => panic!("a file at the index path must be rejected"),
        };
        assert_eq!(
            error.code,
            LanceDbVectorStoreRegistryErrorCode::StoreUnavailable
        );
        assert!(!error.message.contains(&index.display().to_string()));
    }

    #[test]
    fn roots_are_cached_and_bounded() {
        tauri::async_runtime::block_on(async {
            let registry = LanceDbVectorStoreRegistry::new(2).unwrap();
            let roots = (0..3)
                .map(|_| tempfile::tempdir().unwrap())
                .collect::<Vec<_>>();
            for root in &roots {
                let index = root.path().join("vectors").join("lancedb");
                std::fs::create_dir_all(index).unwrap();
                assert!(registry
                    .existing_store(root.path())
                    .await
                    .unwrap()
                    .is_some());
            }
            assert_eq!(registry.cached_count(), 2);
            assert!(registry
                .existing_store(roots[2].path())
                .await
                .unwrap()
                .is_some());
            assert_eq!(registry.cached_count(), 2);
        });
    }
}
