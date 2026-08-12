//! Bounded, credential-free reuse of existing LanceDB connections.

use std::{
    collections::VecDeque,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::Serialize;

use super::{
    generation_store_root, ExistingGenerationVectorStoreProvider, LanceDbVectorStore,
    VectorGenerationId, VectorStore, VectorStoreError, VectorStoreErrorCode, VectorStoreFuture,
};

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
    generation_key: Option<GenerationRegistryKey>,
    store: Arc<LanceDbVectorStore>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenerationRegistryKey {
    root_identity: PathBuf,
    generation_id: VectorGenerationId,
}

/// Registry for derived vector stores only. It retains neither profiles nor
/// credentials, and it never creates a missing index directory.
pub struct LanceDbVectorStoreRegistry {
    capacity: usize,
    stores: Mutex<VecDeque<CachedStore>>,
}

/// A registry provider permanently bound to one canonical data-root snapshot.
/// It can only resolve an already-existing generation directory.
#[allow(dead_code)] // The S3 runner is intentionally not wired in DB1.
pub(crate) struct BoundExistingGenerationVectorStoreProvider<'a> {
    registry: &'a LanceDbVectorStoreRegistry,
    data_root: PathBuf,
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

    /// Binds an existing-generation-only provider to the caller's canonical
    /// data-root identity. This never creates a vector directory.
    #[allow(dead_code)] // The S3 runner is intentionally not wired in DB1.
    pub(crate) fn bind_existing_generation_provider(
        &self,
        data_root: &Path,
    ) -> Result<BoundExistingGenerationVectorStoreProvider<'_>, VectorStoreError> {
        let data_root = root_identity(data_root).map_err(|_| {
            VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "The derived vector store is unavailable.",
                true,
            )
        })?;
        Ok(BoundExistingGenerationVectorStoreProvider {
            registry: self,
            data_root,
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
            generation_key: None,
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
            generation_key: None,
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

    /// Opens (or creates) a generation-specific Lance directory under
    /// `<dataRoot>/vectors/generations/<id>/lancedb`.
    /// Does not touch the legacy `<dataRoot>/vectors/lancedb` path.
    pub async fn generation_store_for_write(
        &self,
        data_root: &Path,
        generation_id: &VectorGenerationId,
    ) -> Result<Arc<LanceDbVectorStore>, LanceDbVectorStoreRegistryError> {
        let key = generation_registry_key(data_root, generation_id)?;
        let index_root = generation_store_root(data_root, generation_id);
        if index_root.exists() && !index_root.is_dir() {
            return Err(error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable));
        }
        if index_root.is_dir() {
            if let Some(store) = self.lookup_generation(&key)? {
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
        self.insert_generation_cache(canonical_root, key, Arc::clone(&store))?;
        Ok(store)
    }

    /// Returns an existing generation store without creating the directory.
    pub async fn existing_generation_store(
        &self,
        data_root: &Path,
        generation_id: &VectorGenerationId,
    ) -> Result<Option<Arc<LanceDbVectorStore>>, LanceDbVectorStoreRegistryError> {
        let key = generation_registry_key(data_root, generation_id)?;
        let index_root = generation_store_root(data_root, generation_id);
        if !index_root.exists() {
            return Ok(None);
        }
        if !index_root.is_dir() {
            return Err(error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable));
        }
        let canonical_root = std::fs::canonicalize(&index_root)
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        if let Some(store) = self.lookup_generation(&key)? {
            return Ok(Some(store));
        }
        let store = Arc::new(
            LanceDbVectorStore::open(&canonical_root)
                .await
                .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?,
        );
        self.insert_generation_cache(canonical_root, key, Arc::clone(&store))?;
        Ok(Some(store))
    }

    /// Releases registry handles for a generation and deletes its directory.
    /// Idempotent when the generation does not exist.
    pub async fn drop_generation(
        &self,
        data_root: &Path,
        generation_id: &VectorGenerationId,
    ) -> Result<(), VectorStoreError> {
        let key = generation_registry_key_for_drop(data_root, generation_id)?;
        let index_root = generation_store_root(data_root, generation_id);
        // Release only the exact root + generation cache entry before deleting.
        {
            let mut stores = self.stores.lock().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::GenerationLocked,
                    "The vector generation is locked by an open handle.",
                    true,
                )
            })?;
            stores.retain(|entry| entry.generation_key.as_ref() != Some(&key));
        }
        LanceDbVectorStore::drop_generation_directory(&index_root).await
    }

    fn lookup_generation(
        &self,
        key: &GenerationRegistryKey,
    ) -> Result<Option<Arc<LanceDbVectorStore>>, LanceDbVectorStoreRegistryError> {
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        let Some(position) = stores
            .iter()
            .position(|entry| entry.generation_key.as_ref() == Some(key))
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

    fn insert_generation_cache(
        &self,
        canonical_root: PathBuf,
        generation_key: GenerationRegistryKey,
        store: Arc<LanceDbVectorStore>,
    ) -> Result<(), LanceDbVectorStoreRegistryError> {
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))?;
        if let Some(position) = stores
            .iter()
            .position(|entry| entry.generation_key.as_ref() == Some(&generation_key))
        {
            let entry = stores
                .remove(position)
                .expect("position was derived from deque");
            stores.push_front(entry);
            return Ok(());
        }
        stores.push_front(CachedStore {
            canonical_root,
            generation_key: Some(generation_key),
            store,
        });
        while stores.len() > self.capacity {
            stores.pop_back();
        }
        Ok(())
    }

    #[cfg(test)]
    fn cached_count(&self) -> usize {
        self.stores
            .lock()
            .map(|stores| stores.len())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn has_cached_generation(&self, data_root: &Path, generation_id: &VectorGenerationId) -> bool {
        let Ok(key) = generation_registry_key(data_root, generation_id) else {
            return false;
        };
        self.stores
            .lock()
            .map(|stores| {
                stores
                    .iter()
                    .any(|entry| entry.generation_key.as_ref() == Some(&key))
            })
            .unwrap_or(false)
    }
}

impl ExistingGenerationVectorStoreProvider for BoundExistingGenerationVectorStoreProvider<'_> {
    fn existing_for_generation<'a>(
        &'a self,
        generation_id: &'a VectorGenerationId,
    ) -> VectorStoreFuture<'a, Result<Arc<dyn VectorStore>, VectorStoreError>> {
        Box::pin(async move {
            match self
                .registry
                .existing_generation_store(&self.data_root, generation_id)
                .await
            {
                Ok(Some(store)) => {
                    let store: Arc<dyn VectorStore> = store;
                    Ok(store)
                }
                Ok(None) => Err(VectorStoreError::new(
                    VectorStoreErrorCode::GenerationNotFound,
                    "The requested vector generation does not exist.",
                    false,
                )),
                Err(_) => Err(VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The derived vector store is unavailable.",
                    true,
                )),
            }
        })
    }
}

fn generation_registry_key(
    data_root: &Path,
    generation_id: &VectorGenerationId,
) -> Result<GenerationRegistryKey, LanceDbVectorStoreRegistryError> {
    root_identity(data_root)
        .map(|root_identity| GenerationRegistryKey {
            root_identity,
            generation_id: generation_id.clone(),
        })
        .map_err(|_| error(LanceDbVectorStoreRegistryErrorCode::StoreUnavailable))
}

fn generation_registry_key_for_drop(
    data_root: &Path,
    generation_id: &VectorGenerationId,
) -> Result<GenerationRegistryKey, VectorStoreError> {
    root_identity(data_root)
        .map(|root_identity| GenerationRegistryKey {
            root_identity,
            generation_id: generation_id.clone(),
        })
        .map_err(|_| {
            VectorStoreError::new(
                VectorStoreErrorCode::GenerationDropFailed,
                "The vector generation could not be dropped.",
                true,
            )
        })
}

fn root_identity(data_root: &Path) -> std::io::Result<PathBuf> {
    let absolute = std::path::absolute(data_root)?;
    let lexical = lexical_normalize(&absolute);
    if lexical.exists() {
        std::fs::canonicalize(lexical)
    } else {
        Ok(lexical)
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                let _ = normalized.pop();
            }
        }
    }
    normalized
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
    use crate::vector_store::{
        ExistingGenerationVectorStoreProvider, GenerationVectorRecord, VectorGenerationContext,
        VectorStore,
    };
    use std::sync::Arc;

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

    #[test]
    fn generation_paths_are_isolated_from_legacy_and_drop_releases_handles() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let registry = LanceDbVectorStoreRegistry::default();
            let gen = VectorGenerationId::parse("gen-drop-1").unwrap();
            let store = registry
                .generation_store_for_write(temp.path(), &gen)
                .await
                .unwrap();
            let gen_path = generation_store_root(temp.path(), &gen);
            assert!(gen_path.is_dir());
            assert!(!temp.path().join("vectors").join("lancedb").exists());
            drop(store);
            registry.drop_generation(temp.path(), &gen).await.unwrap();
            assert!(!gen_path.exists());
            // Idempotent drop.
            registry.drop_generation(temp.path(), &gen).await.unwrap();
        });
    }

    #[test]
    fn generation_cache_and_drop_are_isolated_by_root_and_generation_identity() {
        tauri::async_runtime::block_on(async {
            let root_a = tempfile::tempdir().unwrap();
            let root_b = tempfile::tempdir().unwrap();
            let missing_root = tempfile::tempdir().unwrap();
            let registry = LanceDbVectorStoreRegistry::default();
            let generation = VectorGenerationId::parse("same-generation").unwrap();
            let context =
                VectorGenerationContext::new(generation.clone(), "same-generation-descriptor", 2)
                    .unwrap();

            let a = registry
                .generation_store_for_write(root_a.path(), &generation)
                .await
                .unwrap();
            let b = registry
                .generation_store_for_write(root_b.path(), &generation)
                .await
                .unwrap();
            a.create_generation(&context).await.unwrap();
            b.create_generation(&context).await.unwrap();
            b.upsert_generation(
                &context,
                GenerationVectorRecord::try_new(
                    generation.clone(),
                    "life-b",
                    "memory-b",
                    1,
                    "content-memory-b",
                    context.descriptor_hash(),
                    vec![1.0, 0.0],
                )
                .unwrap(),
            )
            .await
            .unwrap();
            assert!(registry.has_cached_generation(root_a.path(), &generation));
            assert!(registry.has_cached_generation(root_b.path(), &generation));

            // A missing root with the same generation identifier must not evict B.
            registry
                .drop_generation(missing_root.path(), &generation)
                .await
                .unwrap();
            assert!(registry.has_cached_generation(root_b.path(), &generation));
            let reopened_b = registry
                .existing_generation_store(root_b.path(), &generation)
                .await
                .unwrap()
                .unwrap();
            assert!(Arc::ptr_eq(&b, &reopened_b));

            let path_a = generation_store_root(root_a.path(), &generation);
            let path_b = generation_store_root(root_b.path(), &generation);
            drop(a);
            registry
                .drop_generation(root_a.path(), &generation)
                .await
                .unwrap();
            assert!(!path_a.exists());
            assert!(path_b.exists());
            assert!(!registry.has_cached_generation(root_a.path(), &generation));
            assert!(registry.has_cached_generation(root_b.path(), &generation));
            assert_eq!(b.count_generation(&context, None).await.unwrap(), 1);
        });
    }

    #[test]
    fn generation_registry_drop_supports_unicode_data_roots() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let unicode_root = temp.path().join("向量索引根目录");
            let registry = LanceDbVectorStoreRegistry::default();
            let generation = VectorGenerationId::parse("unicode-generation").unwrap();
            let store = registry
                .generation_store_for_write(&unicode_root, &generation)
                .await
                .unwrap();
            let generation_root = generation_store_root(&unicode_root, &generation);
            assert!(generation_root.is_dir());
            drop(store);
            registry
                .drop_generation(&unicode_root, &generation)
                .await
                .unwrap();
            assert!(!generation_root.exists());
        });
    }

    #[test]
    fn bound_existing_generation_provider_opens_only_the_requested_generation() {
        tauri::async_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let registry = LanceDbVectorStoreRegistry::default();
            let g1 = VectorGenerationId::parse("generation-one").unwrap();
            let g2 = VectorGenerationId::parse("generation-two").unwrap();
            let context = VectorGenerationContext::new(g2.clone(), "descriptor-two", 2).unwrap();
            let g2_store = registry
                .generation_store_for_write(temp.path(), &g2)
                .await
                .unwrap();
            g2_store.create_generation(&context).await.unwrap();
            let legacy = temp.path().join("vectors").join("lancedb");
            std::fs::create_dir_all(&legacy).unwrap();

            let provider = registry
                .bind_existing_generation_provider(temp.path())
                .unwrap();
            assert!(provider.existing_for_generation(&g2).await.is_ok());
            let missing = match provider.existing_for_generation(&g1).await {
                Err(error) => error,
                Ok(_) => panic!("a missing generation must not resolve a store"),
            };
            assert_eq!(missing.code, VectorStoreErrorCode::GenerationNotFound);
            assert!(
                legacy.is_dir(),
                "legacy path is neither opened nor replaced"
            );
            assert!(!generation_store_root(temp.path(), &g1).exists());
        });
    }
}
