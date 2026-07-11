use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{StorageError, DATABASE_FILE_NAME};

pub const LOCATION_CONFIG_FILE_NAME: &str = "storage-location.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageLocationConfig {
    active_data_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct StorageLocationResolver {
    default_root: PathBuf,
    config_path: PathBuf,
    project_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum ConfigSnapshot {
    Missing,
    Existing(Vec<u8>),
}

impl StorageLocationResolver {
    pub fn new(default_root: PathBuf, project_root: Option<PathBuf>) -> Self {
        let config_path = default_root.join(LOCATION_CONFIG_FILE_NAME);
        Self {
            default_root,
            config_path,
            project_root,
        }
    }

    pub fn default_root(&self) -> &Path {
        &self.default_root
    }

    pub fn resolve_active_root(&self) -> Result<PathBuf, StorageError> {
        fs::create_dir_all(&self.default_root).map_err(|error| {
            StorageError::new(
                "DEFAULT_STORAGE_UNAVAILABLE",
                format!("Cannot create the default data directory: {error}"),
                false,
            )
        })?;

        if !self.config_path.exists() {
            return Ok(self.default_root.clone());
        }

        let configured_root = match self.read_config() {
            Ok(config) => config.active_data_root,
            Err(error) => return self.fallback_to_default(error),
        };

        if configured_root == self.default_root {
            return Ok(self.default_root.clone());
        }

        let configured_database = configured_root.join(DATABASE_FILE_NAME);
        if configured_root.is_absolute()
            && configured_root.is_dir()
            && configured_database.is_file()
        {
            return Ok(configured_root);
        }

        self.fallback_to_default(StorageError::new(
            "CONFIGURED_STORAGE_UNAVAILABLE",
            "The configured data directory or database is unavailable.",
            false,
        ))
    }

    fn fallback_to_default(&self, original_error: StorageError) -> Result<PathBuf, StorageError> {
        if self.default_root.join(DATABASE_FILE_NAME).is_file() {
            Ok(self.default_root.clone())
        } else {
            Err(original_error)
        }
    }

    fn read_config(&self) -> Result<StorageLocationConfig, StorageError> {
        let bytes = fs::read(&self.config_path).map_err(|error| {
            StorageError::new(
                "STORAGE_CONFIG_READ_FAILED",
                format!("Cannot read the storage location configuration: {error}"),
                false,
            )
        })?;

        serde_json::from_slice(&bytes).map_err(|error| {
            StorageError::new(
                "STORAGE_CONFIG_INVALID",
                format!("The storage location configuration is invalid: {error}"),
                false,
            )
        })
    }

    pub fn validate_candidate(
        &self,
        candidate: &str,
        current_root: &Path,
    ) -> Result<PathBuf, StorageError> {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return Err(StorageError::new(
                "STORAGE_PATH_EMPTY",
                "The candidate data directory cannot be empty.",
                true,
            ));
        }

        let candidate = PathBuf::from(trimmed);
        if !candidate.is_absolute() {
            return Err(StorageError::new(
                "STORAGE_PATH_NOT_ABSOLUTE",
                "The candidate data directory must be an absolute path.",
                true,
            ));
        }

        if contains_forbidden_component(&candidate) {
            return Err(StorageError::new(
                "STORAGE_PATH_FORBIDDEN",
                "The data directory cannot be inside node_modules, target, or dist.",
                true,
            ));
        }

        if let Some(project_root) = &self.project_root {
            if let Ok(canonical_project) = fs::canonicalize(project_root) {
                if candidate.starts_with(&canonical_project) {
                    return Err(StorageError::new(
                        "STORAGE_PATH_IN_PROJECT",
                        "The data directory cannot be inside the project source directory.",
                        true,
                    ));
                }
            }
        }

        if candidate.exists() && !candidate.is_dir() {
            return Err(StorageError::new(
                "STORAGE_PATH_IS_FILE",
                "The candidate path is a file, not a directory.",
                true,
            ));
        }

        fs::create_dir_all(&candidate).map_err(|error| {
            StorageError::new(
                "STORAGE_PATH_CREATE_FAILED",
                format!("Cannot create the candidate data directory: {error}"),
                true,
            )
        })?;

        let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
            StorageError::new(
                "STORAGE_PATH_RESOLVE_FAILED",
                format!("Cannot resolve the candidate data directory: {error}"),
                true,
            )
        })?;
        let canonical_current = fs::canonicalize(current_root).map_err(|error| {
            StorageError::new(
                "CURRENT_STORAGE_RESOLVE_FAILED",
                format!("Cannot resolve the current data directory: {error}"),
                false,
            )
        })?;

        if canonical_candidate == canonical_current {
            return Err(StorageError::new(
                "STORAGE_PATH_UNCHANGED",
                "The candidate data directory is the current data directory.",
                true,
            ));
        }

        if let Some(project_root) = &self.project_root {
            if let Ok(canonical_project) = fs::canonicalize(project_root) {
                if canonical_candidate.starts_with(canonical_project) {
                    return Err(StorageError::new(
                        "STORAGE_PATH_IN_PROJECT",
                        "The data directory cannot be inside the project source directory.",
                        true,
                    ));
                }
            }
        }

        verify_writable(&canonical_candidate)?;
        Ok(canonical_candidate)
    }

    pub fn capture_config(&self) -> Result<ConfigSnapshot, StorageError> {
        if !self.config_path.exists() {
            return Ok(ConfigSnapshot::Missing);
        }

        fs::read(&self.config_path)
            .map(ConfigSnapshot::Existing)
            .map_err(|error| {
                StorageError::new(
                    "STORAGE_CONFIG_READ_FAILED",
                    format!("Cannot snapshot the storage location configuration: {error}"),
                    false,
                )
            })
    }

    pub fn write_active_root(&self, root: &Path) -> Result<(), StorageError> {
        let config = StorageLocationConfig {
            active_data_root: root.to_path_buf(),
        };
        let bytes = serde_json::to_vec_pretty(&config).map_err(|error| {
            StorageError::new(
                "STORAGE_CONFIG_SERIALIZE_FAILED",
                format!("Cannot serialize the storage location configuration: {error}"),
                false,
            )
        })?;
        self.atomic_write(&bytes)
    }

    pub fn restore_config(&self, snapshot: &ConfigSnapshot) -> Result<(), StorageError> {
        match snapshot {
            ConfigSnapshot::Missing => {
                if self.config_path.exists() {
                    fs::remove_file(&self.config_path).map_err(|error| {
                        StorageError::new(
                            "STORAGE_CONFIG_ROLLBACK_FAILED",
                            format!("Cannot restore the previous empty configuration: {error}"),
                            false,
                        )
                    })?;
                }
                Ok(())
            }
            ConfigSnapshot::Existing(bytes) => self.atomic_write(bytes),
        }
    }

    fn atomic_write(&self, bytes: &[u8]) -> Result<(), StorageError> {
        fs::create_dir_all(&self.default_root).map_err(|error| {
            StorageError::new(
                "STORAGE_CONFIG_DIRECTORY_FAILED",
                format!("Cannot create the configuration directory: {error}"),
                false,
            )
        })?;

        let temporary_path = self.default_root.join(format!(
            ".{LOCATION_CONFIG_FILE_NAME}.{}.tmp",
            unique_suffix()
        ));
        let write_result = (|| -> Result<(), StorageError> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path)
                .map_err(|error| {
                    StorageError::new(
                        "STORAGE_CONFIG_TEMP_CREATE_FAILED",
                        format!("Cannot create the temporary configuration: {error}"),
                        false,
                    )
                })?;
            file.write_all(bytes).map_err(|error| {
                StorageError::new(
                    "STORAGE_CONFIG_WRITE_FAILED",
                    format!("Cannot write the temporary configuration: {error}"),
                    false,
                )
            })?;
            file.sync_all().map_err(|error| {
                StorageError::new(
                    "STORAGE_CONFIG_SYNC_FAILED",
                    format!("Cannot sync the temporary configuration: {error}"),
                    false,
                )
            })?;
            atomic_replace(&temporary_path, &self.config_path).map_err(|error| {
                StorageError::new(
                    "STORAGE_CONFIG_REPLACE_FAILED",
                    format!("Cannot atomically replace the configuration: {error}"),
                    false,
                )
            })
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result
    }
}

fn contains_forbidden_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(value) => {
            let value = value.to_string_lossy().to_ascii_lowercase();
            matches!(value.as_str(), "node_modules" | "target" | "dist")
        }
        _ => false,
    })
}

fn verify_writable(directory: &Path) -> Result<(), StorageError> {
    let probe_path = directory.join(format!(".digital-life-write-probe-{}.tmp", unique_suffix()));
    let result = (|| -> Result<(), StorageError> {
        let mut probe = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe_path)
            .map_err(|error| {
                StorageError::new(
                    "STORAGE_PATH_NOT_WRITABLE",
                    format!("Cannot create a probe file in the candidate directory: {error}"),
                    true,
                )
            })?;
        probe
            .write_all(b"digital-life-storage-probe")
            .map_err(|error| {
                StorageError::new(
                    "STORAGE_PATH_NOT_WRITABLE",
                    format!("Cannot write to the candidate directory: {error}"),
                    true,
                )
            })?;
        probe.sync_all().map_err(|error| {
            StorageError::new(
                "STORAGE_PATH_NOT_WRITABLE",
                format!("Cannot sync data in the candidate directory: {error}"),
                true,
            )
        })?;
        Ok(())
    })();
    let cleanup_result = fs::remove_file(&probe_path);

    result?;
    cleanup_result.map_err(|error| {
        StorageError::new(
            "STORAGE_PROBE_CLEANUP_FAILED",
            format!("Cannot remove the candidate directory probe file: {error}"),
            true,
        )
    })
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    let source = wide(source.as_os_str());
    let destination = wide(destination.as_os_str());
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("digital-life-location-{name}-{}", unique_suffix()));
            fs::create_dir_all(&root).expect("create test root");
            Self(root)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_config_uses_default_root() {
        let root = TestRoot::new("missing-config");
        let resolver = StorageLocationResolver::new(root.0.clone(), None);
        assert_eq!(resolver.resolve_active_root().unwrap(), root.0.clone());
    }

    #[test]
    fn valid_custom_directory_passes_validation() {
        let root = TestRoot::new("valid");
        let current = root.0.join("current");
        let candidate = root.0.join("candidate");
        let project = root.0.join("project");
        fs::create_dir_all(&current).unwrap();
        fs::create_dir_all(&project).unwrap();
        let resolver = StorageLocationResolver::new(current.clone(), Some(project));
        assert!(resolver
            .validate_candidate(candidate.to_str().unwrap(), &current)
            .is_ok());
    }

    #[test]
    fn same_directory_is_rejected() {
        let root = TestRoot::new("same");
        let resolver = StorageLocationResolver::new(root.0.clone(), None);
        let error = resolver
            .validate_candidate(root.0.to_str().unwrap(), &root.0)
            .unwrap_err();
        assert_eq!(error.code, "STORAGE_PATH_UNCHANGED");
    }

    #[test]
    fn relative_path_is_rejected() {
        let root = TestRoot::new("relative");
        let resolver = StorageLocationResolver::new(root.0.clone(), None);
        let error = resolver
            .validate_candidate("relative/data", &root.0)
            .unwrap_err();
        assert_eq!(error.code, "STORAGE_PATH_NOT_ABSOLUTE");
    }

    #[test]
    fn file_path_is_rejected() {
        let root = TestRoot::new("file");
        let file_path = root.0.join("not-a-directory");
        File::create(&file_path).unwrap();
        let resolver = StorageLocationResolver::new(root.0.clone(), None);
        let error = resolver
            .validate_candidate(file_path.to_str().unwrap(), &root.0)
            .unwrap_err();
        assert_eq!(error.code, "STORAGE_PATH_IS_FILE");
    }

    #[test]
    fn corrupt_config_does_not_create_database() {
        let root = TestRoot::new("corrupt");
        fs::write(root.0.join(LOCATION_CONFIG_FILE_NAME), b"{not-json").unwrap();
        let resolver = StorageLocationResolver::new(root.0.clone(), None);
        let error = resolver.resolve_active_root().unwrap_err();
        assert_eq!(error.code, "STORAGE_CONFIG_INVALID");
        assert!(!root.0.join(DATABASE_FILE_NAME).exists());
    }
}
