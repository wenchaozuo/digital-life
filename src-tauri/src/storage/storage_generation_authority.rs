//! Durable storage-generation retirement for capability authority.
//!
//! The D30/D31 mutex gives one serialization point for a database identity,
//! but a mutex alone cannot tell an already-open process that its database was
//! retired.  This small marker lives beside each SQLite database and is read
//! on every capability-authority crossing.  It is deliberately outside the
//! SQLite schema, so the repair does not add Migration031 or alter Schema 30.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{location, unique_suffix, StorageError, DATABASE_FILE_NAME};

pub(super) const MARKER_FILE_NAME: &str = ".digital-life-storage-generation.json";

const MARKER_VERSION: u32 = 1;
const GENERATION_ID_BYTES: usize = 32;
const GENERATION_ID_HEX_LENGTH: usize = GENERATION_ID_BYTES * 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MarkerState {
    Pending,
    Active,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct StorageGenerationMarker {
    version: u32,
    generation_id: String,
    database_path: PathBuf,
    state: MarkerState,
}

fn marker_path(root: &Path) -> PathBuf {
    root.join(MARKER_FILE_NAME)
}

fn restart_required() -> StorageError {
    StorageError::capability_authority_restart_required()
}

fn marker_invalid() -> StorageError {
    StorageError::new(
        "CAPABILITY_AUTHORITY_GENERATION_INVALID",
        "The storage capability-authority generation marker is invalid; restart the application.",
        true,
    )
}

fn generation_id_invalid() -> StorageError {
    marker_invalid()
}

fn valid_generation_id(value: &str) -> bool {
    value.len() == GENERATION_ID_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_database_path(database_path: &Path) -> Result<PathBuf, StorageError> {
    if !database_path.is_absolute() {
        return Err(marker_invalid());
    }
    if database_path.file_name().and_then(|name| name.to_str()) != Some(DATABASE_FILE_NAME) {
        return Err(marker_invalid());
    }
    if database_path.exists() {
        return fs::canonicalize(database_path).map_err(|_| marker_invalid());
    }
    let parent = database_path.parent().ok_or_else(marker_invalid)?;
    let parent = fs::canonicalize(parent).map_err(|_| marker_invalid())?;
    Ok(parent.join(DATABASE_FILE_NAME))
}

fn validate_marker(
    marker: &StorageGenerationMarker,
    database_path: &Path,
) -> Result<(), StorageError> {
    if marker.version != MARKER_VERSION || !valid_generation_id(&marker.generation_id) {
        return Err(generation_id_invalid());
    }
    let expected = canonical_database_path(database_path)?;
    if marker.state != MarkerState::Pending && !database_path.is_file() {
        return Err(marker_invalid());
    }
    let marked = canonical_database_path(&marker.database_path)?;
    if marked != expected {
        return Err(marker_invalid());
    }
    Ok(())
}

fn read_marker(root: &Path) -> Result<Option<StorageGenerationMarker>, StorageError> {
    let path = marker_path(root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(marker_invalid()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| marker_invalid())
}

fn mint_generation_id() -> Result<String, StorageError> {
    let mut bytes = [0_u8; GENERATION_ID_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| {
        StorageError::new(
            "CAPABILITY_AUTHORITY_GENERATION_UNAVAILABLE",
            "The storage capability-authority generation identity could not be generated.",
            true,
        )
    })?;
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn write_marker(
    root: &Path,
    database_path: &Path,
    generation_id: &str,
    state: MarkerState,
) -> Result<(), StorageError> {
    if !valid_generation_id(generation_id) {
        return Err(generation_id_invalid());
    }
    let database_path = canonical_database_path(database_path)?;
    let marker = StorageGenerationMarker {
        version: MARKER_VERSION,
        generation_id: generation_id.to_string(),
        database_path,
        state,
    };
    let bytes = serde_json::to_vec_pretty(&marker).map_err(|_| marker_invalid())?;
    fs::create_dir_all(root).map_err(|_| marker_invalid())?;
    let temporary_path = root.join(format!(".{MARKER_FILE_NAME}.{}.tmp", unique_suffix()));
    let result = (|| -> Result<(), StorageError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .map_err(|_| marker_invalid())?;
        file.write_all(&bytes).map_err(|_| marker_invalid())?;
        file.sync_all().map_err(|_| marker_invalid())?;
        location::atomic_replace(&temporary_path, &marker_path(root)).map_err(|_| marker_invalid())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Returns the active generation ID for an opened database, creating the
/// marker only for an otherwise unmarked legacy root.  Callers hold the
/// composite capability gate while invoking this function.
pub(super) fn open_or_create_active(
    root: &Path,
    database_path: &Path,
) -> Result<String, StorageError> {
    match read_marker(root).map_err(|_| restart_required())? {
        Some(marker) => {
            validate_marker(&marker, database_path).map_err(|_| restart_required())?;
            if marker.state != MarkerState::Active {
                return Err(restart_required());
            }
            Ok(marker.generation_id)
        }
        None => {
            let generation_id = mint_generation_id()?;
            write_marker(root, database_path, &generation_id, MarkerState::Active)?;
            Ok(generation_id)
        }
    }
}

/// Reject a root whose marker is already in a non-active publication phase.
/// This is called before SQLite is opened, so a Host cannot create an empty
/// target database while a migration has deliberately marked that target
/// `pending`.
pub(super) fn reject_nonactive_before_open(root: &Path) -> Result<(), StorageError> {
    let Some(marker) = read_marker(root).map_err(|_| restart_required())? else {
        return Ok(());
    };
    // Validate the marker against the exact database path that the Host is
    // about to open.  Any malformed, redirected, or half-published marker is
    // an ambiguous generation and therefore gets the one stable restart
    // boundary before SQLite can be opened.
    let database_path = root.join(DATABASE_FILE_NAME);
    validate_marker(&marker, &database_path).map_err(|_| restart_required())?;
    if marker.state != MarkerState::Active {
        return Err(restart_required());
    }
    Ok(())
}

/// Re-read the durable marker before an authority decision or mutation.  A
/// missing, pending, retired, malformed, or mismatched marker is fail-closed;
/// no caller is allowed to reopen or transplant the operation to another
/// database generation here.
pub(super) fn ensure_active_generation(
    root: &Path,
    database_path: &Path,
    expected_generation_id: &str,
) -> Result<(), StorageError> {
    let Some(marker) = read_marker(root).map_err(|_| restart_required())? else {
        return Err(restart_required());
    };
    validate_marker(&marker, database_path).map_err(|_| restart_required())?;
    if marker.state != MarkerState::Active || marker.generation_id != expected_generation_id {
        return Err(restart_required());
    }
    Ok(())
}

/// Prepare a target root without making it executable.  A fresh Host that
/// happens to resolve the target while migration is publishing cannot derive
/// authority while the marker is `pending`.
pub(super) fn create_pending_target(
    root: &Path,
    database_path: &Path,
    predecessor_generation_id: &str,
) -> Result<String, StorageError> {
    if read_marker(root)?.is_some() {
        return Err(StorageError::new(
            "MIGRATION_TARGET_GENERATION_EXISTS",
            "The target directory already contains a storage-generation marker.",
            true,
        ));
    }
    if !valid_generation_id(predecessor_generation_id) {
        return Err(generation_id_invalid());
    }
    let generation_id = mint_generation_id()?;
    write_marker(root, database_path, &generation_id, MarkerState::Pending)?;
    Ok(generation_id)
}

pub(super) fn retire_source(
    root: &Path,
    database_path: &Path,
    generation_id: &str,
) -> Result<(), StorageError> {
    let Some(marker) = read_marker(root)? else {
        return Err(restart_required());
    };
    validate_marker(&marker, database_path)?;
    if marker.state != MarkerState::Active || marker.generation_id != generation_id {
        return Err(restart_required());
    }
    write_marker(root, database_path, generation_id, MarkerState::Retired)
}

pub(super) fn restore_source_active(
    root: &Path,
    database_path: &Path,
    generation_id: &str,
) -> Result<(), StorageError> {
    let Some(marker) = read_marker(root)? else {
        return Err(restart_required());
    };
    validate_marker(&marker, database_path)?;
    if marker.generation_id != generation_id {
        return Err(restart_required());
    }
    write_marker(root, database_path, generation_id, MarkerState::Active)
}

pub(super) fn activate_target(
    root: &Path,
    database_path: &Path,
    generation_id: &str,
) -> Result<(), StorageError> {
    let Some(marker) = read_marker(root)? else {
        return Err(restart_required());
    };
    validate_marker(&marker, database_path)?;
    if marker.state != MarkerState::Pending || marker.generation_id != generation_id {
        return Err(restart_required());
    }
    write_marker(root, database_path, generation_id, MarkerState::Active)
}

pub(super) fn remove_marker(root: &Path) -> Result<(), StorageError> {
    match fs::remove_file(marker_path(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(marker_invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn root(name: &str) -> (TempDir, PathBuf) {
        let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        (root, data)
    }

    fn database(root: &Path) -> PathBuf {
        let path = root.join(DATABASE_FILE_NAME);
        fs::write(&path, b"marker-test").unwrap();
        fs::canonicalize(path).unwrap()
    }

    #[test]
    fn legacy_root_gets_one_active_generation_marker() {
        let (_root, data) = root("generation-marker-legacy");
        let db = database(&data);
        let first = open_or_create_active(&data, &db).unwrap();
        let second = open_or_create_active(&data, &db).unwrap();
        assert_eq!(first, second);
        ensure_active_generation(&data, &db, &first).unwrap();
    }

    #[test]
    fn pending_and_retired_markers_fail_closed() {
        let (_root, data) = root("generation-marker-states");
        let db = database(&data);
        let generation = open_or_create_active(&data, &db).unwrap();
        write_marker(&data, &db, &generation, MarkerState::Pending).unwrap();
        assert_eq!(
            ensure_active_generation(&data, &db, &generation)
                .unwrap_err()
                .code,
            super::super::CAPABILITY_AUTHORITY_RESTART_REQUIRED
        );
        write_marker(&data, &db, &generation, MarkerState::Retired).unwrap();
        assert!(ensure_active_generation(&data, &db, &generation).is_err());
    }

    #[test]
    fn malformed_marker_is_a_stable_restart_boundary_before_open() {
        let (_root, data) = root("generation-marker-invalid");
        let marker = StorageGenerationMarker {
            version: MARKER_VERSION,
            generation_id: "0".repeat(GENERATION_ID_HEX_LENGTH),
            database_path: PathBuf::from(DATABASE_FILE_NAME),
            state: MarkerState::Active,
        };
        fs::write(marker_path(&data), serde_json::to_vec(&marker).unwrap()).unwrap();
        assert_eq!(
            reject_nonactive_before_open(&data).unwrap_err().code,
            super::super::CAPABILITY_AUTHORITY_RESTART_REQUIRED
        );
    }
}
