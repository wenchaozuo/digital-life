//! SQLite-authoritative managed Live2D body-package storage.
//!
//! The selected source path is an import-only input.  The package registry is
//! the trust boundary: only bytes represented by a registered manifest can be
//! served to a webview, and no source or managed OS path is serialized.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    http::{header, Method, Request, Response, StatusCode, Uri},
    State,
};
use url::Url;

use super::{unique_suffix, StorageError, StorageService};

pub(crate) const BODY_ASSET_PROTOCOL_SCHEME: &str = "digital-life-body";
pub(crate) const BODY_RENDERER_WEBVIEW_LABEL: &str = "main";
pub(crate) const MANAGED_BODIES_DIRECTORY: &str = "bodies";
pub(crate) const MANAGED_STAGING_DIRECTORY: &str = "staging";
pub(crate) const MANAGED_PACKAGES_DIRECTORY: &str = "packages";

#[cfg(any(test, target_os = "windows", target_os = "android"))]
const WINDOWS_ANDROID_BODY_ASSET_ORIGIN: &str = "http://digital-life-body.localhost/";
#[cfg(any(test, not(any(target_os = "windows", target_os = "android"))))]
const MAC_LINUX_BODY_ASSET_ORIGIN: &str = "digital-life-body://localhost/";
const BODY_ASSET_CORS_ALLOW_ORIGIN: &str = "*";

/// V1 package limits are intentionally centralized and applied to actual
/// bytes read, not only to filesystem metadata or JSON-declared sizes.
pub(crate) const MAX_MODEL_DESCRIPTOR_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_ASSET_COUNT: usize = 256;
pub(crate) const MAX_INDIVIDUAL_ASSET_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_TOTAL_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_RELATIVE_PATH_BYTES: usize = 512;
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = 128;

pub(crate) const MIGRATION_025_TABLE_SQLS: &[&str] = &[
    include_str!("migrations/025_managed_body_package_authority.body_package.sql"),
    include_str!("migrations/025_managed_body_package_authority.body_package_asset.sql"),
];

pub(crate) const MIGRATION_025_TRIGGER_SQLS: &[&str] = &[
    include_str!(
        "migrations/025_managed_body_package_authority.body_package_immutable_trigger.sql"
    ),
    include_str!(
        "migrations/025_managed_body_package_authority.body_package_asset_immutable_trigger.sql"
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyPackageStatus {
    Available,
    CorruptUnavailable,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallLive2DBodyPackageRequest {
    pub source_path: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPackageAssetSnapshot {
    pub relative_path: String,
    pub asset_kind: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledBodyPackageSnapshot {
    pub body_id: String,
    pub display_name: String,
    pub presentation_kind: String,
    pub model_entry: String,
    pub package_content_hash: String,
    pub package_version: i64,
    pub installed_at: String,
    pub status: BodyPackageStatus,
    pub assets: Vec<BodyPackageAssetSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AssetKind {
    Model3,
    Moc3,
    Png,
    Physics3,
    Pose3,
    UserData3,
    Cdi3,
    Motion3,
    Expression3,
}

impl AssetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Model3 => "model3",
            Self::Moc3 => "moc3",
            Self::Png => "png",
            Self::Physics3 => "physics3",
            Self::Pose3 => "pose3",
            Self::UserData3 => "userdata3",
            Self::Cdi3 => "cdi3",
            Self::Motion3 => "motion3",
            Self::Expression3 => "expression3",
        }
    }

    fn expected_suffix(self) -> &'static str {
        match self {
            Self::Model3 => ".model3.json",
            Self::Moc3 => ".moc3",
            Self::Png => ".png",
            Self::Physics3 => ".physics3.json",
            Self::Pose3 => ".pose3.json",
            Self::UserData3 => ".userdata3.json",
            Self::Cdi3 => ".cdi3.json",
            Self::Motion3 => ".motion3.json",
            Self::Expression3 => ".exp3.json",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "model3" => Some(Self::Model3),
            "moc3" => Some(Self::Moc3),
            "png" => Some(Self::Png),
            "physics3" => Some(Self::Physics3),
            "pose3" => Some(Self::Pose3),
            "userdata3" => Some(Self::UserData3),
            "cdi3" => Some(Self::Cdi3),
            "motion3" => Some(Self::Motion3),
            "expression3" => Some(Self::Expression3),
            _ => None,
        }
    }

    fn max_bytes(self) -> u64 {
        if self == Self::Model3 {
            MAX_MODEL_DESCRIPTOR_BYTES
        } else {
            MAX_INDIVIDUAL_ASSET_BYTES
        }
    }
}

#[derive(Clone, Debug)]
struct ManifestEntry {
    relative_path: String,
    asset_kind: AssetKind,
    source_path: PathBuf,
    content_hash: String,
    size_bytes: u64,
}

#[derive(Clone, Debug)]
struct PreparedPackage {
    body_id: String,
    display_name: String,
    model_entry_path: String,
    package_content_hash: String,
    manifest: Vec<ManifestEntry>,
}

#[derive(Clone, Debug)]
struct RegisteredAsset {
    relative_path: String,
    asset_kind: String,
    content_hash: String,
    size_bytes: i64,
}

#[derive(Clone, Debug)]
struct RegisteredPackage {
    body_id: String,
    display_name: String,
    presentation_kind: String,
    model_entry_path: String,
    package_content_hash: String,
    package_version: i64,
    installed_at: String,
    assets: Vec<RegisteredAsset>,
}

#[derive(Deserialize)]
struct Model3Descriptor {
    #[serde(rename = "FileReferences")]
    file_references: Option<Model3FileReferences>,
}

#[derive(Deserialize)]
struct Model3FileReferences {
    #[serde(rename = "Moc")]
    moc: Option<String>,
    #[serde(rename = "Textures")]
    textures: Option<Vec<String>>,
    #[serde(rename = "Physics")]
    physics: Option<String>,
    #[serde(rename = "Pose")]
    pose: Option<String>,
    #[serde(rename = "UserData")]
    user_data: Option<String>,
    #[serde(rename = "DisplayInfo")]
    display_info: Option<String>,
    #[serde(rename = "Motions")]
    motions: Option<BTreeMap<String, Vec<MotionReference>>>,
    #[serde(rename = "Expressions")]
    expressions: Option<Vec<ExpressionReference>>,
}

#[derive(Deserialize)]
struct MotionReference {
    #[serde(rename = "File")]
    file: Option<String>,
    #[serde(rename = "Sound")]
    sound: Option<String>,
}

#[derive(Deserialize)]
struct ExpressionReference {
    #[serde(rename = "File")]
    file: Option<String>,
}

fn package_error(code: &'static str, message: &'static str, recoverable: bool) -> StorageError {
    StorageError::new(code, message, recoverable)
}

fn invalid_input() -> StorageError {
    package_error(
        "BODY_PACKAGE_INVALID_INPUT",
        "The body package import input is invalid.",
        false,
    )
}

fn descriptor_invalid() -> StorageError {
    package_error(
        "BODY_PACKAGE_DESCRIPTOR_INVALID",
        "The Cubism model descriptor is malformed or unsupported.",
        false,
    )
}

fn missing_asset() -> StorageError {
    package_error(
        "BODY_PACKAGE_ASSET_MISSING",
        "A referenced body package asset is missing or is not a regular file.",
        false,
    )
}

fn unsafe_asset_path() -> StorageError {
    package_error(
        "BODY_PACKAGE_ASSET_PATH_UNSAFE",
        "A body package asset path is unsafe.",
        false,
    )
}

fn asset_escape() -> StorageError {
    package_error(
        "BODY_PACKAGE_ASSET_ESCAPE",
        "A body package asset resolves outside its package root.",
        false,
    )
}

fn package_too_large() -> StorageError {
    package_error(
        "BODY_PACKAGE_TOO_LARGE",
        "The body package exceeds a bounded size limit.",
        false,
    )
}

fn too_many_assets() -> StorageError {
    package_error(
        "BODY_PACKAGE_TOO_MANY_ASSETS",
        "The body package contains too many assets.",
        false,
    )
}

fn unsupported_asset_type() -> StorageError {
    package_error(
        "BODY_PACKAGE_ASSET_TYPE_UNSUPPORTED",
        "The body package contains an unsupported asset type.",
        false,
    )
}

fn duplicate_asset() -> StorageError {
    package_error(
        "BODY_PACKAGE_DUPLICATE_ASSET",
        "The body package contains duplicate normalized assets.",
        false,
    )
}

fn import_copy_failed() -> StorageError {
    package_error(
        "BODY_PACKAGE_IMPORT_COPY_FAILED",
        "The body package could not be copied into managed storage.",
        true,
    )
}

fn import_verify_failed() -> StorageError {
    package_error(
        "BODY_PACKAGE_IMPORT_VERIFY_FAILED",
        "The managed body package did not match its validated manifest.",
        false,
    )
}

fn registration_failed() -> StorageError {
    package_error(
        "BODY_PACKAGE_REGISTRATION_FAILED",
        "The body package registry transaction could not be completed.",
        true,
    )
}

fn package_not_found() -> StorageError {
    package_error(
        "BODY_PACKAGE_NOT_FOUND",
        "The body package was not found.",
        false,
    )
}

fn package_in_use() -> StorageError {
    package_error(
        "BODY_PACKAGE_IN_USE",
        "The body package is still referenced by a Life identity.",
        false,
    )
}

fn package_corrupt() -> StorageError {
    package_error(
        "BODY_PACKAGE_CORRUPT",
        "The registered body package payload is missing or corrupt.",
        true,
    )
}

fn asset_not_registered() -> StorageError {
    package_error(
        "BODY_PACKAGE_ASSET_NOT_REGISTERED",
        "The requested body package asset is not registered.",
        false,
    )
}

fn database_unavailable() -> StorageError {
    package_error(
        "BODY_PACKAGE_DATABASE_UNAVAILABLE",
        "The body package registry is unavailable.",
        true,
    )
}

fn cleanup_failed() -> StorageError {
    package_error(
        "BODY_PACKAGE_CLEANUP_FAILED",
        "The body package registry changed, but managed cleanup could not finish.",
        true,
    )
}

fn is_valid_body_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("live2d-") else {
        return false;
    };
    !suffix.is_empty() && value.len() <= 96 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn generate_body_id() -> String {
    let mut hasher = Sha256::new();
    hasher.update(unique_suffix().as_bytes());
    let digest = hasher.finalize();
    format!("live2d-{}", hex_digest(&digest))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn normalize_reference(reference: &str, allow_current_dir: bool) -> Result<String, StorageError> {
    if reference.is_empty()
        || reference.trim() != reference
        || reference.len() > MAX_RELATIVE_PATH_BYTES
        || reference.contains('\\')
        || reference.contains('\0')
        || reference.contains('%')
        || reference.starts_with('/')
        || reference.starts_with("//")
    {
        return Err(unsafe_asset_path());
    }

    let mut components = Vec::new();
    for component in reference.split('/') {
        if component.is_empty()
            || component.contains(':')
            || component.contains('?')
            || component.contains('#')
            || component.chars().any(char::is_control)
        {
            return Err(unsafe_asset_path());
        }
        match component {
            "." if allow_current_dir => {}
            "." | ".." => return Err(unsafe_asset_path()),
            value => components.push(value),
        }
    }

    if components.is_empty() {
        return Err(unsafe_asset_path());
    }

    let normalized = components.join("/");
    if normalized.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(unsafe_asset_path());
    }
    Ok(normalized)
}

fn manifest_key(relative_path: &str) -> String {
    relative_path.to_lowercase()
}

fn validate_asset_suffix(relative_path: &str, asset_kind: AssetKind) -> Result<(), StorageError> {
    if !relative_path
        .to_ascii_lowercase()
        .ends_with(asset_kind.expected_suffix())
    {
        return Err(unsupported_asset_type());
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn reject_link_components(root: &Path, relative_path: &str) -> Result<(), StorageError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| unsafe_asset_path())?;
    if is_reparse_or_symlink(&root_metadata) {
        return Err(unsafe_asset_path());
    }

    let mut current = root.to_path_buf();
    for component in Path::new(relative_path).components() {
        let Component::Normal(value) = component else {
            return Err(unsafe_asset_path());
        };
        current.push(value);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                missing_asset()
            } else {
                unsafe_asset_path()
            }
        })?;
        if is_reparse_or_symlink(&metadata) {
            return Err(unsafe_asset_path());
        }
    }
    Ok(())
}

fn canonical_source_descriptor(source_path: &str) -> Result<(PathBuf, PathBuf), StorageError> {
    if source_path.is_empty()
        || source_path.trim() != source_path
        || source_path.contains("://")
        || source_path.to_ascii_lowercase().starts_with("file:")
        || source_path.to_ascii_lowercase().starts_with("javascript:")
        || source_path.starts_with("\\\\")
        || source_path.starts_with("//")
        || !Path::new(source_path).is_absolute()
    {
        return Err(invalid_input());
    }

    let input = Path::new(source_path);
    let filename = input
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(invalid_input)?;
    if !filename.to_ascii_lowercase().ends_with(".model3.json") {
        return Err(invalid_input());
    }

    reject_source_link_components(input)?;
    let descriptor = fs::canonicalize(input).map_err(|_| missing_asset())?;
    let descriptor_metadata = fs::metadata(&descriptor).map_err(|_| missing_asset())?;
    if !descriptor_metadata.is_file() {
        return Err(missing_asset());
    }
    let root = descriptor.parent().ok_or_else(unsafe_asset_path)?;
    let root = fs::canonicalize(root).map_err(|_| unsafe_asset_path())?;
    Ok((descriptor, root))
}

fn reject_source_link_components(path: &Path) -> Result<(), StorageError> {
    let mut ancestors = Vec::new();
    let mut current = path;
    loop {
        ancestors.push(current);
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
    }

    for ancestor in ancestors.into_iter().rev() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                missing_asset()
            } else {
                unsafe_asset_path()
            }
        })?;
        if is_reparse_or_symlink(&metadata) {
            return Err(unsafe_asset_path());
        }
    }
    Ok(())
}

fn read_file_with_limit(path: &Path, limit: u64) -> Result<Vec<u8>, StorageError> {
    let file = File::open(path).map_err(|_| missing_asset())?;
    let metadata = file.metadata().map_err(|_| missing_asset())?;
    if !metadata.is_file() {
        return Err(missing_asset());
    }
    if metadata.len() > limit {
        return Err(package_too_large());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| package_too_large())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| missing_asset())?;
    if bytes.len() as u64 > limit {
        return Err(package_too_large());
    }
    Ok(bytes)
}

fn hash_file(path: &Path, limit: u64) -> Result<(u64, String), StorageError> {
    let mut file = File::open(path).map_err(|_| missing_asset())?;
    let metadata = file.metadata().map_err(|_| missing_asset())?;
    if !metadata.is_file() {
        return Err(missing_asset());
    }

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| missing_asset())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(package_too_large)?;
        if total > limit {
            return Err(package_too_large());
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex_digest(&hasher.finalize())))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(&hasher.finalize())
}

fn append_manifest_entry(
    root: &Path,
    manifest: &mut BTreeMap<String, ManifestEntry>,
    total_bytes: &mut u64,
    reference: &str,
    asset_kind: AssetKind,
) -> Result<String, StorageError> {
    let relative_path = normalize_reference(reference, true)?;
    validate_asset_suffix(&relative_path, asset_kind)?;
    let key = manifest_key(&relative_path);
    if manifest.contains_key(&key) {
        return Err(duplicate_asset());
    }
    if manifest.len() >= MAX_ASSET_COUNT {
        return Err(too_many_assets());
    }

    let candidate = root.join(Path::new(&relative_path));
    if !candidate.starts_with(root) {
        return Err(asset_escape());
    }
    reject_link_components(root, &relative_path)?;
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            missing_asset()
        } else {
            asset_escape()
        }
    })?;
    if !canonical.starts_with(root) {
        return Err(asset_escape());
    }
    let (size_bytes, content_hash) = hash_file(&canonical, asset_kind.max_bytes())?;
    *total_bytes = total_bytes
        .checked_add(size_bytes)
        .ok_or_else(package_too_large)?;
    if *total_bytes > MAX_TOTAL_PACKAGE_BYTES {
        return Err(package_too_large());
    }

    manifest.insert(
        key,
        ManifestEntry {
            relative_path: relative_path.clone(),
            asset_kind,
            source_path: canonical,
            content_hash,
            size_bytes,
        },
    );
    Ok(relative_path)
}

fn update_manifest_hash(hasher: &mut Sha256, value: &str) {
    let length = (value.len() as u64).to_le_bytes();
    hasher.update(length);
    hasher.update(value.as_bytes());
}

fn package_content_hash(manifest: &[ManifestEntry]) -> String {
    let mut sorted = manifest.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut hasher = Sha256::new();
    for entry in sorted {
        update_manifest_hash(&mut hasher, &entry.relative_path);
        update_manifest_hash(&mut hasher, entry.asset_kind.as_str());
        update_manifest_hash(&mut hasher, &entry.size_bytes.to_string());
        update_manifest_hash(&mut hasher, &entry.content_hash);
    }
    hex_digest(&hasher.finalize())
}

fn prepare_package(source_path: &str, display_name: &str) -> Result<PreparedPackage, StorageError> {
    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(invalid_input());
    }
    let (descriptor, root) = canonical_source_descriptor(source_path)?;
    let descriptor_bytes = read_file_with_limit(&descriptor, MAX_MODEL_DESCRIPTOR_BYTES)?;
    let parsed: Model3Descriptor =
        serde_json::from_slice(&descriptor_bytes).map_err(|_| descriptor_invalid())?;
    let references = parsed.file_references.ok_or_else(descriptor_invalid)?;

    let mut manifest = BTreeMap::new();
    let mut total_bytes = 0_u64;
    let descriptor_name = descriptor
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(descriptor_invalid)?;
    let model_entry_path = append_manifest_entry(
        &root,
        &mut manifest,
        &mut total_bytes,
        descriptor_name,
        AssetKind::Model3,
    )?;

    let moc = references.moc.as_deref().ok_or_else(missing_asset)?;
    append_manifest_entry(&root, &mut manifest, &mut total_bytes, moc, AssetKind::Moc3)?;

    let textures = references.textures.as_ref().ok_or_else(missing_asset)?;
    if textures.is_empty() {
        return Err(missing_asset());
    }
    for texture in textures {
        append_manifest_entry(
            &root,
            &mut manifest,
            &mut total_bytes,
            texture,
            AssetKind::Png,
        )?;
    }

    for (reference, asset_kind) in [
        (references.physics.as_deref(), AssetKind::Physics3),
        (references.pose.as_deref(), AssetKind::Pose3),
        (references.user_data.as_deref(), AssetKind::UserData3),
        (references.display_info.as_deref(), AssetKind::Cdi3),
    ] {
        if let Some(reference) = reference {
            append_manifest_entry(
                &root,
                &mut manifest,
                &mut total_bytes,
                reference,
                asset_kind,
            )?;
        }
    }

    if let Some(motions) = references.motions {
        for motion_group in motions.values() {
            for motion in motion_group {
                if motion.sound.is_some() {
                    return Err(unsupported_asset_type());
                }
                let file = motion.file.as_deref().ok_or_else(missing_asset)?;
                append_manifest_entry(
                    &root,
                    &mut manifest,
                    &mut total_bytes,
                    file,
                    AssetKind::Motion3,
                )?;
            }
        }
    }

    if let Some(expressions) = references.expressions {
        for expression in expressions {
            let file = expression.file.as_deref().ok_or_else(missing_asset)?;
            append_manifest_entry(
                &root,
                &mut manifest,
                &mut total_bytes,
                file,
                AssetKind::Expression3,
            )?;
        }
    }

    let manifest = manifest.into_values().collect::<Vec<_>>();
    Ok(PreparedPackage {
        body_id: generate_body_id(),
        display_name: display_name.to_string(),
        model_entry_path,
        package_content_hash: package_content_hash(&manifest),
        manifest,
    })
}

fn ensure_managed_directory(root: &Path, components: &[&str]) -> Result<PathBuf, StorageError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| import_copy_failed())?;
    if !root_metadata.is_dir() || is_reparse_or_symlink(&root_metadata) {
        return Err(unsafe_asset_path());
    }

    let canonical_root = fs::canonicalize(root).map_err(|_| import_copy_failed())?;
    let mut current = root.to_path_buf();
    for component in components {
        if component.is_empty()
            || component
                .chars()
                .any(|character| matches!(character, '\\' | '/' | ':'))
        {
            return Err(unsafe_asset_path());
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
                    return Err(unsafe_asset_path());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| import_copy_failed())?;
            }
            Err(_) => return Err(import_copy_failed()),
        }
    }
    let canonical = fs::canonicalize(&current).map_err(|_| import_copy_failed())?;
    if !canonical.starts_with(&canonical_root) {
        return Err(asset_escape());
    }
    Ok(canonical)
}

fn managed_roots(active_root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), StorageError> {
    let bodies = ensure_managed_directory(active_root, &[MANAGED_BODIES_DIRECTORY])?;
    let staging = ensure_managed_directory(&bodies, &[MANAGED_STAGING_DIRECTORY])?;
    let packages = ensure_managed_directory(&bodies, &[MANAGED_PACKAGES_DIRECTORY])?;
    Ok((bodies, staging, packages))
}

fn remove_managed_package(packages_root: &Path, body_id: &str) -> Result<(), StorageError> {
    if !is_valid_body_id(body_id) {
        return Err(unsafe_asset_path());
    }
    let metadata = match fs::symlink_metadata(packages_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(cleanup_failed()),
    };
    if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
        return Err(cleanup_failed());
    }
    let package_dir = packages_root.join(body_id);
    let package_metadata = match fs::symlink_metadata(&package_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(cleanup_failed()),
    };
    if !package_metadata.is_dir() || is_reparse_or_symlink(&package_metadata) {
        return Err(cleanup_failed());
    }
    let canonical_parent = fs::canonicalize(packages_root).map_err(|_| cleanup_failed())?;
    let canonical_package = fs::canonicalize(&package_dir).map_err(|_| cleanup_failed())?;
    if !canonical_package.starts_with(&canonical_parent) {
        return Err(cleanup_failed());
    }
    fs::remove_dir_all(package_dir).map_err(|_| cleanup_failed())
}

fn copy_manifest_to_staging(
    package: &PreparedPackage,
    staging_root: &Path,
) -> Result<(), StorageError> {
    maybe_import_failure(ImportFailurePoint::BeforeCopy)?;
    let canonical_staging = fs::canonicalize(staging_root).map_err(|_| import_copy_failed())?;
    let mut copied_total = 0_u64;
    for entry in &package.manifest {
        let destination = staging_root.join(Path::new(&entry.relative_path));
        if !destination.starts_with(staging_root) {
            return Err(asset_escape());
        }
        let parent_components = entry
            .relative_path
            .rsplit_once('/')
            .map(|(parent, _)| parent.split('/').collect::<Vec<_>>())
            .unwrap_or_default();
        if !parent_components.is_empty() {
            ensure_managed_directory(staging_root, &parent_components)?;
        }
        fs::copy(&entry.source_path, &destination).map_err(|_| import_copy_failed())?;
        let metadata = fs::symlink_metadata(&destination).map_err(|_| import_verify_failed())?;
        if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
            return Err(import_verify_failed());
        }
        let canonical_destination =
            fs::canonicalize(&destination).map_err(|_| import_verify_failed())?;
        if !canonical_destination.starts_with(&canonical_staging) {
            return Err(asset_escape());
        }
        let (size_bytes, content_hash) =
            hash_file(&canonical_destination, entry.asset_kind.max_bytes())
                .map_err(|_| import_verify_failed())?;
        if size_bytes != entry.size_bytes || content_hash != entry.content_hash {
            return Err(import_verify_failed());
        }
        copied_total = copied_total
            .checked_add(size_bytes)
            .ok_or_else(package_too_large)?;
        if copied_total > MAX_TOTAL_PACKAGE_BYTES {
            return Err(package_too_large());
        }
    }
    maybe_import_failure(ImportFailurePoint::AfterCopyVerification)?;
    Ok(())
}

fn register_package_in_connection(
    connection: &mut Connection,
    package: &PreparedPackage,
) -> Result<(), StorageError> {
    maybe_import_failure(ImportFailurePoint::BeforeRegistration)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| registration_failed())?;
    let installed_at: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| registration_failed())?;
    transaction
        .execute(
            "INSERT INTO body_package
                (body_id, display_name, presentation_kind, model_entry_path,
                 package_content_hash, package_version, installed_at)
             VALUES (?1, ?2, 'live2d', ?3, ?4, 1, ?5)",
            params![
                package.body_id,
                package.display_name,
                package.model_entry_path,
                package.package_content_hash,
                installed_at,
            ],
        )
        .map_err(|_| registration_failed())?;
    maybe_import_failure(ImportFailurePoint::AfterPackageInsert)?;
    for entry in &package.manifest {
        transaction
            .execute(
                "INSERT INTO body_package_asset
                    (body_id, relative_path, asset_kind, content_hash, size_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    package.body_id,
                    entry.relative_path,
                    entry.asset_kind.as_str(),
                    entry.content_hash,
                    i64::try_from(entry.size_bytes).map_err(|_| registration_failed())?,
                ],
            )
            .map_err(|_| registration_failed())?;
    }
    transaction.commit().map_err(|_| registration_failed())
}

fn read_registered_packages(
    connection: &Connection,
    body_id: Option<&str>,
) -> Result<Vec<RegisteredPackage>, StorageError> {
    let mut packages = Vec::new();
    let mut statement = if body_id.is_some() {
        connection
            .prepare(
                "SELECT body_id, display_name, presentation_kind, model_entry_path,
                        package_content_hash, package_version, installed_at
                 FROM body_package WHERE body_id = ?1 ORDER BY body_id",
            )
            .map_err(|_| database_unavailable())?
    } else {
        connection
            .prepare(
                "SELECT body_id, display_name, presentation_kind, model_entry_path,
                        package_content_hash, package_version, installed_at
                 FROM body_package ORDER BY body_id",
            )
            .map_err(|_| database_unavailable())?
    };
    let mut rows = if let Some(body_id) = body_id {
        statement
            .query(params![body_id])
            .map_err(|_| database_unavailable())?
    } else {
        statement.query([]).map_err(|_| database_unavailable())?
    };
    while let Some(row) = rows.next().map_err(|_| database_unavailable())? {
        let package = RegisteredPackage {
            body_id: row.get(0).map_err(|_| database_unavailable())?,
            display_name: row.get(1).map_err(|_| database_unavailable())?,
            presentation_kind: row.get(2).map_err(|_| database_unavailable())?,
            model_entry_path: row.get(3).map_err(|_| database_unavailable())?,
            package_content_hash: row.get(4).map_err(|_| database_unavailable())?,
            package_version: row.get(5).map_err(|_| database_unavailable())?,
            installed_at: row.get(6).map_err(|_| database_unavailable())?,
            assets: Vec::new(),
        };
        packages.push(package);
    }
    drop(rows);
    drop(statement);

    for package in &mut packages {
        let mut statement = connection
            .prepare(
                "SELECT relative_path, asset_kind, content_hash, size_bytes
                 FROM body_package_asset WHERE body_id = ?1 ORDER BY relative_path",
            )
            .map_err(|_| database_unavailable())?;
        let rows = statement
            .query_map(params![package.body_id], |row| {
                Ok(RegisteredAsset {
                    relative_path: row.get(0)?,
                    asset_kind: row.get(1)?,
                    content_hash: row.get(2)?,
                    size_bytes: row.get(3)?,
                })
            })
            .map_err(|_| database_unavailable())?;
        package.assets = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| database_unavailable())?;
    }
    Ok(packages)
}

fn managed_package_root(active_root: &Path, body_id: &str) -> PathBuf {
    active_root
        .join(MANAGED_BODIES_DIRECTORY)
        .join(MANAGED_PACKAGES_DIRECTORY)
        .join(body_id)
}

fn resolve_managed_asset(
    active_root: &Path,
    body_id: &str,
    relative_path: &str,
) -> Result<PathBuf, StorageError> {
    if !is_valid_body_id(body_id) {
        return Err(asset_not_registered());
    }
    let normalized = normalize_reference(relative_path, false)?;
    if normalized != relative_path {
        return Err(asset_not_registered());
    }
    let package_root = managed_package_root(active_root, body_id);
    let package_metadata = fs::symlink_metadata(&package_root).map_err(|_| package_corrupt())?;
    if !package_metadata.is_dir() || is_reparse_or_symlink(&package_metadata) {
        return Err(package_corrupt());
    }
    reject_link_components(&package_root, relative_path).map_err(|_| package_corrupt())?;
    let candidate = package_root.join(Path::new(relative_path));
    if !candidate.starts_with(&package_root) {
        return Err(asset_escape());
    }
    let canonical_root = fs::canonicalize(&package_root).map_err(|_| package_corrupt())?;
    let canonical = fs::canonicalize(&candidate).map_err(|_| package_corrupt())?;
    if !canonical.starts_with(&canonical_root) {
        return Err(asset_escape());
    }
    Ok(canonical)
}

fn package_is_available(active_root: &Path, package: &RegisteredPackage) -> bool {
    if !is_valid_body_id(&package.body_id)
        || package.presentation_kind != "live2d"
        || package.package_version != 1
        || package.assets.len() > MAX_ASSET_COUNT
    {
        return false;
    }
    let Some(model_asset) = package
        .assets
        .iter()
        .find(|asset| asset.relative_path == package.model_entry_path)
    else {
        return false;
    };
    if AssetKind::from_str(&model_asset.asset_kind) != Some(AssetKind::Model3) {
        return false;
    }

    let mut manifest = Vec::new();
    for asset in &package.assets {
        let Some(asset_kind) = AssetKind::from_str(&asset.asset_kind) else {
            return false;
        };
        if validate_asset_suffix(&asset.relative_path, asset_kind).is_err() {
            return false;
        }
        if asset.size_bytes < 0 {
            return false;
        }
        let size_bytes = asset.size_bytes as u64;
        if size_bytes > asset_kind.max_bytes() {
            return false;
        }
        let Ok(path) = resolve_managed_asset(active_root, &package.body_id, &asset.relative_path)
        else {
            return false;
        };
        let Ok((actual_size, actual_hash)) = hash_file(&path, asset_kind.max_bytes()) else {
            return false;
        };
        if actual_size != size_bytes || actual_hash != asset.content_hash {
            return false;
        }
        manifest.push(ManifestEntry {
            relative_path: asset.relative_path.clone(),
            asset_kind,
            source_path: path,
            content_hash: asset.content_hash.clone(),
            size_bytes,
        });
    }
    package_content_hash(&manifest) == package.package_content_hash
}

#[cfg(any(target_os = "windows", target_os = "android"))]
fn body_asset_origin() -> &'static str {
    WINDOWS_ANDROID_BODY_ASSET_ORIGIN
}

#[cfg(not(any(target_os = "windows", target_os = "android")))]
fn body_asset_origin() -> &'static str {
    MAC_LINUX_BODY_ASSET_ORIGIN
}

fn body_asset_url_for_origin(origin: &str, body_id: &str, relative_path: &str) -> Option<String> {
    if !is_valid_body_id(body_id)
        || normalize_reference(relative_path, false).ok()? != relative_path
    {
        return None;
    }
    let mut url = Url::parse(origin).ok()?;
    {
        let mut segments = url.path_segments_mut().ok()?;
        segments.push(body_id);
        for component in relative_path.split('/') {
            segments.push(component);
        }
    }
    Some(url.to_string())
}

fn body_asset_url(body_id: &str, relative_path: &str) -> Option<String> {
    body_asset_url_for_origin(body_asset_origin(), body_id, relative_path)
}

fn snapshot_for_package(
    active_root: &Path,
    package: RegisteredPackage,
) -> InstalledBodyPackageSnapshot {
    let status = if package_is_available(active_root, &package) {
        BodyPackageStatus::Available
    } else {
        BodyPackageStatus::CorruptUnavailable
    };
    let model_entry = package
        .assets
        .iter()
        .find(|asset| {
            asset.relative_path == package.model_entry_path
                && AssetKind::from_str(&asset.asset_kind) == Some(AssetKind::Model3)
                && validate_asset_suffix(&asset.relative_path, AssetKind::Model3).is_ok()
        })
        .and_then(|_| body_asset_url(&package.body_id, &package.model_entry_path))
        .unwrap_or_default();
    let assets = package
        .assets
        .into_iter()
        .filter_map(|asset| {
            let size_bytes = u64::try_from(asset.size_bytes).ok()?;
            Some(BodyPackageAssetSnapshot {
                relative_path: asset.relative_path,
                asset_kind: asset.asset_kind,
                content_hash: asset.content_hash,
                size_bytes,
            })
        })
        .collect();
    InstalledBodyPackageSnapshot {
        body_id: package.body_id,
        display_name: package.display_name,
        presentation_kind: package.presentation_kind,
        model_entry,
        package_content_hash: package.package_content_hash,
        package_version: package.package_version,
        installed_at: package.installed_at,
        status,
        assets,
    }
}

impl StorageService {
    pub fn install_live2d_body_package(
        &self,
        request: InstallLive2DBodyPackageRequest,
    ) -> Result<InstalledBodyPackageSnapshot, StorageError> {
        let package = prepare_package(&request.source_path, &request.display_name)?;
        let mut state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let (_bodies, staging_root, packages_root) = managed_roots(&active_root)?;
        if !is_valid_body_id(&package.body_id) {
            return Err(invalid_input());
        }
        let staging_dir = staging_root.join(format!("import-{}", unique_suffix()));
        fs::create_dir(&staging_dir).map_err(|_| import_copy_failed())?;
        let staged_result = copy_manifest_to_staging(&package, &staging_dir);
        if let Err(error) = staged_result {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(error);
        }

        let final_dir = packages_root.join(&package.body_id);
        if fs::symlink_metadata(&final_dir).is_ok() {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(registration_failed());
        }
        fs::rename(&staging_dir, &final_dir).map_err(|_| {
            let _ = fs::remove_dir_all(&staging_dir);
            import_copy_failed()
        })?;

        let registration = register_package_in_connection(&mut state.connection, &package);
        drop(state);
        if let Err(error) = registration {
            let _ = remove_managed_package(&packages_root, &package.body_id);
            return Err(error);
        }
        self.get_body_package(&package.body_id)?
            .ok_or_else(registration_failed)
    }

    pub fn list_body_packages(&self) -> Result<Vec<InstalledBodyPackageSnapshot>, StorageError> {
        let state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let packages = read_registered_packages(&state.connection, None)?;
        drop(state);
        Ok(packages
            .into_iter()
            .map(|package| snapshot_for_package(&active_root, package))
            .collect())
    }

    pub fn get_body_package(
        &self,
        body_id: &str,
    ) -> Result<Option<InstalledBodyPackageSnapshot>, StorageError> {
        if !is_valid_body_id(body_id) {
            return Ok(None);
        }
        let state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let mut packages = read_registered_packages(&state.connection, Some(body_id))?;
        drop(state);
        Ok(packages
            .pop()
            .map(|package| snapshot_for_package(&active_root, package)))
    }

    pub fn get_body_package_registry_snapshot(
        &self,
    ) -> Result<Vec<InstalledBodyPackageSnapshot>, StorageError> {
        self.list_body_packages()
    }

    pub fn delete_body_package(&self, body_id: &str) -> Result<(), StorageError> {
        if !is_valid_body_id(body_id) {
            return Err(package_not_found());
        }
        let mut state = self.state().map_err(|_| database_unavailable())?;
        let active_root = state.active_root.clone();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| database_unavailable())?;
        let exists: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM body_package WHERE body_id = ?1",
                params![body_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| database_unavailable())?;
        if exists.is_none() {
            return Err(package_not_found());
        }
        let in_use: i64 = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE body_id = ?1)",
                params![body_id],
                |row| row.get(0),
            )
            .map_err(|_| database_unavailable())?;
        if in_use != 0 {
            return Err(package_in_use());
        }
        transaction
            .execute(
                "DELETE FROM body_package WHERE body_id = ?1",
                params![body_id],
            )
            .map_err(|_| database_unavailable())?;
        transaction.commit().map_err(|_| database_unavailable())?;
        drop(state);

        let packages_root = active_root
            .join(MANAGED_BODIES_DIRECTORY)
            .join(MANAGED_PACKAGES_DIRECTORY);
        remove_managed_package(&packages_root, body_id)
    }
}

#[tauri::command]
pub fn install_live2d_body_package(
    storage: State<'_, StorageService>,
    request: InstallLive2DBodyPackageRequest,
) -> Result<InstalledBodyPackageSnapshot, StorageError> {
    storage.install_live2d_body_package(request)
}

#[tauri::command]
pub fn list_body_packages(
    storage: State<'_, StorageService>,
) -> Result<Vec<InstalledBodyPackageSnapshot>, StorageError> {
    storage.list_body_packages()
}

#[tauri::command]
pub fn get_body_package(
    storage: State<'_, StorageService>,
    body_id: String,
) -> Result<Option<InstalledBodyPackageSnapshot>, StorageError> {
    storage.get_body_package(&body_id)
}

#[tauri::command]
pub fn delete_body_package(
    storage: State<'_, StorageService>,
    body_id: String,
) -> Result<(), StorageError> {
    storage.delete_body_package(&body_id)
}

#[tauri::command]
pub fn get_body_package_registry_snapshot(
    storage: State<'_, StorageService>,
) -> Result<Vec<InstalledBodyPackageSnapshot>, StorageError> {
    storage.get_body_package_registry_snapshot()
}

fn percent_decode_path(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = hex_value(bytes[index + 1]).ok_or(())?;
        let low = hex_value(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_asset_request(uri: &Uri) -> Result<(String, String), ()> {
    if uri.query().is_some() {
        return Err(());
    }
    let decoded = percent_decode_path(uri.path())?;
    if decoded.contains('%') || !decoded.starts_with('/') || decoded.starts_with("//") {
        return Err(());
    }
    let mut segments = decoded[1..].split('/');
    let body_id = segments.next().ok_or(())?;
    if !is_valid_body_id(body_id) {
        return Err(());
    }
    let relative_path = segments.collect::<Vec<_>>().join("/");
    if relative_path.is_empty() || normalize_reference(&relative_path, false).is_err() {
        return Err(());
    }
    Ok((body_id.to_string(), relative_path))
}

fn mime_type(asset_kind: AssetKind) -> &'static str {
    match asset_kind {
        AssetKind::Png => "image/png",
        AssetKind::Moc3 => "application/octet-stream",
        AssetKind::Model3
        | AssetKind::Physics3
        | AssetKind::Pose3
        | AssetKind::UserData3
        | AssetKind::Cdi3
        | AssetKind::Motion3
        | AssetKind::Expression3 => "application/json",
    }
}

fn empty_asset_response(status: StatusCode) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Vec::new())
        .expect("fixed body asset response must be valid")
}

fn serve_registered_asset(
    storage: &StorageService,
    body_id: &str,
    relative_path: &str,
) -> Result<(Vec<u8>, &'static str), StorageError> {
    let state = storage.state().map_err(|_| database_unavailable())?;
    let active_root = state.active_root.clone();
    let mut packages = read_registered_packages(&state.connection, Some(body_id))?;
    drop(state);
    let package = packages.pop().ok_or_else(asset_not_registered)?;
    let asset = package
        .assets
        .iter()
        .find(|asset| asset.relative_path == relative_path)
        .ok_or_else(asset_not_registered)?;
    let asset_kind = AssetKind::from_str(&asset.asset_kind).ok_or_else(asset_not_registered)?;
    validate_asset_suffix(relative_path, asset_kind).map_err(|_| asset_not_registered())?;
    let path = resolve_managed_asset(&active_root, body_id, relative_path)?;
    let bytes = read_file_with_limit(&path, asset_kind.max_bytes())?;
    let size_bytes = u64::try_from(asset.size_bytes).map_err(|_| package_corrupt())?;
    if bytes.len() as u64 != size_bytes || hash_bytes(&bytes) != asset.content_hash {
        return Err(package_corrupt());
    }
    Ok((bytes, mime_type(asset_kind)))
}

pub(crate) fn serve_body_asset_request_for_webview(
    storage: &StorageService,
    webview_label: &str,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    if webview_label != BODY_RENDERER_WEBVIEW_LABEL {
        return empty_asset_response(StatusCode::FORBIDDEN);
    }
    serve_body_asset_request(storage, request)
}

pub(crate) fn serve_body_asset_request(
    storage: &StorageService,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return empty_asset_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let (body_id, relative_path) = match parse_asset_request(request.uri()) {
        Ok(value) => value,
        Err(()) => return empty_asset_response(StatusCode::FORBIDDEN),
    };
    let (bytes, mime) = match serve_registered_asset(storage, &body_id, &relative_path) {
        Ok(value) => value,
        Err(_) => return empty_asset_response(StatusCode::NOT_FOUND),
    };
    let content_length = bytes.len().to_string();
    let body = if request.method() == Method::HEAD {
        Vec::new()
    } else {
        bytes
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, content_length)
        .header("Access-Control-Allow-Origin", BODY_ASSET_CORS_ALLOW_ORIGIN)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("fixed body asset response must be valid")
}

pub(crate) fn validate_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    for (table, expected_sql) in [
        (
            "body_package",
            include_str!("migrations/025_managed_body_package_authority.body_package.sql"),
        ),
        (
            "body_package_asset",
            include_str!("migrations/025_managed_body_package_authority.body_package_asset.sql"),
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| {
                package_error(
                    "MIGRATION_TRANSACTION_FAILED",
                    "The body package schema could not be validated.",
                    false,
                )
            })?;
        let Some(actual) = actual else {
            return Err(package_error(
                "MIGRATION_TRANSACTION_FAILED",
                "The body package schema could not be validated.",
                false,
            ));
        };
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(package_error(
                "MIGRATION_TRANSACTION_FAILED",
                "The body package schema could not be validated.",
                false,
            ));
        }
    }
    for (trigger, expected_sql) in [
        (
            "body_package_immutable_guard",
            include_str!(
                "migrations/025_managed_body_package_authority.body_package_immutable_trigger.sql"
            ),
        ),
        (
            "body_package_asset_immutable_guard",
            include_str!(
                "migrations/025_managed_body_package_authority.body_package_asset_immutable_trigger.sql"
            ),
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [trigger],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| package_error("MIGRATION_TRANSACTION_FAILED", "The body package schema could not be validated.", false))?;
        let Some(actual) = actual else {
            return Err(package_error(
                "MIGRATION_TRANSACTION_FAILED",
                "The body package schema could not be validated.",
                false,
            ));
        };
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(package_error(
                "MIGRATION_TRANSACTION_FAILED",
                "The body package schema could not be validated.",
                false,
            ));
        }
    }

    let asset_fk_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('body_package_asset')
             WHERE \"table\"='body_package' AND \"from\"='body_id'
               AND \"to\"='body_id' AND on_delete='CASCADE'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            package_error(
                "MIGRATION_TRANSACTION_FAILED",
                "The body package schema could not be validated.",
                false,
            )
        })?;
    if asset_fk_count != 1 {
        return Err(package_error(
            "MIGRATION_TRANSACTION_FAILED",
            "The body package schema could not be validated.",
            false,
        ));
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImportFailurePoint {
    BeforeCopy,
    AfterCopyVerification,
    BeforeRegistration,
    AfterPackageInsert,
}

#[cfg(test)]
thread_local! {
    static IMPORT_FAILURE_POINT: std::cell::Cell<Option<ImportFailurePoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn fail_next_import_at_for_test(point: ImportFailurePoint) {
    IMPORT_FAILURE_POINT.with(|failure| failure.set(Some(point)));
}

#[cfg(test)]
fn maybe_import_failure(point: ImportFailurePoint) -> Result<(), StorageError> {
    IMPORT_FAILURE_POINT.with(|failure| {
        if failure.get() == Some(point) {
            failure.set(None);
            Err(match point {
                ImportFailurePoint::BeforeCopy => import_copy_failed(),
                ImportFailurePoint::AfterCopyVerification => import_verify_failed(),
                ImportFailurePoint::BeforeRegistration | ImportFailurePoint::AfterPackageInsert => {
                    registration_failed()
                }
            })
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn maybe_import_failure(_point: ImportFailurePoint) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use serde_json::{json, Value};
    use tauri::http::{header, Method, Request, StatusCode};

    use super::*;
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};

    struct Fixture {
        storage: StorageService,
        root: tempfile::TempDir,
        descriptor: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            write_source_assets(&source);
            let descriptor = source.join("avatar.model3.json");
            write_full_descriptor(&descriptor);
            let storage =
                StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
            Self {
                storage,
                root,
                descriptor,
            }
        }

        fn source_dir(&self) -> &Path {
            self.descriptor.parent().unwrap()
        }

        fn package_dir(&self, body_id: &str) -> PathBuf {
            self.root
                .path()
                .join("data")
                .join(MANAGED_BODIES_DIRECTORY)
                .join(MANAGED_PACKAGES_DIRECTORY)
                .join(body_id)
        }

        fn packages_dir(&self) -> PathBuf {
            self.root
                .path()
                .join("data")
                .join(MANAGED_BODIES_DIRECTORY)
                .join(MANAGED_PACKAGES_DIRECTORY)
        }
    }

    fn write_source_assets(source: &Path) {
        for (name, contents) in [
            ("avatar.moc3", b"moc-bytes".as_slice()),
            ("texture.png", b"png-bytes".as_slice()),
            ("physics.physics3.json", br#"{"Physics":[]}"#.as_slice()),
            ("pose.pose3.json", br#"{"Pose":[]}"#.as_slice()),
            ("userdata.userdata3.json", br#"{"UserData":[]}"#.as_slice()),
            ("display.cdi3.json", br#"{"Parameters":[]}"#.as_slice()),
            ("idle.motion3.json", br#"{"Motion":[]}"#.as_slice()),
            ("smile.exp3.json", br#"{"Expression":[]}"#.as_slice()),
        ] {
            fs::write(source.join(name), contents).unwrap();
        }
    }

    fn write_full_descriptor(path: &Path) {
        write_descriptor_value(
            path,
            json!({
                "Version": 3,
                "FileReferences": {
                    "Moc": "avatar.moc3",
                    "Textures": ["texture.png"],
                    "Physics": "physics.physics3.json",
                    "Pose": "pose.pose3.json",
                    "UserData": "userdata.userdata3.json",
                    "DisplayInfo": "display.cdi3.json",
                    "Motions": {
                        "Idle": [{"File": "idle.motion3.json"}]
                    },
                    "Expressions": [{"Name": "smile", "File": "smile.exp3.json"}]
                }
            }),
        );
    }

    fn write_descriptor_value(path: &Path, value: Value) {
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn write_minimal_descriptor(path: &Path, moc: &str, textures: Vec<String>) {
        write_descriptor_value(
            path,
            json!({
                "Version": 3,
                "FileReferences": {
                    "Moc": moc,
                    "Textures": textures
                }
            }),
        );
    }

    fn install(fixture: &Fixture) -> InstalledBodyPackageSnapshot {
        fixture
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: fixture.descriptor.to_str().unwrap().to_string(),
                display_name: "Test Body".to_string(),
            })
            .unwrap()
    }

    fn request(method: Method, uri: &str) -> Request<Vec<u8>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Vec::new())
            .unwrap_or_else(|error| panic!("invalid test URI {uri:?}: {error}"))
    }

    fn body_asset_uri(body_id: &str, path: &str) -> String {
        format!("{BODY_ASSET_PROTOCOL_SCHEME}://localhost/{body_id}/{path}")
    }

    #[test]
    fn body_asset_url_uses_platform_origin_and_encodes_path_components() {
        let body_id = "live2d-deadbeef";
        let relative_path = "Textures/face one.png";
        assert_eq!(
            body_asset_url_for_origin(WINDOWS_ANDROID_BODY_ASSET_ORIGIN, body_id, relative_path,)
                .unwrap(),
            "http://digital-life-body.localhost/live2d-deadbeef/Textures/face%20one.png"
        );
        assert_eq!(
            body_asset_url_for_origin(MAC_LINUX_BODY_ASSET_ORIGIN, body_id, relative_path).unwrap(),
            "digital-life-body://localhost/live2d-deadbeef/Textures/face%20one.png"
        );
        #[cfg(any(target_os = "windows", target_os = "android"))]
        assert_eq!(
            body_asset_url(body_id, relative_path).unwrap(),
            "http://digital-life-body.localhost/live2d-deadbeef/Textures/face%20one.png"
        );
        #[cfg(not(any(target_os = "windows", target_os = "android")))]
        assert_eq!(
            body_asset_url(body_id, relative_path).unwrap(),
            "digital-life-body://localhost/live2d-deadbeef/Textures/face%20one.png"
        );
    }

    fn assert_no_managed_children(path: &Path) {
        let children = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        assert!(
            children.is_empty(),
            "managed directory is not empty: {path:?}"
        );
    }

    #[test]
    fn valid_local_package_is_copied_registered_and_exposed_without_source_paths() {
        let fixture = Fixture::new();
        let package = install(&fixture);

        assert!(is_valid_body_id(&package.body_id));
        assert_eq!(package.presentation_kind, "live2d");
        assert_eq!(package.status, BodyPackageStatus::Available);
        assert_eq!(
            package.model_entry,
            body_asset_url(&package.body_id, "avatar.model3.json").unwrap()
        );
        assert_eq!(package.assets.len(), 9);
        let asset_paths = package
            .assets
            .iter()
            .map(|asset| asset.relative_path.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(asset_paths.len(), package.assets.len());
        assert!(asset_paths.contains("avatar.model3.json"));
        assert!(asset_paths.contains("avatar.moc3"));
        assert!(asset_paths.contains("texture.png"));
        assert!(fixture.package_dir(&package.body_id).is_dir());
        {
            let state = fixture.storage.state().unwrap();
            assert_eq!(
                state
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM body_package WHERE body_id=?1",
                        [&package.body_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
            assert_eq!(
                state
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM body_package_asset WHERE body_id=?1",
                        [&package.body_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                9
            );
        }
        for asset in &package.assets {
            let bytes = fs::read(
                fixture
                    .package_dir(&package.body_id)
                    .join(&asset.relative_path),
            )
            .unwrap();
            assert_eq!(asset.size_bytes, bytes.len() as u64);
            assert_eq!(asset.content_hash, hash_bytes(&bytes));
        }

        let serialized = serde_json::to_string(&package).unwrap();
        assert!(!serialized.contains(fixture.descriptor.to_str().unwrap()));
        assert!(!serialized.contains("\\data\\"));

        let second = install(&fixture);
        assert_ne!(package.body_id, second.body_id);
        assert_eq!(package.package_content_hash, second.package_content_hash);
        assert_eq!(fixture.storage.list_body_packages().unwrap().len(), 2);
        assert!(fixture
            .storage
            .get_body_package("live2d-deadbeef")
            .unwrap()
            .is_none());
    }

    #[test]
    fn direct_remote_source_strings_are_rejected_before_registration() {
        let fixture = Fixture::new();
        for source_path in [
            "https://example.invalid/avatar.model3.json",
            "http://example.invalid/avatar.model3.json",
            "file:///tmp/avatar.model3.json",
            "data:application/json,{}",
            "javascript:alert(1)",
            "//server/share/avatar.model3.json",
        ] {
            let error = fixture
                .storage
                .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                    source_path: source_path.to_string(),
                    display_name: "Rejected".to_string(),
                })
                .unwrap_err();
            assert!(
                error.code.starts_with("BODY_PACKAGE_"),
                "unexpected error for {source_path}: {error:?}"
            );
        }
        assert!(fixture.storage.list_body_packages().unwrap().is_empty());
    }

    #[test]
    fn unsafe_or_unsupported_descriptor_references_are_rejected() {
        let fixture = Fixture::new();
        for (index, reference) in [
            "../escape.moc3",
            "/absolute.moc3",
            "C:/absolute.moc3",
            "\\\\server\\share\\escape.moc3",
            "https://example.invalid/remote.moc3",
            "file:///tmp/remote.moc3",
            "data:application/octet-stream,evil",
            "javascript:alert(1)",
            "not-a-moc.js",
        ]
        .into_iter()
        .enumerate()
        {
            let descriptor = fixture
                .source_dir()
                .join(format!("unsafe-{index}.model3.json"));
            write_minimal_descriptor(&descriptor, reference, vec!["texture.png".to_string()]);
            let error = fixture
                .storage
                .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                    source_path: descriptor.to_str().unwrap().to_string(),
                    display_name: "Rejected".to_string(),
                })
                .unwrap_err();
            assert!(
                error.code == "BODY_PACKAGE_ASSET_PATH_UNSAFE"
                    || error.code == "BODY_PACKAGE_ASSET_ESCAPE"
                    || error.code == "BODY_PACKAGE_ASSET_TYPE_UNSUPPORTED",
                "unsafe reference {reference} returned {error:?}"
            );
        }
        assert!(fixture.storage.list_body_packages().unwrap().is_empty());
    }

    #[test]
    fn invalid_descriptor_shapes_and_references_fail_closed() {
        let wrong_extension = Fixture::new();
        let wrong_path = wrong_extension.source_dir().join("avatar.json");
        fs::write(&wrong_path, br#"{"FileReferences":{}}"#).unwrap();
        let error = wrong_extension
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: wrong_path.to_str().unwrap().to_string(),
                display_name: "Wrong extension".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_INVALID_INPUT");

        let malformed = Fixture::new();
        fs::write(&malformed.descriptor, b"not json").unwrap();
        let error = malformed
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: malformed.descriptor.to_str().unwrap().to_string(),
                display_name: "Malformed".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_DESCRIPTOR_INVALID");

        for (label, moc, textures, expected) in [
            (
                "missing moc",
                "missing.moc3",
                vec!["texture.png".to_string()],
                "BODY_PACKAGE_ASSET_MISSING",
            ),
            (
                "missing texture",
                "avatar.moc3",
                vec!["missing.png".to_string()],
                "BODY_PACKAGE_ASSET_MISSING",
            ),
        ] {
            let fixture = Fixture::new();
            write_minimal_descriptor(&fixture.descriptor, moc, textures);
            let error = fixture
                .storage
                .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                    source_path: fixture.descriptor.to_str().unwrap().to_string(),
                    display_name: label.to_string(),
                })
                .unwrap_err();
            assert_eq!(error.code, expected, "{label}");
        }

        let missing_motion = Fixture::new();
        write_descriptor_value(
            &missing_motion.descriptor,
            json!({
                "FileReferences": {
                    "Moc": "avatar.moc3",
                    "Textures": ["texture.png"],
                    "Motions": {"Idle": [{"File": "missing.motion3.json"}]}
                }
            }),
        );
        let error = missing_motion
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: missing_motion.descriptor.to_str().unwrap().to_string(),
                display_name: "Missing motion".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_ASSET_MISSING");

        let oversized_asset = Fixture::new();
        let large_path = oversized_asset.source_dir().join("large.moc3");
        let large_file = fs::File::create(&large_path).unwrap();
        large_file.set_len(MAX_INDIVIDUAL_ASSET_BYTES + 1).unwrap();
        write_minimal_descriptor(
            &oversized_asset.descriptor,
            "large.moc3",
            vec!["texture.png".to_string()],
        );
        let error = oversized_asset
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: oversized_asset.descriptor.to_str().unwrap().to_string(),
                display_name: "Oversized asset".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_TOO_LARGE");
    }

    #[test]
    fn descriptor_limits_and_manifest_deduplication_are_enforced() {
        let oversized = Fixture::new();
        fs::write(
            &oversized.descriptor,
            vec![b'x'; usize::try_from(MAX_MODEL_DESCRIPTOR_BYTES + 1).unwrap()],
        )
        .unwrap();
        let error = oversized
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: oversized.descriptor.to_str().unwrap().to_string(),
                display_name: "Oversized".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_TOO_LARGE");

        let duplicate = Fixture::new();
        write_minimal_descriptor(
            &duplicate.descriptor,
            "avatar.moc3",
            vec!["texture.png".to_string(), "./texture.png".to_string()],
        );
        let error = duplicate
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: duplicate.descriptor.to_str().unwrap().to_string(),
                display_name: "Duplicate".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_DUPLICATE_ASSET");

        let too_many = Fixture::new();
        let mut textures = Vec::new();
        for index in 0..255 {
            let name = format!("texture-{index:03}.png");
            fs::write(too_many.source_dir().join(&name), b"png").unwrap();
            textures.push(name);
        }
        write_minimal_descriptor(&too_many.descriptor, "avatar.moc3", textures);
        let error = too_many
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: too_many.descriptor.to_str().unwrap().to_string(),
                display_name: "Too Many".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_TOO_MANY_ASSETS");

        let total_bound = Fixture::new();
        let total_bound_root = fs::canonicalize(total_bound.source_dir()).unwrap();
        let mut manifest = BTreeMap::new();
        let mut total_bytes = MAX_TOTAL_PACKAGE_BYTES;
        let error = append_manifest_entry(
            &total_bound_root,
            &mut manifest,
            &mut total_bytes,
            "texture.png",
            AssetKind::Png,
        )
        .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_TOO_LARGE");

        let sound = Fixture::new();
        write_descriptor_value(
            &sound.descriptor,
            json!({
                "FileReferences": {
                    "Moc": "avatar.moc3",
                    "Textures": ["texture.png"],
                    "Motions": {"Idle": [{
                        "File": "idle.motion3.json",
                        "Sound": "voice.wav"
                    }]}
                }
            }),
        );
        let error = sound
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: sound.descriptor.to_str().unwrap().to_string(),
                display_name: "Audio".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_ASSET_TYPE_UNSUPPORTED");
    }

    #[test]
    fn import_failures_leave_no_registry_row_or_managed_package() {
        for point in [
            ImportFailurePoint::BeforeCopy,
            ImportFailurePoint::AfterCopyVerification,
            ImportFailurePoint::BeforeRegistration,
            ImportFailurePoint::AfterPackageInsert,
        ] {
            let fixture = Fixture::new();
            fail_next_import_at_for_test(point);
            let error = fixture
                .storage
                .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                    source_path: fixture.descriptor.to_str().unwrap().to_string(),
                    display_name: "Failure".to_string(),
                })
                .unwrap_err();
            assert!(
                error.code == "BODY_PACKAGE_IMPORT_COPY_FAILED"
                    || error.code == "BODY_PACKAGE_IMPORT_VERIFY_FAILED"
                    || error.code == "BODY_PACKAGE_REGISTRATION_FAILED",
                "unexpected failure-point error: {error:?}"
            );
            assert!(fixture.storage.list_body_packages().unwrap().is_empty());
            assert_no_managed_children(&fixture.packages_dir());
            assert_no_managed_children(
                &fixture
                    .root
                    .path()
                    .join("data")
                    .join(MANAGED_BODIES_DIRECTORY)
                    .join(MANAGED_STAGING_DIRECTORY),
            );
        }
    }

    #[test]
    fn registry_reports_corruption_and_delete_removes_authority_before_files() {
        let fixture = Fixture::new();
        let package = install(&fixture);
        fs::write(
            fixture.package_dir(&package.body_id).join("texture.png"),
            b"tampered",
        )
        .unwrap();
        let listed = fixture
            .storage
            .get_body_package(&package.body_id)
            .unwrap()
            .unwrap();
        assert_eq!(listed.status, BodyPackageStatus::CorruptUnavailable);

        fixture
            .storage
            .delete_body_package(&package.body_id)
            .unwrap();
        assert!(fixture
            .storage
            .get_body_package(&package.body_id)
            .unwrap()
            .is_none());
        assert!(!fixture.package_dir(&package.body_id).exists());

        let failed_cleanup = Fixture::new();
        let package = install(&failed_cleanup);
        fs::remove_dir_all(failed_cleanup.package_dir(&package.body_id)).unwrap();
        fs::write(
            failed_cleanup.package_dir(&package.body_id),
            b"not a directory",
        )
        .unwrap();
        let error = failed_cleanup
            .storage
            .delete_body_package(&package.body_id)
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_CLEANUP_FAILED");
        assert!(failed_cleanup
            .storage
            .get_body_package(&package.body_id)
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_and_directory_symlink_escapes_are_rejected() {
        use std::os::unix::fs::symlink;

        let file_fixture = Fixture::new();
        let outside_file = file_fixture.root.path().join("outside.moc3");
        fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside_file, file_fixture.source_dir().join("linked.moc3")).unwrap();
        write_minimal_descriptor(
            &file_fixture.descriptor,
            "linked.moc3",
            vec!["texture.png".to_string()],
        );
        let error = file_fixture
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: file_fixture.descriptor.to_str().unwrap().to_string(),
                display_name: "File link".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_ASSET_PATH_UNSAFE");

        let directory_fixture = Fixture::new();
        let outside_dir = directory_fixture.root.path().join("outside-dir");
        fs::create_dir(&outside_dir).unwrap();
        fs::write(outside_dir.join("linked.moc3"), b"outside").unwrap();
        symlink(
            &outside_dir,
            directory_fixture.source_dir().join("linked-dir"),
        )
        .unwrap();
        write_minimal_descriptor(
            &directory_fixture.descriptor,
            "linked-dir/linked.moc3",
            vec!["texture.png".to_string()],
        );
        let error = directory_fixture
            .storage
            .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                source_path: directory_fixture.descriptor.to_str().unwrap().to_string(),
                display_name: "Directory link".to_string(),
            })
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_ASSET_PATH_UNSAFE");
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_source_components_are_rejected_or_creation_is_explicitly_denied() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let file_fixture = Fixture::new();
        let file_link = file_fixture.source_dir().join("linked.moc3");
        match symlink_file(file_fixture.source_dir().join("avatar.moc3"), &file_link) {
            Ok(()) => {
                write_minimal_descriptor(
                    &file_fixture.descriptor,
                    "linked.moc3",
                    vec!["texture.png".to_string()],
                );
                let error = file_fixture
                    .storage
                    .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                        source_path: file_fixture.descriptor.to_str().unwrap().to_string(),
                        display_name: "File reparse".to_string(),
                    })
                    .unwrap_err();
                assert_eq!(error.code, "BODY_PACKAGE_ASSET_PATH_UNSAFE");
            }
            Err(error) => {
                assert!(
                    matches!(error.raw_os_error(), Some(5) | Some(1314)),
                    "unexpected Windows symlink failure: {error:?}"
                );
            }
        }

        let directory_fixture = Fixture::new();
        let directory_link = directory_fixture.source_dir().join("linked-dir");
        match symlink_dir(directory_fixture.source_dir(), &directory_link) {
            Ok(()) => {
                let linked_descriptor = directory_link.join("avatar.model3.json");
                let error = directory_fixture
                    .storage
                    .install_live2d_body_package(InstallLive2DBodyPackageRequest {
                        source_path: linked_descriptor.to_str().unwrap().to_string(),
                        display_name: "Directory reparse".to_string(),
                    })
                    .unwrap_err();
                assert_eq!(error.code, "BODY_PACKAGE_ASSET_PATH_UNSAFE");
            }
            Err(error) => {
                assert!(
                    matches!(error.raw_os_error(), Some(5) | Some(1314)),
                    "unexpected Windows directory-link failure: {error:?}"
                );
            }
        }
    }

    #[test]
    fn in_use_package_cannot_be_deleted_and_life_body_id_is_not_rewritten() {
        let fixture = Fixture::new();
        let package = install(&fixture);
        fixture
            .storage
            .save_persona(PersonaTemplateRecord {
                id: "persona-body-package".to_string(),
                name: "Persona".to_string(),
                version: 1,
                persona_json: "{}".to_string(),
            })
            .unwrap();
        fixture
            .storage
            .save_life(LifeIdentityRecord {
                id: "life-body-package".to_string(),
                name: "Life".to_string(),
                created_at: "2026-08-29T00:00:00.000Z".to_string(),
                version: 1,
                body_id: package.body_id.clone(),
                persona_id: "persona-body-package".to_string(),
                persona_version: 1,
            })
            .unwrap();

        let error = fixture
            .storage
            .delete_body_package(&package.body_id)
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_IN_USE");
        assert_eq!(
            fixture
                .storage
                .get_life("life-body-package")
                .unwrap()
                .unwrap()
                .body_id,
            package.body_id
        );
        assert!(fixture.package_dir(&package.body_id).exists());
        let error = fixture
            .storage
            .delete_body_package("../outside")
            .unwrap_err();
        assert_eq!(error.code, "BODY_PACKAGE_NOT_FOUND");
    }

    #[test]
    fn custom_body_asset_protocol_serves_only_registered_assets_with_bounded_methods() {
        let fixture = Fixture::new();
        let package = install(&fixture);
        let model_response =
            serve_body_asset_request(&fixture.storage, request(Method::GET, &package.model_entry));
        assert_eq!(model_response.status(), StatusCode::OK);
        assert_eq!(
            model_response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
        assert_eq!(
            model_response.body(),
            &fs::read(&fixture.descriptor).unwrap()
        );
        assert_eq!(
            model_response
                .headers()
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );

        let texture_uri = body_asset_uri(&package.body_id, "texture.png");
        let texture_response =
            serve_body_asset_request(&fixture.storage, request(Method::GET, &texture_uri));
        assert_eq!(texture_response.status(), StatusCode::OK);
        assert_eq!(
            texture_response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "image/png"
        );
        assert_eq!(texture_response.body(), b"png-bytes");

        let head_response =
            serve_body_asset_request(&fixture.storage, request(Method::HEAD, &texture_uri));
        assert_eq!(head_response.status(), StatusCode::OK);
        assert!(head_response.body().is_empty());
        assert_eq!(
            head_response
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "9"
        );
        assert_eq!(
            head_response
                .headers()
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );

        let post_response =
            serve_body_asset_request(&fixture.storage, request(Method::POST, &texture_uri));
        assert_eq!(post_response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let forbidden_paths = [
            format!("{BODY_ASSET_PROTOCOL_SCHEME}://localhost//avatar.model3.json"),
            body_asset_uri(&package.body_id, "../avatar.model3.json"),
            body_asset_uri(&package.body_id, "%2e%2e/avatar.model3.json"),
            body_asset_uri(&package.body_id, "%252e%252e/avatar.model3.json"),
            body_asset_uri(&package.body_id, "avatar%5c.model3.json"),
            body_asset_uri(&package.body_id, "C%3A/evil.png"),
            body_asset_uri(&package.body_id, "%5C%5Cserver%5Cevil.png"),
            body_asset_uri(&package.body_id, "/avatar.model3.json"),
            body_asset_uri(&package.body_id, "avatar.model3.json%ZZ"),
            format!("{texture_uri}?cache=1"),
            body_asset_uri(&package.body_id, "avatar.model3.json%23fragment"),
        ];
        for uri in forbidden_paths {
            let response = serve_body_asset_request(&fixture.storage, request(Method::GET, &uri));
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "unsafe URI was served: {uri}"
            );
        }

        let unknown_body = body_asset_uri("live2d-deadbeef", "texture.png");
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &unknown_body))
                .status(),
            StatusCode::NOT_FOUND
        );
        let unknown_asset = body_asset_uri(&package.body_id, "unregistered.png");
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &unknown_asset))
                .status(),
            StatusCode::NOT_FOUND
        );
        fs::write(
            fixture.package_dir(&package.body_id).join("extra.png"),
            b"extra",
        )
        .unwrap();
        let extra_asset = body_asset_uri(&package.body_id, "extra.png");
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &extra_asset)).status(),
            StatusCode::NOT_FOUND
        );
        fs::write(
            fixture.package_dir(&package.body_id).join("script.js"),
            b"alert(1)",
        )
        .unwrap();
        let executable_asset = body_asset_uri(&package.body_id, "script.js");
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &executable_asset))
                .status(),
            StatusCode::NOT_FOUND
        );
        let orphan_body_id = "live2d-deadbeef";
        let orphan_dir = fixture.packages_dir().join(orphan_body_id);
        fs::create_dir(&orphan_dir).unwrap();
        fs::write(orphan_dir.join("orphan.model3.json"), b"{}").unwrap();
        let orphan_asset = body_asset_uri(orphan_body_id, "orphan.model3.json");
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &orphan_asset))
                .status(),
            StatusCode::NOT_FOUND
        );

        fixture
            .storage
            .delete_body_package(&package.body_id)
            .unwrap();
        assert_eq!(
            serve_body_asset_request(&fixture.storage, request(Method::GET, &texture_uri)).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn body_asset_protocol_allows_only_the_main_webview_label() {
        let fixture = Fixture::new();
        let package = install(&fixture);

        let main_response = serve_body_asset_request_for_webview(
            &fixture.storage,
            BODY_RENDERER_WEBVIEW_LABEL,
            request(Method::GET, &package.model_entry),
        );
        assert_eq!(main_response.status(), StatusCode::OK);
        assert_eq!(
            main_response
                .headers()
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );

        for label in ["settings", "chat", "background"] {
            let response = serve_body_asset_request_for_webview(
                &fixture.storage,
                label,
                request(Method::GET, &package.model_entry),
            );
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "label: {label}");
            assert!(response.body().is_empty(), "label: {label}");
        }
    }
}
