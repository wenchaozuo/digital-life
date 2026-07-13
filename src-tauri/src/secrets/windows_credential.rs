use std::{ffi::c_void, ptr, slice};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_NOT_FOUND},
    Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_MAX_CREDENTIAL_BLOB_SIZE,
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    },
};

use super::{
    SecretIdentifier, SecretStatus, SecretStore, SecretStoreError, SecretStoreErrorCode,
    SecretValue,
};

const PRODUCTION_NAMESPACE: &str = "com.digitallife.app/credential/v1";
const TARGET_FORMAT_VERSION: &[u8] = b"digital-life-secret-target-v1";

pub struct WindowsCredentialSecretStore {
    namespace: &'static str,
}

impl Default for WindowsCredentialSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsCredentialSecretStore {
    pub const fn new() -> Self {
        Self {
            namespace: PRODUCTION_NAMESPACE,
        }
    }

    fn target_name(&self, identifier: &SecretIdentifier) -> Result<Vec<u16>, SecretStoreError> {
        identifier.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(TARGET_FORMAT_VERSION);
        hasher.update([0]);
        hasher.update(identifier.purpose.canonical_name().as_bytes());
        hasher.update([0]);
        hasher.update(identifier.profile_id.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        Ok(format!("{}/{digest}\0", self.namespace)
            .encode_utf16()
            .collect())
    }

    fn read_raw(
        &self,
        identifier: &SecretIdentifier,
    ) -> Result<CredentialBuffer, SecretStoreError> {
        let target = self.target_name(identifier)?;
        let mut credential = ptr::null_mut();
        // SAFETY: target is NUL-terminated and credential is a valid out pointer.
        let success = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
        if success == 0 {
            return Err(last_windows_error());
        }
        if credential.is_null() {
            return Err(SecretStoreError::internal());
        }
        Ok(CredentialBuffer(credential))
    }
}

impl SecretStore for WindowsCredentialSecretStore {
    fn set_secret(
        &self,
        identifier: &SecretIdentifier,
        value: SecretValue,
    ) -> Result<SecretStatus, SecretStoreError> {
        let mut target = self.target_name(identifier)?;
        let mut username: Vec<u16> = "Digital Life\0".encode_utf16().collect();
        let bytes = value.expose_secret().as_bytes();
        if bytes.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(SecretStoreError::new(
                SecretStoreErrorCode::InvalidSecret,
                "The credential value exceeds the Windows secure storage limit.",
                false,
            ));
        }
        let blob_size = u32::try_from(bytes.len()).map_err(|_| SecretStoreError::internal())?;
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: blob_size,
            CredentialBlob: bytes.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: username.as_mut_ptr(),
            ..Default::default()
        };
        // SAFETY: all pointers remain valid for the duration of CredWriteW and
        // sizes exactly describe their buffers. The API does not retain them.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(last_windows_error());
        }
        Ok(SecretStatus {
            exists: true,
            updated: true,
            deleted: false,
        })
    }

    fn get_secret(&self, identifier: &SecretIdentifier) -> Result<SecretValue, SecretStoreError> {
        let buffer = self.read_raw(identifier)?;
        // SAFETY: CredentialBuffer owns a successful CredReadW allocation.
        let credential = unsafe { &*buffer.0 };
        if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
            return Err(SecretStoreError::internal());
        }
        // SAFETY: Windows reports the readable byte length for this blob.
        let bytes = unsafe {
            slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
        };
        let value = std::str::from_utf8(bytes).map_err(|_| SecretStoreError::internal())?;
        SecretValue::new(value.to_owned()).map_err(|_| SecretStoreError::internal())
    }

    fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
        match self.read_raw(identifier) {
            Ok(buffer) => {
                drop(buffer);
                Ok(true)
            }
            Err(error) if error.code == SecretStoreErrorCode::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn delete_secret(
        &self,
        identifier: &SecretIdentifier,
    ) -> Result<SecretStatus, SecretStoreError> {
        let target = self.target_name(identifier)?;
        // SAFETY: target is a valid, NUL-terminated UTF-16 string.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let error = last_windows_error();
            if error.code == SecretStoreErrorCode::NotFound {
                return Ok(SecretStatus {
                    exists: false,
                    updated: false,
                    deleted: false,
                });
            }
            return Err(error);
        }
        Ok(SecretStatus {
            exists: false,
            updated: false,
            deleted: true,
        })
    }
}

struct CredentialBuffer(*mut CREDENTIALW);

impl Drop for CredentialBuffer {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: this pointer comes from CredReadW. Zero only the credential
        // blob before releasing the complete allocation with CredFree.
        unsafe {
            let credential = &mut *self.0;
            if !credential.CredentialBlob.is_null() && credential.CredentialBlobSize > 0 {
                ptr::write_bytes(
                    credential.CredentialBlob,
                    0,
                    credential.CredentialBlobSize as usize,
                );
            }
            CredFree(self.0.cast::<c_void>());
        }
    }
}

fn last_windows_error() -> SecretStoreError {
    // SAFETY: GetLastError has no preconditions and is read immediately after
    // the failing credential API call.
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_FOUND {
        SecretStoreError::not_found()
    } else {
        SecretStoreError::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretPurpose;

    #[test]
    fn target_name_is_stable_and_does_not_expose_profile_id() {
        let store = WindowsCredentialSecretStore::new();
        let identifier =
            SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, "private-profile-name")
                .unwrap();
        let first = store.target_name(&identifier).unwrap();
        let second = store.target_name(&identifier).unwrap();
        assert_eq!(first, second);
        let target = String::from_utf16_lossy(&first);
        assert!(target.starts_with(PRODUCTION_NAMESPACE));
        assert!(!target.contains("private-profile-name"));
    }
}
