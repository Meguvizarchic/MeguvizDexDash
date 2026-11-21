//! Content-addressed source blob storage (`thin` external CAS vs `standalone` embedded blobs).

use mdd_types::{ErrorCode, MddError, MddResult, sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Content-addressed external blob store rooted under a cache directory (`cas/sha256/<p2>/<hex>.blob`).
#[derive(Clone, Debug)]
pub struct CasStore {
    root: PathBuf,
}

impl CasStore {
    pub fn new(cache_root: impl AsRef<Path>) -> Self {
        Self {
            root: cache_root.as_ref().join("cas").join("sha256"),
        }
    }

    pub fn relative_path_for_digest(hex_digest: &str) -> MddResult<String> {
        if hex_digest.len() != 64
            || !hex_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.cas",
                "CAS digest must be lowercase 64-digit SHA-256 hex",
            ));
        }
        let prefix = &hex_digest[..2];
        Ok(format!("cas/sha256/{prefix}/{hex_digest}.blob"))
    }

    pub fn path_for_digest(&self, hex_digest: &str) -> MddResult<PathBuf> {
        if hex_digest.len() != 64
            || !hex_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.cas",
                "CAS digest must be lowercase 64-digit SHA-256 hex",
            ));
        }
        Ok(self
            .root
            .join(&hex_digest[..2])
            .join(format!("{hex_digest}.blob")))
    }

    /// Write raw bytes to the external CAS via private temporary file + fsync + atomic publish.
    /// Returns `(sha256_hex, relative_path, reused_existing)`.
    pub fn put_verified(&self, bytes: &[u8]) -> MddResult<(String, String, bool)> {
        let digest = sha256(bytes);
        let rel = Self::relative_path_for_digest(&digest)?;
        let target = self.path_for_digest(&digest)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                MddError::new(ErrorCode::InternalFault, "cache.cas", error.to_string())
            })?;
        }
        if target.is_file()
            && let Ok(existing) = fs::read(&target)
            && sha256(&existing) == digest
        {
            return Ok((digest, rel, true));
        }
        let temp = self.temp_path(&target)?;
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|error| {
                    MddError::new(ErrorCode::InternalFault, "cache.cas", error.to_string())
                })?;
            if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&temp);
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "cache.cas",
                    error.to_string(),
                ));
            }
        }
        if let Err(error) = fs::rename(&temp, &target) {
            let _ = fs::remove_file(&temp);
            // Another concurrent writer may have finished publishing the exact content-addressed blob.
            if target.is_file()
                && let Ok(existing) = fs::read(&target)
                && sha256(&existing) == digest
            {
                return Ok((digest, rel, true));
            }
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "cache.cas",
                error.to_string(),
            ));
        }
        Ok((digest, rel, false))
    }

    /// Read an external CAS object and strictly re-verify its length and SHA-256 digest.
    pub fn get_verified(&self, expected_digest: &str, expected_len: u64) -> MddResult<Vec<u8>> {
        let target = self.path_for_digest(expected_digest)?;
        if !target.exists() {
            return Err(MddError::new(
                ErrorCode::StaleCache,
                "cache.cas",
                format!("external CAS blob missing for sha256:{expected_digest}"),
            )
            .detail("reason", "CAS_BLOB_MISSING")
            .detail("expected_sha256", expected_digest.to_owned()));
        }
        let bytes = fs::read(&target).map_err(|error| {
            MddError::new(ErrorCode::CacheCorrupt, "cache.cas", error.to_string())
                .detail("reason", "CAS_BLOB_READ_FAILED")
        })?;
        if bytes.len() as u64 != expected_len || sha256(&bytes) != expected_digest {
            return Err(MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.cas",
                format!("external CAS blob digest/length mismatch for sha256:{expected_digest}"),
            )
            .detail("reason", "CAS_BLOB_DIGEST_MISMATCH")
            .detail("expected_sha256", expected_digest.to_owned()));
        }
        Ok(bytes)
    }

    fn temp_path(&self, target: &Path) -> MddResult<PathBuf> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "cache.cas", error.to_string())
        })?;
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("blob");
        Ok(target.with_file_name(format!(".{file_name}.tmp.{}.{hex}", std::process::id())))
    }

    pub fn verify_digest_slice(
        bytes: &[u8],
        expected_digest: &str,
        expected_len: u64,
    ) -> MddResult<()> {
        if bytes.len() as u64 != expected_len || sha256(bytes) != expected_digest {
            return Err(MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.cas",
                "embedded source blob digest/length mismatch",
            )
            .detail("reason", "EMBEDDED_BLOB_DIGEST_MISMATCH")
            .detail("expected_sha256", expected_digest.to_owned()));
        }
        Ok(())
    }
}
