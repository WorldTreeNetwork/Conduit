//! Blob storage backend for uploaded media.
//!
//! Files are stored on the filesystem under a sharded directory layout:
//! `{root}/{sha256[0..2]}/{sha256[2..4]}/{sha256}`.
//!
//! Content-addressed: identical content is deduplicated automatically.
//! The directory root is read from the `CONDUIT_MEDIA_ROOT` environment
//! variable, defaulting to `./media-data`.

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use tokio::fs;

/// Blob storage rooted at a filesystem directory.
#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Create (or open) a `BlobStore` at `root`.  The directory is created if
    /// it does not already exist.
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Read the media root from `CONDUIT_MEDIA_ROOT` (default `./media-data`).
    pub fn from_env() -> std::io::Result<Self> {
        let root = std::env::var("CONDUIT_MEDIA_ROOT")
            .unwrap_or_else(|_| "./media-data".to_owned());
        Self::new(PathBuf::from(root))
    }

    /// Store `bytes` on disk.  Returns `(sha256_hex, rel_path, size)`.
    ///
    /// If a file with the same sha256 already exists on disk it is not
    /// rewritten (content-addressed dedup).
    pub async fn put(&self, bytes: &[u8]) -> std::io::Result<(String, String, u64)> {
        let sha256 = hex::encode(Sha256::digest(bytes));
        let rel_path = shard_path(&sha256);
        let abs_path = self.root.join(&rel_path);

        // Create parent dirs.
        if let Some(parent) = abs_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Dedup: if the file already exists, skip writing.
        if !abs_path.exists() {
            fs::write(&abs_path, bytes).await?;
        }

        let size = bytes.len() as u64;
        Ok((sha256, rel_path, size))
    }

    /// Read and return the file at `rel_path` (relative to root).
    pub async fn get(&self, rel_path: &str) -> std::io::Result<Vec<u8>> {
        let abs_path = self.root.join(rel_path);
        fs::read(&abs_path).await
    }

    /// Delete the file at `rel_path` (relative to root).
    ///
    /// Does not error if the file does not exist.
    pub async fn delete(&self, rel_path: &str) -> std::io::Result<()> {
        let abs_path = self.root.join(rel_path);
        match fs::remove_file(&abs_path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return the absolute path for `rel_path`.  Useful for streaming reads.
    pub fn abs_path(&self, rel_path: &str) -> PathBuf {
        self.root.join(rel_path)
    }
}

/// Build the sharded relative path for a sha256 hex string.
/// Layout: `{sha[0..2]}/{sha[2..4]}/{sha}`.
fn shard_path(sha256: &str) -> String {
    format!("{}/{}/{}", &sha256[0..2], &sha256[2..4], sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn round_trip_bytes() {
        let dir = TempDir::new().unwrap();
        let store = BlobStore::new(dir.path().to_path_buf()).unwrap();
        let data = b"hello media world";
        let (sha, path, size) = store.put(data).await.unwrap();
        assert_eq!(size, data.len() as u64);
        assert!(!sha.is_empty());
        let got = store.get(&path).await.unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn dedup_same_content() {
        let dir = TempDir::new().unwrap();
        let store = BlobStore::new(dir.path().to_path_buf()).unwrap();
        let data = b"dedup test";
        let (sha1, path1, _) = store.put(data).await.unwrap();
        let (sha2, path2, _) = store.put(data).await.unwrap();
        assert_eq!(sha1, sha2);
        assert_eq!(path1, path2);
    }
}
