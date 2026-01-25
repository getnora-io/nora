use async_trait::async_trait;
use axum::body::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncReadExt;

use super::{FileMeta, Result, StorageBackend, StorageError};

/// Local filesystem storage backend (zero-config default)
pub struct LocalStorage {
    base_path: PathBuf,
}

impl LocalStorage {
    pub fn new(path: &str) -> Self {
        Self {
            base_path: PathBuf::from(path),
        }
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        self.base_path.join(key)
    }

    /// Recursively list all files under a directory (sync helper)
    fn list_files_sync(dir: &PathBuf, base: &PathBuf, prefix: &str, results: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(rel_path) = path.strip_prefix(base) {
                        let key = rel_path.to_string_lossy().replace('\\', "/");
                        if key.starts_with(prefix) || prefix.is_empty() {
                            results.push(key);
                        }
                    }
                } else if path.is_dir() {
                    Self::list_files_sync(&path, base, prefix, results);
                }
            }
        }
    }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.key_to_path(key);

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }

        // Write file
        fs::write(&path, data)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Err(StorageError::NotFound);
        }

        let mut file = fs::File::open(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(e.to_string())
            }
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(Bytes::from(buffer))
    }

    async fn list(&self, prefix: &str) -> Vec<String> {
        let base = self.base_path.clone();
        let prefix = prefix.to_string();

        // Use blocking task for filesystem traversal
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            if base.exists() {
                Self::list_files_sync(&base, &base, &prefix, &mut results);
            }
            results.sort();
            results
        })
        .await
        .unwrap_or_default()
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let path = self.key_to_path(key);
        let metadata = fs::metadata(&path).await.ok()?;
        let modified = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(FileMeta {
            size: metadata.len(),
            modified,
        })
    }

    async fn health_check(&self) -> bool {
        // For local storage, just check if base directory exists or can be created
        if self.base_path.exists() {
            return true;
        }
        fs::create_dir_all(&self.base_path).await.is_ok()
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }
}
