// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

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

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);

        fs::remove_file(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(e.to_string())
            }
        })?;

        Ok(())
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

    async fn total_size(&self) -> u64 {
        let base = self.base_path.clone();
        tokio::task::spawn_blocking(move || {
            fn dir_size(path: &std::path::Path) -> u64 {
                let mut total = 0u64;
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                        } else if path.is_dir() {
                            total += dir_size(&path);
                        }
                    }
                }
                total
            }
            dir_size(&base)
        })
        .await
        .unwrap_or(0)
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_put_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("test/key", b"test data").await.unwrap();
        let data = storage.get("test/key").await.unwrap();
        assert_eq!(&*data, b"test data");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        let result = storage.get("nonexistent").await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn test_list_with_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("docker/image/blob1", b"data1").await.unwrap();
        storage.put("docker/image/blob2", b"data2").await.unwrap();
        storage.put("maven/artifact", b"data3").await.unwrap();

        let docker_keys = storage.list("docker/").await;
        assert_eq!(docker_keys.len(), 2);
        assert!(docker_keys.iter().all(|k| k.starts_with("docker/")));

        let all_keys = storage.list("").await;
        assert_eq!(all_keys.len(), 3);
    }

    #[tokio::test]
    async fn test_stat() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("test", b"12345").await.unwrap();
        let meta = storage.stat("test").await.unwrap();
        assert_eq!(meta.size, 5);
        assert!(meta.modified > 0);
    }

    #[tokio::test]
    async fn test_stat_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        let meta = storage.stat("nonexistent").await;
        assert!(meta.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert!(storage.health_check().await);
    }

    #[tokio::test]
    async fn test_health_check_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let new_path = temp_dir.path().join("new_storage");
        let storage = LocalStorage::new(new_path.to_str().unwrap());

        assert!(!new_path.exists());
        assert!(storage.health_check().await);
        assert!(new_path.exists());
    }

    #[tokio::test]
    async fn test_nested_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("a/b/c/d/e/file", b"deep").await.unwrap();
        let data = storage.get("a/b/c/d/e/file").await.unwrap();
        assert_eq!(&*data, b"deep");
    }

    #[tokio::test]
    async fn test_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("key", b"original").await.unwrap();
        storage.put("key", b"updated").await.unwrap();

        let data = storage.get("key").await.unwrap();
        assert_eq!(&*data, b"updated");
    }

    #[test]
    fn test_backend_name() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert_eq!(storage.backend_name(), "local");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_writes_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        let mut handles = Vec::new();
        for i in 0..10u8 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let data = vec![i; 1024];
                s.put("shared/key", &data).await
            }));
        }

        for h in handles {
            h.await.expect("task panicked").expect("put failed");
        }

        let data = storage.get("shared/key").await.expect("get failed");
        assert_eq!(data.len(), 1024);
        let first = data[0];
        assert!(
            data.iter().all(|&b| b == first),
            "file is corrupted — mixed writers"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_writes_different_keys() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        let mut handles = Vec::new();
        for i in 0..10u32 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("key/{}", i);
                s.put(&key, format!("data-{}", i).as_bytes()).await
            }));
        }

        for h in handles {
            h.await.expect("task panicked").expect("put failed");
        }

        for i in 0..10u32 {
            let key = format!("key/{}", i);
            let data = storage.get(&key).await.expect("get failed");
            assert_eq!(&*data, format!("data-{}", i).as_bytes());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_read_during_write() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        let old_data = vec![0u8; 4096];
        storage.put("rw/key", &old_data).await.expect("seed put");

        let new_data = vec![1u8; 4096];
        let sw = storage.clone();
        let writer = tokio::spawn(async move {
            sw.put("rw/key", &new_data).await.expect("put failed");
        });

        let sr = storage.clone();
        let reader = tokio::spawn(async move {
            match sr.get("rw/key").await {
                Ok(_data) => {
                    // tokio::fs::write is not atomic, so partial reads
                    // (mix of old and new bytes) are expected — not a bug.
                    // We only verify the final state after both tasks complete.
                }
                Err(crate::storage::StorageError::NotFound) => {}
                Err(e) => panic!("unexpected error: {}", e),
            }
        });

        writer.await.expect("writer panicked");
        reader.await.expect("reader panicked");

        let data = storage.get("rw/key").await.expect("final get");
        assert_eq!(&*data, &vec![1u8; 4096]);
    }

    #[tokio::test]
    async fn test_total_size_empty() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert_eq!(storage.total_size().await, 0);
    }

    #[tokio::test]
    async fn test_total_size_with_files() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("a/file1", b"hello").await.unwrap(); // 5 bytes
        storage.put("b/file2", b"world!").await.unwrap(); // 6 bytes

        let size = storage.total_size().await;
        assert_eq!(size, 11);
    }

    #[tokio::test]
    async fn test_total_size_after_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        storage.put("file1", b"12345").await.unwrap();
        storage.put("file2", b"67890").await.unwrap();
        assert_eq!(storage.total_size().await, 10);

        storage.delete("file1").await.unwrap();
        assert_eq!(storage.total_size().await, 5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_deletes_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        storage.put("del/key", b"ephemeral").await.expect("put");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let _ = s.delete("del/key").await;
            }));
        }

        for h in handles {
            h.await.expect("task panicked");
        }

        assert!(matches!(
            storage.get("del/key").await,
            Err(crate::storage::StorageError::NotFound)
        ));
    }
}
