// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

mod local;
mod s3;

pub use local::LocalStorage;
pub use s3::S3Storage;

use crate::hash_pin_store::HashPinStore;
use crate::metrics::STORAGE_OPERATIONS;
use crate::validation::{validate_storage_key, ValidationError};
use async_trait::async_trait;
use axum::body::Bytes;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncRead;

/// File metadata
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub size: u64,
    pub modified: u64, // Unix timestamp
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Object not found")]
    NotFound,

    #[error("IO error: {0}")]
    Io(String),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Stored artifact failed hash-pin verification — tampering or on-disk
    /// corruption detected. Fail-closed: the tampered bytes are never served
    /// (handlers map this to 5xx). See #582.
    #[error("Integrity violation: artifact failed hash-pin verification")]
    IntegrityViolation,
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Bytes>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn stat(&self, key: &str) -> Option<FileMeta>;
    async fn health_check(&self) -> bool;
    /// Total size of all stored artifacts in bytes
    async fn total_size(&self) -> u64;
    fn backend_name(&self) -> &'static str;
    /// Refresh any cached size data. No-op for backends without caching.
    async fn refresh_total_size(&self) {}
    /// Move or copy a file from `src` into storage under `key`.
    ///
    /// Local backend: atomic `rename`, with streaming copy fallback on EXDEV.
    /// S3 backend: multipart upload from file.
    /// The caller is responsible for deleting `src` on error.
    async fn put_from_path(&self, key: &str, src: &Path) -> Result<()>;

    /// Open an artifact for streaming read without loading it into memory (#580).
    ///
    /// Returns `(size_bytes, reader)`. The caller converts the reader to a
    /// streaming HTTP response via `ReaderStream` + `Body::from_stream()`.
    ///
    /// Local backend: `tokio::fs::File::open` + metadata.
    /// S3 backend: `object_store::get` → byte-stream wrapped in `StreamReader`.
    async fn get_reader(&self, key: &str) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)>;
}

/// Storage wrapper for dynamic dispatch with integrity verification.
#[derive(Clone)]
pub struct Storage {
    inner: Arc<dyn StorageBackend>,
    pin_store: Option<Arc<HashPinStore>>,
}

impl Storage {
    pub fn new_local(path: &str) -> Self {
        let pin_path = PathBuf::from(path).join(".nora-pins.ndjson");
        Self {
            inner: Arc::new(LocalStorage::new(path)),
            pin_store: Some(Arc::new(HashPinStore::new(pin_path))),
        }
    }

    pub fn new_s3(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Self {
        tracing::warn!(
            "Hash pin store disabled for S3 backend — integrity verification unavailable"
        );
        Self {
            inner: Arc::new(S3Storage::new(
                s3_url, bucket, region, access_key, secret_key,
            )),
            pin_store: None,
        }
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.put(key, data).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key = key.to_string();
                    let data = data.to_vec();
                    // SHA-256 + sync file append — offload from tokio worker
                    tokio::task::spawn_blocking(move || pins.record(&key, &data));
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["put", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        validate_storage_key(key)?;
        match self.inner.get(key).await {
            Ok(data) => {
                STORAGE_OPERATIONS.with_label_values(&["get", "ok"]).inc();
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key_owned = key.to_string();
                    let data_ref = data.clone();
                    // SHA-256 verification — offloaded from the tokio worker.
                    // A buffered `get()` may hold a large artifact in memory;
                    // hashing it inline would stall the async worker for the
                    // hash duration, so we keep the blocking pool. The panic
                    // path is handled fail-closed below — see #582.
                    match tokio::task::spawn_blocking(move || pins.verify(&key_owned, &data_ref))
                        .await
                    {
                        // Genuine hash mismatch — tampering or on-disk corruption.
                        // Fail-closed: never serve the tampered bytes (#582).
                        Ok(false) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["get", "integrity_fail"])
                                .inc();
                            tracing::error!(
                                key = %key,
                                "integrity violation: refusing to serve tampered artifact"
                            );
                            return Err(StorageError::IntegrityViolation);
                        }
                        // Verification task itself panicked. We cannot prove the
                        // bytes are intact, so fail-closed too — a crashed
                        // verifier must not become an integrity bypass (#582).
                        Err(e) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["get", "verify_error"])
                                .inc();
                            tracing::error!(
                                error = %e,
                                key = %key,
                                "hash verification task failed: refusing to serve unverified artifact"
                            );
                            return Err(StorageError::IntegrityViolation);
                        }
                        // Hash matched, or no pin exists for this key (open-world).
                        Ok(true) => {}
                    }
                }
                Ok(data)
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.delete(key).await {
            Ok(()) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["delete", "ok"])
                    .inc();
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key = key.to_string();
                    // Sync file append — offload from tokio worker
                    tokio::task::spawn_blocking(move || pins.remove(&key));
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["delete", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // Empty prefix is valid for listing all
        if !prefix.is_empty() {
            validate_storage_key(prefix)?;
        }
        let keys = self.inner.list(prefix).await?;
        Ok(keys
            .into_iter()
            .filter(|k| !k.starts_with(".nora-"))
            .collect())
    }

    pub async fn stat(&self, key: &str) -> Option<FileMeta> {
        if validate_storage_key(key).is_err() {
            return None;
        }
        self.inner.stat(key).await
    }

    pub async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    pub async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }

    /// Look up the pinned SHA-256 hash for a storage key (None if pin store is disabled or key is unknown).
    pub fn get_pin_hash(&self, key: &str) -> Option<String> {
        self.pin_store.as_ref().and_then(|p| p.get(key))
    }

    /// Number of pinned hashes (0 if pin store is disabled).
    pub fn pinned_count(&self) -> usize {
        self.pin_store.as_ref().map_or(0, |p| p.len())
    }

    /// Refresh cached total_size. No-op for local storage, computes for S3.
    pub async fn refresh_total_size_cache(&self) {
        self.inner.refresh_total_size().await;
    }

    /// Move or copy a file from `src` into storage under `key`.
    ///
    /// When `sha256` is `Some`, the hash is recorded in the pin store without
    /// re-reading the file — used by streaming download paths where the hash
    /// was already computed incrementally (#580).
    ///
    /// When `sha256` is `None`, the pin store is not updated (legacy behavior
    /// for callers that have already verified integrity separately).
    pub async fn put_from_path(&self, key: &str, src: &Path, sha256: Option<&str>) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.put_from_path(key, src).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
                if let (Some(hash), Some(ref pins)) = (sha256, &self.pin_store) {
                    let pins = Arc::clone(pins);
                    let key = key.to_string();
                    let hash = hash.to_string();
                    tokio::task::spawn_blocking(move || pins.record_hash(&key, &hash));
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["put", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    /// Open an artifact for streaming read without loading into memory (#580).
    ///
    /// Returns `(size_bytes, reader)`. Pin-store integrity is NOT checked here
    /// because streaming prevents full-data hashing. Callers that need integrity
    /// verification should use `verify_integrity_by_hash` with the content digest
    /// (available from the URL for Docker blobs).
    pub async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        validate_storage_key(key)?;
        match self.inner.get_reader(key).await {
            Ok(reader) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_reader", "ok"])
                    .inc();
                Ok(reader)
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_reader", "error"])
                    .inc();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Wait until the fire-and-forget pin record from `put()` has landed.
    async fn await_pin(storage: &Storage, key: &str) {
        for _ in 0..200 {
            if storage.get_pin_hash(key).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("pin for {key} was never recorded");
    }

    /// Regression for #582: a pinned artifact corrupted on disk must NOT be
    /// served. Exercises the real call path `Storage::get()` — not `verify()`
    /// in isolation (PM-4). The bug was that `get()` computed the verification
    /// result and then returned `Ok(data)` regardless.
    #[tokio::test]
    async fn get_fails_closed_on_integrity_mismatch() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        let key = "raw/example/app.bin";
        storage.put(key, b"genuine-bytes").await.unwrap();
        await_pin(&storage, key).await;

        // Sanity: an untampered read returns the bytes.
        assert_eq!(&storage.get(key).await.unwrap()[..], b"genuine-bytes");

        // Tamper with the artifact directly on disk, bypassing NORA — exactly
        // the threat the pin store exists to catch.
        let before = STORAGE_OPERATIONS
            .with_label_values(&["get", "integrity_fail"])
            .get();
        std::fs::write(dir.path().join(key), b"TAMPERED").unwrap();

        // get() must refuse to serve the tampered bytes.
        let result = storage.get(key).await;
        assert!(
            matches!(result, Err(StorageError::IntegrityViolation)),
            "expected IntegrityViolation, got {result:?}"
        );

        // ...and the failure must be recorded (acceptance criterion).
        let after = STORAGE_OPERATIONS
            .with_label_values(&["get", "integrity_fail"])
            .get();
        assert!(after > before, "integrity_fail metric must increment");
    }

    /// The fix must not break legitimate reads: a matching hash still returns
    /// the bytes, and an unpinned key (open-world) passes through.
    #[tokio::test]
    async fn get_succeeds_for_matching_and_unpinned() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Pinned + matching → served.
        let key = "raw/ok/file.bin";
        storage.put(key, b"hello").await.unwrap();
        await_pin(&storage, key).await;
        assert_eq!(&storage.get(key).await.unwrap()[..], b"hello");

        // Unpinned key (written straight to disk, no pin) → open-world pass.
        let unpinned = "raw/ok/unpinned.bin";
        std::fs::write(dir.path().join(unpinned), b"no-pin").unwrap();
        assert_eq!(&storage.get(unpinned).await.unwrap()[..], b"no-pin");
    }
}
