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
use std::sync::Arc;
use thiserror::Error;

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
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Bytes>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Vec<String>;
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
                    pins.record(key, data);
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
                    if !pins.verify(key, &data) {
                        STORAGE_OPERATIONS
                            .with_label_values(&["get", "integrity_fail"])
                            .inc();
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
                    pins.remove(key);
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

    pub async fn list(&self, prefix: &str) -> Vec<String> {
        // Empty prefix is valid for listing all
        if !prefix.is_empty() && validate_storage_key(prefix).is_err() {
            return Vec::new();
        }
        self.inner
            .list(prefix)
            .await
            .into_iter()
            .filter(|k| !k.starts_with(".nora-"))
            .collect()
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
    /// Digest is assumed already verified by the caller — pin store is
    /// not updated (re-reading gigabytes just to hash is wasteful).
    pub async fn put_from_path(&self, key: &str, src: &Path) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.put_from_path(key, src).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
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
}
