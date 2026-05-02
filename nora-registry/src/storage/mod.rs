// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

mod local;
mod s3;

pub use local::LocalStorage;
pub use s3::S3Storage;

use crate::hash_pin_store::HashPinStore;
use crate::validation::{validate_storage_key, ValidationError};
use async_trait::async_trait;
use axum::body::Bytes;
use std::path::PathBuf;
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
        self.inner.put(key, data).await?;
        if let Some(ref pins) = self.pin_store {
            pins.record(key, data);
        }
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        validate_storage_key(key)?;
        let data = self.inner.get(key).await?;
        if let Some(ref pins) = self.pin_store {
            pins.verify(key, &data);
        }
        Ok(data)
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        validate_storage_key(key)?;
        self.inner.delete(key).await?;
        if let Some(ref pins) = self.pin_store {
            pins.remove(key);
        }
        Ok(())
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

    /// Number of pinned hashes (0 if pin store is disabled).
    pub fn pinned_count(&self) -> usize {
        self.pin_store.as_ref().map_or(0, |p| p.len())
    }

    /// Refresh cached total_size. No-op for local storage, computes for S3.
    pub async fn refresh_total_size_cache(&self) {
        self.inner.refresh_total_size().await;
    }
}
