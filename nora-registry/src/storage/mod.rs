// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod local;
mod s3;

pub use local::LocalStorage;
pub use s3::S3Storage;

use crate::validation::{validate_storage_key, ValidationError};
use async_trait::async_trait;
use axum::body::Bytes;
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
    fn backend_name(&self) -> &'static str;
}

/// Storage wrapper for dynamic dispatch
#[derive(Clone)]
pub struct Storage {
    inner: Arc<dyn StorageBackend>,
}

impl Storage {
    pub fn new_local(path: &str) -> Self {
        Self {
            inner: Arc::new(LocalStorage::new(path)),
        }
    }

    pub fn new_s3(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Self {
        Self {
            inner: Arc::new(S3Storage::new(
                s3_url, bucket, region, access_key, secret_key,
            )),
        }
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        validate_storage_key(key)?;
        self.inner.put(key, data).await
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        validate_storage_key(key)?;
        self.inner.get(key).await
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        validate_storage_key(key)?;
        self.inner.delete(key).await
    }

    pub async fn list(&self, prefix: &str) -> Vec<String> {
        // Empty prefix is valid for listing all
        if !prefix.is_empty() && validate_storage_key(prefix).is_err() {
            return Vec::new();
        }
        self.inner.list(prefix).await
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

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }
}
