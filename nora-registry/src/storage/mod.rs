mod local;
mod s3;

pub use local::LocalStorage;
pub use s3::S3Storage;

use async_trait::async_trait;
use axum::body::Bytes;
use std::fmt;
use std::sync::Arc;

/// File metadata
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub size: u64,
    pub modified: u64, // Unix timestamp
}

#[derive(Debug)]
pub enum StorageError {
    Network(String),
    NotFound,
    Io(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Network error: {}", msg),
            Self::NotFound => write!(f, "Object not found"),
            Self::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Bytes>;
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

    pub fn new_s3(s3_url: &str, bucket: &str) -> Self {
        Self {
            inner: Arc::new(S3Storage::new(s3_url, bucket)),
        }
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        self.inner.put(key, data).await
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        self.inner.get(key).await
    }

    pub async fn list(&self, prefix: &str) -> Vec<String> {
        self.inner.list(prefix).await
    }

    pub async fn stat(&self, key: &str) -> Option<FileMeta> {
        self.inner.stat(key).await
    }

    pub async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }
}
