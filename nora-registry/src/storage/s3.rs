// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use axum::body::Bytes;
use futures::TryStreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};

use super::{FileMeta, Result, StorageBackend, StorageError};

/// S3-compatible storage backend using the `object_store` crate.
pub struct S3Storage {
    store: AmazonS3,
    /// Cached total size in bytes, refreshed by background task.
    cached_total_size: std::sync::atomic::AtomicU64,
    /// Whether cached_total_size has been initialized at least once.
    size_cache_initialized: std::sync::atomic::AtomicBool,
}

impl S3Storage {
    /// Create new S3 storage with optional credentials.
    pub fn new(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Self {
        let url = s3_url.trim_end_matches('/');
        let allow_http = url.starts_with("http://");

        let mut builder = AmazonS3Builder::new()
            .with_endpoint(url)
            .with_bucket_name(bucket)
            .with_region(region)
            .with_allow_http(allow_http)
            .with_virtual_hosted_style_request(false);

        match (access_key, secret_key) {
            (Some(ak), Some(sk)) => {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
            _ => {
                builder = builder.with_skip_signature(true);
            }
        }

        let store = builder.build().expect("Failed to build S3 client");

        Self {
            store,
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// Encode `@` in S3 keys to `_at_` for SeaweedFS compatibility.
///
/// SeaweedFS returns 500 on GET/PUT for keys containing `@`
/// (e.g. npm scoped packages like `npm/@babel/core/...`).
fn encode_s3_key(key: &str) -> String {
    key.replace('@', "_at_")
}

/// Decode `_at_` back to `@` in S3 keys.
fn decode_s3_key(key: &str) -> String {
    key.replace("_at_", "@")
}

/// Map object_store errors to StorageError.
fn map_err(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Network(other.to_string()),
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let encoded = encode_s3_key(key);
        let path = Path::from(encoded);
        let payload = PutPayload::from(data.to_vec());
        self.store.put(&path, payload).await.map_err(map_err)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let encoded = encode_s3_key(key);
        let path = Path::from(encoded);
        let result = self.store.get(&path).await.map_err(map_err)?;
        let bytes = result.bytes().await.map_err(map_err)?;
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let encoded = encode_s3_key(key);
        let path = Path::from(encoded);
        self.store.delete(&path).await.map_err(map_err)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Vec<String> {
        let encoded = encode_s3_key(prefix);
        let prefix_path = Path::from(encoded);
        let list_prefix = if prefix.is_empty() {
            None
        } else {
            Some(&prefix_path)
        };

        // Collect all objects from the listing stream.
        let result: std::result::Result<Vec<_>, _> =
            self.store.list(list_prefix).try_collect().await;

        match result {
            Ok(objects) => objects
                .into_iter()
                .map(|meta| decode_s3_key(meta.location.as_ref()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let encoded = encode_s3_key(key);
        let path = Path::from(encoded);
        let meta = self.store.head(&path).await.ok()?;

        let modified = meta.last_modified.timestamp().try_into().unwrap_or(0u64);

        Some(FileMeta {
            size: meta.size,
            modified,
        })
    }

    async fn health_check(&self) -> bool {
        // Try listing with no prefix — if the store responds, it's healthy.
        // Even an empty bucket or a 404 on prefix is fine.
        let result: std::result::Result<Vec<_>, _> = self.store.list(None).try_collect().await;
        result.is_ok()
    }

    async fn total_size(&self) -> u64 {
        self.cached_total_size
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }

    async fn refresh_total_size(&self) {
        let result: std::result::Result<Vec<_>, _> = self.store.list(None).try_collect().await;

        if let Ok(objects) = result {
            let total: u64 = objects.iter().map(|m| m.size).sum();
            self.cached_total_size
                .store(total, std::sync::atomic::Ordering::Relaxed);
            self.size_cache_initialized
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_name() {
        let storage = S3Storage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    #[test]
    fn test_s3_storage_creation_anonymous() {
        let storage = S3Storage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            None,
            None,
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    #[test]
    fn test_s3_total_size_returns_zero_before_init() {
        let storage = S3Storage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
        );
        assert!(!storage
            .size_cache_initialized
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_error_mapping_not_found() {
        let err = object_store::Error::NotFound {
            path: "test/key".to_string(),
            source: "not found".into(),
        };
        match map_err(err) {
            StorageError::NotFound => {}
            other => panic!("Expected NotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_error_mapping_network() {
        let err = object_store::Error::Generic {
            store: "S3",
            source: "connection refused".into(),
        };
        match map_err(err) {
            StorageError::Network(msg) => {
                assert!(msg.contains("connection refused"));
            }
            other => panic!("Expected Network, got: {:?}", other),
        }
    }

    #[test]
    fn test_encode_s3_key() {
        assert_eq!(encode_s3_key("npm/@scope/pkg"), "npm/_at_scope/pkg");
        assert_eq!(
            encode_s3_key("npm/@babel/core/metadata.json"),
            "npm/_at_babel/core/metadata.json"
        );
    }

    #[test]
    fn test_decode_s3_key() {
        assert_eq!(decode_s3_key("npm/_at_scope/pkg"), "npm/@scope/pkg");
        assert_eq!(
            decode_s3_key("npm/_at_babel/core/metadata.json"),
            "npm/@babel/core/metadata.json"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let keys = [
            "npm/@scope/pkg",
            "npm/@babel/core/metadata.json",
            "simple/key/no-at",
            "raw/@org/file.txt",
        ];
        for key in keys {
            assert_eq!(decode_s3_key(&encode_s3_key(key)), key);
        }
    }

    #[test]
    fn test_encode_no_at() {
        let key = "npm/chalk/metadata.json";
        assert_eq!(encode_s3_key(key), key);
    }
}
