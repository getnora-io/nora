use async_trait::async_trait;
use axum::body::Bytes;

use super::{FileMeta, Result, StorageBackend, StorageError};

/// S3-compatible storage backend (MinIO, AWS S3)
pub struct S3Storage {
    s3_url: String,
    bucket: String,
    client: reqwest::Client,
}

impl S3Storage {
    pub fn new(s3_url: &str, bucket: &str) -> Self {
        Self {
            s3_url: s3_url.to_string(),
            bucket: bucket.to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn parse_s3_keys(xml: &str, prefix: &str) -> Vec<String> {
        xml.split("<Key>")
            .filter_map(|part| part.split("</Key>").next())
            .filter(|key| key.starts_with(prefix))
            .map(String::from)
            .collect()
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let url = format!("{}/{}/{}", self.s3_url, self.bucket, key);
        let response = self
            .client
            .put(&url)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(StorageError::Network(format!(
                "PUT failed: {}",
                response.status()
            )))
        }
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let url = format!("{}/{}/{}", self.s3_url, self.bucket, key);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        if response.status().is_success() {
            response
                .bytes()
                .await
                .map_err(|e| StorageError::Network(e.to_string()))
        } else if response.status().as_u16() == 404 {
            Err(StorageError::NotFound)
        } else {
            Err(StorageError::Network(format!(
                "GET failed: {}",
                response.status()
            )))
        }
    }

    async fn list(&self, prefix: &str) -> Vec<String> {
        let url = format!("{}/{}", self.s3_url, self.bucket);
        match self.client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(xml) = response.text().await {
                    Self::parse_s3_keys(&xml, prefix)
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let url = format!("{}/{}/{}", self.s3_url, self.bucket, key);
        let response = self.client.head(&url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let size = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // S3 uses Last-Modified header, but for simplicity use current time if unavailable
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0);
        Some(FileMeta { size, modified })
    }

    async fn health_check(&self) -> bool {
        let url = format!("{}/{}", self.s3_url, self.bucket);
        match self.client.head(&url).send().await {
            Ok(response) => response.status().is_success() || response.status().as_u16() == 404,
            Err(_) => false,
        }
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }
}
