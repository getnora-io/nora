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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_put_success() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("PUT"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = storage.put("test-key", b"data").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_put_failure() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("PUT"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let result = storage.put("test-key", b"data").await;
        assert!(matches!(result, Err(StorageError::Network(_))));
    }

    #[tokio::test]
    async fn test_get_success() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("GET"))
            .and(path("/test-bucket/test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"test data".to_vec()))
            .mount(&mock_server)
            .await;

        let data = storage.get("test-key").await.unwrap();
        assert_eq!(&*data, b"test data");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("GET"))
            .and(path("/test-bucket/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let result = storage.get("missing").await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn test_list() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        let xml_response = r#"<?xml version="1.0"?>
            <ListBucketResult>
                <Key>docker/image1</Key>
                <Key>docker/image2</Key>
                <Key>maven/artifact</Key>
            </ListBucketResult>"#;

        Mock::given(method("GET"))
            .and(path("/test-bucket"))
            .respond_with(ResponseTemplate::new(200).set_body_string(xml_response))
            .mount(&mock_server)
            .await;

        let keys = storage.list("docker/").await;
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.starts_with("docker/")));
    }

    #[tokio::test]
    async fn test_stat_success() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("HEAD"))
            .and(path("/test-bucket/test-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-length", "1234")
                    .insert_header("last-modified", "Sun, 06 Nov 1994 08:49:37 GMT"),
            )
            .mount(&mock_server)
            .await;

        let meta = storage.stat("test-key").await.unwrap();
        assert_eq!(meta.size, 1234);
        assert!(meta.modified > 0);
    }

    #[tokio::test]
    async fn test_stat_not_found() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("HEAD"))
            .and(path("/test-bucket/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let meta = storage.stat("missing").await;
        assert!(meta.is_none());
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("HEAD"))
            .and(path("/test-bucket"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        assert!(storage.health_check().await);
    }

    #[tokio::test]
    async fn test_health_check_bucket_not_found_is_ok() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("HEAD"))
            .and(path("/test-bucket"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        // 404 is OK for health check (bucket may be empty)
        assert!(storage.health_check().await);
    }

    #[tokio::test]
    async fn test_health_check_server_error() {
        let mock_server = MockServer::start().await;
        let storage = S3Storage::new(&mock_server.uri(), "test-bucket");

        Mock::given(method("HEAD"))
            .and(path("/test-bucket"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        assert!(!storage.health_check().await);
    }

    #[test]
    fn test_backend_name() {
        let storage = S3Storage::new("http://localhost:9000", "bucket");
        assert_eq!(storage.backend_name(), "s3");
    }

    #[test]
    fn test_parse_s3_keys() {
        let xml = r#"<Key>docker/a</Key><Key>docker/b</Key><Key>maven/c</Key>"#;
        let keys = S3Storage::parse_s3_keys(xml, "docker/");
        assert_eq!(keys, vec!["docker/a", "docker/b"]);
    }
}
