// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use axum::body::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::{FileMeta, Result, StorageBackend, StorageError};

type HmacSha256 = Hmac<Sha256>;

/// S3-compatible storage backend (MinIO, AWS S3)
pub struct S3Storage {
    s3_url: String,
    bucket: String,
    region: String,
    access_key: Option<String>,
    secret_key: Option<String>,
    client: reqwest::Client,
}

impl S3Storage {
    /// Create new S3 storage with optional credentials
    pub fn new(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Self {
        Self {
            s3_url: s3_url.trim_end_matches('/').to_string(),
            bucket: bucket.to_string(),
            region: region.to_string(),
            access_key: access_key.map(String::from),
            secret_key: secret_key.map(String::from),
            client: reqwest::Client::new(),
        }
    }

    /// Sign a request using AWS Signature v4
    fn sign_request(
        &self,
        method: &str,
        path: &str,
        payload_hash: &str,
        timestamp: &str,
        date: &str,
    ) -> Option<String> {
        let (access_key, secret_key) = match (&self.access_key, &self.secret_key) {
            (Some(ak), Some(sk)) => (ak.as_str(), sk.as_str()),
            _ => return None,
        };

        // Parse host from URL
        let host = self
            .s3_url
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        // Canonical request
        // URI must be URL-encoded (except /)
        let encoded_path = uri_encode(path);
        let canonical_uri = format!("/{}/{}", self.bucket, encoded_path);
        let canonical_query = "";
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, timestamp
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        // AWS Signature v4 canonical request format:
        // HTTPMethod\nCanonicalURI\nCanonicalQueryString\nCanonicalHeaders\n\nSignedHeaders\nHashedPayload
        // Note: CanonicalHeaders already ends with \n, plus blank line before SignedHeaders
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

        // String to sign
        let credential_scope = format!("{}/{}/s3/aws4_request", date, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, canonical_request_hash
        );

        // Calculate signature
        let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        // Authorization header
        Some(format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            access_key, credential_scope, signed_headers, signature
        ))
    }

    /// Make a signed request
    async fn signed_request(
        &self,
        method: reqwest::Method,
        key: &str,
        body: Option<&[u8]>,
    ) -> std::result::Result<reqwest::Response, StorageError> {
        let url = format!("{}/{}/{}", self.s3_url, self.bucket, key);
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();

        let payload_hash = match body {
            Some(data) => hex::encode(Sha256::digest(data)),
            None => hex::encode(Sha256::digest(b"")),
        };

        let mut request = self
            .client
            .request(method.clone(), &url)
            .header("x-amz-date", &timestamp)
            .header("x-amz-content-sha256", &payload_hash);

        if let Some(auth) =
            self.sign_request(method.as_str(), key, &payload_hash, &timestamp, &date)
        {
            request = request.header("Authorization", auth);
        }

        if let Some(data) = body {
            request = request.body(data.to_vec());
        }

        request
            .send()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))
    }

    fn parse_s3_keys(xml: &str, prefix: &str) -> Vec<String> {
        xml.split("<Key>")
            .filter_map(|part| part.split("</Key>").next())
            .filter(|key| key.starts_with(prefix))
            .map(String::from)
            .collect()
    }
}

/// URL-encode a string for S3 canonical URI (encode all except A-Za-z0-9-_.~/)
fn uri_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '/' => result.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let response = self
            .signed_request(reqwest::Method::PUT, key, Some(data))
            .await?;

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
        let response = self.signed_request(reqwest::Method::GET, key, None).await?;

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

    async fn delete(&self, key: &str) -> Result<()> {
        let response = self
            .signed_request(reqwest::Method::DELETE, key, None)
            .await?;

        if response.status().is_success() || response.status().as_u16() == 204 {
            Ok(())
        } else if response.status().as_u16() == 404 {
            Err(StorageError::NotFound)
        } else {
            Err(StorageError::Network(format!(
                "DELETE failed: {}",
                response.status()
            )))
        }
    }

    async fn list(&self, prefix: &str) -> Vec<String> {
        // For listing, we need to make a request to the bucket
        let url = format!("{}/{}", self.s3_url, self.bucket);
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(b""));

        let host = self
            .s3_url
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        let mut request = self
            .client
            .get(&url)
            .header("x-amz-date", &timestamp)
            .header("x-amz-content-sha256", &payload_hash);

        // Sign for bucket listing (different path)
        if let (Some(access_key), Some(secret_key)) = (&self.access_key, &self.secret_key) {
            let canonical_uri = format!("/{}", self.bucket);
            let canonical_headers = format!(
                "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                host, payload_hash, timestamp
            );
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";

            let canonical_request = format!(
                "GET\n{}\n\n{}\n{}\n{}",
                canonical_uri, canonical_headers, signed_headers, payload_hash
            );

            let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
            let credential_scope = format!("{}/{}/s3/aws4_request", date, self.region);
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{}\n{}\n{}",
                timestamp, credential_scope, canonical_request_hash
            );

            let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date.as_bytes());
            let k_region = hmac_sha256(&k_date, self.region.as_bytes());
            let k_service = hmac_sha256(&k_region, b"s3");
            let k_signing = hmac_sha256(&k_service, b"aws4_request");
            let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

            let auth = format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                access_key, credential_scope, signed_headers, signature
            );
            request = request.header("Authorization", auth);
        }

        match request.send().await {
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
        let response = self
            .signed_request(reqwest::Method::HEAD, key, None)
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let size = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

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
        // Try HEAD on the bucket
        let url = format!("{}/{}", self.s3_url, self.bucket);
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(b""));

        let host = self
            .s3_url
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        let mut request = self
            .client
            .head(&url)
            .header("x-amz-date", &timestamp)
            .header("x-amz-content-sha256", &payload_hash);

        if let (Some(access_key), Some(secret_key)) = (&self.access_key, &self.secret_key) {
            let canonical_uri = format!("/{}", self.bucket);
            let canonical_headers = format!(
                "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                host, payload_hash, timestamp
            );
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";

            let canonical_request = format!(
                "HEAD\n{}\n\n{}\n{}\n{}",
                canonical_uri, canonical_headers, signed_headers, payload_hash
            );

            let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
            let credential_scope = format!("{}/{}/s3/aws4_request", date, self.region);
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{}\n{}\n{}",
                timestamp, credential_scope, canonical_request_hash
            );

            let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date.as_bytes());
            let k_region = hmac_sha256(&k_date, self.region.as_bytes());
            let k_service = hmac_sha256(&k_region, b"s3");
            let k_signing = hmac_sha256(&k_service, b"aws4_request");
            let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

            let auth = format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                access_key, credential_scope, signed_headers, signature
            );
            request = request.header("Authorization", auth);
        }

        match request.send().await {
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
    fn test_parse_s3_keys() {
        let xml = r#"<Key>docker/a</Key><Key>docker/b</Key><Key>maven/c</Key>"#;
        let keys = S3Storage::parse_s3_keys(xml, "docker/");
        assert_eq!(keys, vec!["docker/a", "docker/b"]);
    }

    #[test]
    fn test_hmac_sha256() {
        let result = hmac_sha256(b"key", b"data");
        assert!(!result.is_empty());
    }
}
