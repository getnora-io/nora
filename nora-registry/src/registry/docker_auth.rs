// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::config::basic_auth_header;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cached Docker registry token
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Docker registry authentication handler
/// Manages Bearer token acquisition and caching for upstream registries
pub struct DockerAuth {
    tokens: RwLock<HashMap<String, CachedToken>>,
    client: reqwest::Client,
}

impl DockerAuth {
    pub fn new(timeout: u64) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Get a valid token for the given registry and repository scope
    /// Returns cached token if still valid, otherwise fetches a new one
    pub async fn get_token(
        &self,
        registry_url: &str,
        name: &str,
        www_authenticate: Option<&str>,
        basic_auth: Option<&str>,
    ) -> Option<String> {
        let cache_key = format!("{}:{}", registry_url, name);

        // Check cache first
        {
            let tokens = self.tokens.read();
            if let Some(cached) = tokens.get(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Some(cached.token.clone());
                }
            }
        }

        // Need to fetch a new token
        let www_auth = www_authenticate?;
        let token = self.fetch_token(www_auth, name, basic_auth).await?;

        // Cache the token (default 5 minute expiry)
        {
            let mut tokens = self.tokens.write();
            tokens.insert(
                cache_key,
                CachedToken {
                    token: token.clone(),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );
        }

        Some(token)
    }

    /// Parse Www-Authenticate header and fetch token from auth server
    /// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"
    async fn fetch_token(
        &self,
        www_authenticate: &str,
        name: &str,
        basic_auth: Option<&str>,
    ) -> Option<String> {
        let params = parse_www_authenticate(www_authenticate)?;

        let realm = params.get("realm")?;
        let service = params.get("service").map(|s| s.as_str()).unwrap_or("");

        // Build token request URL
        let scope = format!("repository:{}:pull", name);
        let url = format!("{}?service={}&scope={}", realm, service, scope);

        tracing::debug!(url = %url, "Fetching auth token");

        let mut request = self.client.get(&url);
        if let Some(credentials) = basic_auth {
            request = request.header("Authorization", basic_auth_header(credentials));
            tracing::debug!("Using basic auth for token request");
        }

        let response = request.send().await.ok()?;

        if !response.status().is_success() {
            tracing::warn!(status = %response.status(), "Token request failed");
            return None;
        }

        let json: serde_json::Value = response.json().await.ok()?;

        // Docker Hub returns "token", some registries return "access_token"
        json.get("token")
            .or_else(|| json.get("access_token"))
            .and_then(|v| v.as_str())
            .map(String::from)
    }
}

impl Default for DockerAuth {
    fn default() -> Self {
        Self::new(60)
    }
}

/// Parse Www-Authenticate header into key-value pairs
/// Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
fn parse_www_authenticate(header: &str) -> Option<HashMap<String, String>> {
    let header = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;

    let mut params = HashMap::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            params.insert(key.to_string(), value.to_string());
        }
    }

    Some(params)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_www_authenticate() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let params = parse_www_authenticate(header).unwrap();

        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
        assert_eq!(
            params.get("service"),
            Some(&"registry.docker.io".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_lowercase() {
        let header = r#"bearer realm="https://ghcr.io/token",service="ghcr.io""#;
        let params = parse_www_authenticate(header).unwrap();

        assert_eq!(
            params.get("realm"),
            Some(&"https://ghcr.io/token".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_no_bearer() {
        assert!(parse_www_authenticate("Basic realm=\"test\"").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_empty() {
        assert!(parse_www_authenticate("").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_partial() {
        let header = r#"Bearer realm="https://example.com/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://example.com/token".to_string())
        );
        assert!(!params.contains_key("service"));
    }

    #[test]
    fn test_docker_auth_default() {
        let auth = DockerAuth::default();
        assert!(auth.tokens.read().is_empty());
    }

    #[test]
    fn test_docker_auth_new() {
        let auth = DockerAuth::new(30);
        assert!(auth.tokens.read().is_empty());
    }

    #[tokio::test]
    async fn test_get_token_no_www_authenticate() {
        let auth = DockerAuth::default();
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_token_cache_hit() {
        let auth = DockerAuth::default();
        // Manually insert a cached token
        {
            let mut tokens = auth.tokens.write();
            tokens.insert(
                "https://registry.example.com:library/test".to_string(),
                CachedToken {
                    token: "cached-token-123".to_string(),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );
        }
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Some("cached-token-123".to_string()));
    }

    #[tokio::test]
    async fn test_get_token_cache_expired() {
        let auth = DockerAuth::default();
        {
            let mut tokens = auth.tokens.write();
            tokens.insert(
                "https://registry.example.com:library/test".to_string(),
                CachedToken {
                    token: "expired-token".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        // Without www_authenticate, returns None (can't fetch new token)
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_www_authenticate_bearer_only() {
        let params = parse_www_authenticate("Bearer ").unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_www_authenticate_missing_realm() {
        let header = r#"Bearer service="registry.docker.io""#;
        let params = parse_www_authenticate(header).unwrap();
        assert!(params.get("realm").is_none());
        assert_eq!(
            params.get("service"),
            Some(&"registry.docker.io".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_missing_service() {
        let header = r#"Bearer realm="https://auth.docker.io/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
        assert!(params.get("service").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_malformed_kv() {
        let header = r#"Bearer garbage,realm="https://auth.docker.io/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
    }

    #[tokio::test]
    async fn test_fetch_token_invalid_url() {
        let auth = DockerAuth::new(1);
        let result = auth
            .get_token(
                "https://registry.example.com",
                "library/test",
                Some(r#"Bearer realm="http://127.0.0.1:1/token",service="test""#),
                None,
            )
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_fetch_token_missing_realm_in_header() {
        let auth = DockerAuth::default();
        let result = auth
            .get_token(
                "https://registry.example.com",
                "library/test",
                Some(r#"Bearer service="registry.docker.io""#),
                None,
            )
            .await;
        assert!(result.is_none());
    }
}
