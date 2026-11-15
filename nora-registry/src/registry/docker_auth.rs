// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::config::basic_auth_header;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached Docker registry token
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Why a 401 challenge got no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// The upstream will not let NORA in with what it has (#1196): its challenge is not one
    /// that a token answers (`Basic`, another scheme, none at all), or its token server refused
    /// the credentials with 401 or 403. A configuration fault, not an outage.
    Refused,
    /// The token server could not be reached, or its challenge or answer was unusable.
    Unavailable,
}

/// Docker registry authentication handler
/// Manages Bearer token acquisition and caching for upstream registries
#[derive(Clone)]
pub struct DockerAuth {
    /// Shared by every clone, so a spool resuming a blob reuses the token that opened it.
    tokens: Arc<RwLock<HashMap<String, CachedToken>>>,
    client: reqwest::Client,
    timeout: Duration,
}

impl DockerAuth {
    /// Create a new DockerAuth using the provided HTTP client.
    ///
    /// The client should be pre-configured with any required TLS settings
    /// (e.g. custom CA certificates). The timeout is applied per-request.
    pub fn new(client: reqwest::Client, timeout: u64) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            client,
            timeout: Duration::from_secs(timeout),
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
    ) -> Result<String, TokenError> {
        let cache_key = format!("{}:{}", registry_url, name);

        // Check cache first
        {
            let tokens = self.tokens.read();
            if let Some(cached) = tokens.get(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Need to fetch a new token. A 401 without a challenge names no way in.
        let www_auth = www_authenticate.ok_or(TokenError::Refused)?;
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

        Ok(token)
    }

    /// Parse Www-Authenticate header and fetch token from auth server
    /// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"
    async fn fetch_token(
        &self,
        www_authenticate: &str,
        name: &str,
        basic_auth: Option<&str>,
    ) -> Result<String, TokenError> {
        // Not a Bearer challenge (Harbor answers `Basic realm="harbor"` to a robot account
        // without access): no token can answer it.
        let params = parse_www_authenticate(www_authenticate).ok_or(TokenError::Refused)?;

        let realm = params.get("realm").ok_or(TokenError::Unavailable)?;

        // Validate realm URL scheme — only HTTP(S) allowed
        if !realm.starts_with("https://") && !realm.starts_with("http://") {
            tracing::warn!(realm = %realm, "Rejecting auth realm with non-HTTP(S) scheme");
            return Err(TokenError::Unavailable);
        }

        let service = params.get("service").map(|s| s.as_str()).unwrap_or("");

        // Build token request URL
        let scope = format!("repository:{}:pull", name);
        let url = format!("{}?service={}&scope={}", realm, service, scope);

        tracing::debug!(url = %url, "Fetching auth token");

        let mut request = self.client.get(&url).timeout(self.timeout);
        if let Some(credentials) = basic_auth {
            request = request.header("Authorization", basic_auth_header(credentials));
            tracing::debug!("Using basic auth for token request");
        }

        let response = request.send().await.map_err(|_| TokenError::Unavailable)?;

        let status = response.status();
        if !status.is_success() {
            tracing::warn!(status = %status, "Token request failed");
            // Docker Hub answers wrong credentials with 401 "incorrect username or password".
            return Err(match status {
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                    TokenError::Refused
                }
                _ => TokenError::Unavailable,
            });
        }

        let json: serde_json::Value = response.json().await.map_err(|_| TokenError::Unavailable)?;

        // Docker Hub returns "token", some registries return "access_token"
        json.get("token")
            .or_else(|| json.get("access_token"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or(TokenError::Unavailable)
    }
}

impl Default for DockerAuth {
    fn default() -> Self {
        Self::new(reqwest::Client::new(), 60)
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
        let auth = DockerAuth::new(reqwest::Client::new(), 30);
        assert!(auth.tokens.read().is_empty());
    }

    #[tokio::test]
    async fn test_get_token_no_www_authenticate() {
        let auth = DockerAuth::default();
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Err(TokenError::Refused));
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
        assert_eq!(result, Ok("cached-token-123".to_string()));
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
        // Without www_authenticate, no new token can be fetched
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Err(TokenError::Refused));
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
        let auth = DockerAuth::new(reqwest::Client::new(), 1);
        let result = auth
            .get_token(
                "https://registry.example.com",
                "library/test",
                Some(r#"Bearer realm="http://127.0.0.1:1/token",service="test""#),
                None,
            )
            .await;
        assert_eq!(result, Err(TokenError::Unavailable));
    }

    /// #1196: how a challenge that yields no token is told apart. A refusal is the upstream
    /// keeping NORA out (a challenge no token answers, the token server's 401 or 403); anything
    /// else that yields no token is the token server failing.
    #[tokio::test]
    async fn a_refused_token_is_told_from_an_unavailable_one() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (challenge, token_answer, want) in [
            ("Basic realm=\"harbor\"", None, Err(TokenError::Refused)),
            ("Negotiate", None, Err(TokenError::Refused)),
            ("", None, Err(TokenError::Refused)),
            (
                "Bearer",
                Some(ResponseTemplate::new(401)),
                Err(TokenError::Refused),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(403)),
                Err(TokenError::Refused),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(500)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(429)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(404)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_string("not json")),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_json(serde_json::json!({}))),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "t"}))),
                Ok("t".to_string()),
            ),
            (
                "Bearer",
                Some(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"access_token": "a"})),
                ),
                Ok("a".to_string()),
            ),
        ] {
            let server = MockServer::start().await;
            let challenge = if challenge == "Bearer" {
                format!("Bearer realm=\"{}/token\",service=\"s\"", server.uri())
            } else {
                challenge.to_string()
            };
            let asked_token_server = token_answer.is_some();
            if let Some(answer) = token_answer {
                Mock::given(wiremock::matchers::any())
                    .respond_with(answer)
                    .mount(&server)
                    .await;
            }
            let auth = DockerAuth::new(reqwest::Client::new(), 5);
            let got = auth
                .get_token(
                    "https://registry.example.com",
                    "project1/service1",
                    Some(&challenge),
                    Some("robot:secret"),
                )
                .await;
            assert_eq!(got, want, "{challenge:?}");
            assert_eq!(
                !server.received_requests().await.unwrap().is_empty(),
                asked_token_server,
                "{challenge:?}: token server asked"
            );
        }
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
        assert_eq!(result, Err(TokenError::Unavailable));
    }
}
