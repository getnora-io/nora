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
        let token = self.fetch_token(www_auth, name).await?;

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
    async fn fetch_token(&self, www_authenticate: &str, name: &str) -> Option<String> {
        let params = parse_www_authenticate(www_authenticate)?;

        let realm = params.get("realm")?;
        let service = params.get("service").map(|s| s.as_str()).unwrap_or("");

        // Build token request URL
        let scope = format!("repository:{}:pull", name);
        let url = format!("{}?service={}&scope={}", realm, service, scope);

        tracing::debug!(url = %url, "Fetching auth token");

        let response = self.client.get(&url).send().await.ok()?;

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

    /// Make an authenticated request to an upstream registry
    pub async fn fetch_with_auth(
        &self,
        url: &str,
        registry_url: &str,
        name: &str,
    ) -> Result<reqwest::Response, ()> {
        // First try without auth
        let response = self.client.get(url).send().await.map_err(|_| ())?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Extract Www-Authenticate header
            let www_auth = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            // Get token and retry
            if let Some(token) = self
                .get_token(registry_url, name, www_auth.as_deref())
                .await
            {
                return self
                    .client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
                    .map_err(|_| ());
            }

            return Err(());
        }

        Ok(response)
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
}
