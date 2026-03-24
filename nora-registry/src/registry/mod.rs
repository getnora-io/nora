// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod cargo_registry;
pub mod docker;
pub mod docker_auth;
mod maven;
mod npm;
mod pypi;
mod raw;

pub use cargo_registry::routes as cargo_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;
pub use pypi::routes as pypi_routes;
pub use raw::routes as raw_routes;

use crate::config::basic_auth_header;
use std::time::Duration;

/// Fetch from upstream proxy with timeout and 1 retry.
///
/// On transient errors (timeout, connection reset), retries once after a short delay.
/// Non-retryable errors (4xx) fail immediately.
pub(crate) async fn proxy_fetch(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
    auth: Option<&str>,
) -> Result<Vec<u8>, ProxyError> {
    for attempt in 0..2 {
        let mut request = client.get(url).timeout(Duration::from_secs(timeout_secs));
        if let Some(credentials) = auth {
            request = request.header("Authorization", basic_auth_header(credentials));
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    return response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .map_err(|e| ProxyError::Network(e.to_string()));
                }
                let status = response.status().as_u16();
                // Don't retry client errors (4xx)
                if (400..500).contains(&status) {
                    return Err(ProxyError::NotFound);
                }
                // Server error (5xx) — retry
                if attempt == 0 {
                    tracing::debug!(url, status, "upstream 5xx, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                return Err(ProxyError::Upstream(status));
            }
            Err(e) => {
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    Err(ProxyError::Network("max retries exceeded".into()))
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ProxyError {
    NotFound,
    Upstream(u16),
    Network(String),
}

/// Fetch text content from upstream proxy with timeout and 1 retry.
/// Same as proxy_fetch but returns String (for HTML pages like PyPI simple index).
pub(crate) async fn proxy_fetch_text(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
    auth: Option<&str>,
    extra_headers: Option<(&str, &str)>,
) -> Result<String, ProxyError> {
    for attempt in 0..2 {
        let mut request = client.get(url).timeout(Duration::from_secs(timeout_secs));
        if let Some(credentials) = auth {
            request = request.header("Authorization", basic_auth_header(credentials));
        }
        if let Some((key, val)) = extra_headers {
            request = request.header(key, val);
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    return response
                        .text()
                        .await
                        .map_err(|e| ProxyError::Network(e.to_string()));
                }
                let status = response.status().as_u16();
                if (400..500).contains(&status) {
                    return Err(ProxyError::NotFound);
                }
                if attempt == 0 {
                    tracing::debug!(url, status, "upstream 5xx, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                return Err(ProxyError::Upstream(status));
            }
            Err(e) => {
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    Err(ProxyError::Network("max retries exceeded".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_fetch_invalid_url() {
        let client = reqwest::Client::new();
        let result = proxy_fetch(&client, "http://127.0.0.1:1/nonexistent", 2, None).await;
        assert!(matches!(result, Err(ProxyError::Network(_))));
    }
}
