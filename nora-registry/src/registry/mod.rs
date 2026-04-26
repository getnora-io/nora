// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod cargo_registry;
pub mod docker;
pub mod docker_auth;
mod go;
mod maven;
mod npm;
mod pub_dart;
mod pypi;
mod raw;

pub use cargo_registry::routes as cargo_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use go::routes as go_routes;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;
pub use pub_dart::routes as pub_routes;
pub use pypi::routes as pypi_routes;
pub use raw::routes as raw_routes;

use crate::config::basic_auth_header;
use std::time::Duration;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ProxyError {
    NotFound,
    Upstream(u16),
    Network(String),
}

/// Core fetch logic with retry. Callers provide a response extractor.
async fn proxy_fetch_core<T, F, Fut>(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
    auth: Option<&str>,
    extra_headers: Option<(&str, &str)>,
    extract: F,
) -> Result<T, ProxyError>
where
    F: Fn(reqwest::Response) -> Fut + Copy,
    Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
{
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
                    return extract(response)
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

/// Fetch binary content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
    auth: Option<&str>,
) -> Result<Vec<u8>, ProxyError> {
    proxy_fetch_core(client, url, timeout_secs, auth, None, |r| async {
        r.bytes().await.map(|b| b.to_vec())
    })
    .await
}

/// Fetch text content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch_text(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
    auth: Option<&str>,
    extra_headers: Option<(&str, &str)>,
) -> Result<String, ProxyError> {
    proxy_fetch_core(client, url, timeout_secs, auth, extra_headers, |r| r.text()).await
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
