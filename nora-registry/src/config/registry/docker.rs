// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_docker_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_docker_read_timeout")]
    pub read_timeout: u64,
    #[serde(default = "default_docker_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    #[serde(default)]
    pub upstreams: Vec<DockerUpstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerUpstream {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
}

impl DockerUpstream {
    pub fn resolved_namespace(&self) -> String {
        if let Some(ref ns) = self.namespace {
            return ns.clone();
        }
        extract_docker_namespace(&self.url)
    }
}

/// Derive a storage namespace from a Docker registry URL.
pub fn extract_docker_namespace(url: &str) -> String {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("default")
        .split(':')
        .next()
        .unwrap_or("default");
    let host = host.strip_prefix("registry-1.").unwrap_or(host);
    let host = host.strip_prefix("registry.").unwrap_or(host);
    host.to_string()
}

fn default_docker_timeout() -> u64 {
    300
}

fn default_docker_read_timeout() -> u64 {
    60
}

fn default_docker_metadata_ttl() -> i64 {
    -1
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy_timeout: 300,
            read_timeout: 60,
            metadata_ttl: -1,
            serve_stale: true,
            upstreams: vec![DockerUpstream {
                url: "https://registry-1.docker.io".to_string(),
                auth: None,
                namespace: None,
                prefix: None,
            }],
        }
    }
}

impl DockerConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_DOCKER_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_DOCKER_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_DOCKER_READ_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.read_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_DOCKER_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.metadata_ttl = ttl;
            }
        }
        if let Ok(val) = env::var("NORA_DOCKER_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) =
            env::var("NORA_DOCKER_PROXIES").or_else(|_| env::var("NORA_DOCKER_UPSTREAMS"))
        {
            if env::var("NORA_DOCKER_PROXIES").is_err() {
                tracing::warn!("NORA_DOCKER_UPSTREAMS is deprecated, use NORA_DOCKER_PROXIES");
            }
            self.upstreams = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(3, '|').collect();
                    let auth = parts.get(1).and_then(|a| {
                        if a.is_empty() {
                            None
                        } else {
                            Some(ProtectedString::from(*a))
                        }
                    });
                    let prefix = parts.get(2).and_then(|p| {
                        if p.is_empty() {
                            None
                        } else {
                            Some(p.to_string())
                        }
                    });
                    DockerUpstream {
                        url: parts[0].to_string(),
                        auth,
                        namespace: None,
                        prefix,
                    }
                })
                .collect();
            if self.upstreams.iter().any(|u| u.auth.is_some()) {
                tracing::warn!(
                    "Docker upstream credentials passed via NORA_DOCKER_PROXIES environment variable. \
                     For production use config.toml with [[docker.upstreams]] and mount credentials from a Kubernetes Secret."
                );
            }
        }
    }
}
