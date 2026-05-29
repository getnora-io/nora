// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Server and TLS configuration.

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Public URL for generating pull commands (e.g., "registry.example.com")
    #[serde(default)]
    pub public_url: Option<String>,
    /// Maximum request body size in MB (default: 2048 = 2GB)
    #[serde(default = "default_body_limit_mb")]
    pub body_limit_mb: usize,
}

pub(super) fn default_body_limit_mb() -> usize {
    2048 // 2GB - enough for any Docker image
}

/// TLS configuration for outbound connections to upstream registries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM-encoded CA certificate bundle (appended to system CAs)
    #[serde(default)]
    pub ca_cert: Option<String>,
}

impl ServerConfig {
    /// Apply environment variable overrides for server config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HOST") {
            self.host = val;
        }
        if let Ok(val) = env::var("NORA_PORT") {
            super::parse_env_warn("NORA_PORT", &val, &mut self.port);
        }
        if let Ok(val) = env::var("NORA_PUBLIC_URL") {
            self.public_url = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_BODY_LIMIT_MB") {
            super::parse_env_warn("NORA_BODY_LIMIT_MB", &val, &mut self.body_limit_mb);
        }
    }
}

impl TlsConfig {
    /// Apply environment variable overrides for TLS config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_TLS_CA_CERT") {
            self.ca_cert = if val.is_empty() { None } else { Some(val) };
        }
    }
}
