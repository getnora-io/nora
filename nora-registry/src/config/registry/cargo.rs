// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_cargo_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
}

fn default_cargo_proxy() -> Option<String> {
    Some("https://crates.io".to_string())
}

impl Default for CargoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_cargo_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
        }
    }
}

impl CargoConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_CARGO_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CARGO_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CARGO_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_CARGO_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_CARGO_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_CARGO_METADATA_TTL") {
            super::super::parse_env_warn("NORA_CARGO_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
    }
}
