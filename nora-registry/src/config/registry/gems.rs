// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gems_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
}

fn default_gems_proxy() -> Option<String> {
    Some("https://rubygems.org".to_string())
}

impl Default for GemsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_gems_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
        }
    }
}

impl GemsConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GEMS_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_GEMS_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_GEMS_METADATA_TTL") {
            super::super::parse_env_warn("NORA_GEMS_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_GEMS_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
    }
}
