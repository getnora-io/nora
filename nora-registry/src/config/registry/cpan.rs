// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cpan_proxy")]
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

fn default_cpan_proxy() -> Option<String> {
    Some("https://www.cpan.org".to_string())
}

impl Default for CpanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_cpan_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
        }
    }
}

impl CpanConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_CPAN_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CPAN_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CPAN_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_CPAN_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_CPAN_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_CPAN_METADATA_TTL") {
            super::super::parse_env_warn("NORA_CPAN_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_CPAN_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
    }
}
