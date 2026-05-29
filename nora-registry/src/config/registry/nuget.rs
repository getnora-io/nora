// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NugetConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nuget_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_nuget_metadata_timeout")]
    pub metadata_proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    #[serde(default = "default_nuget_search")]
    pub search_service: String,
    #[serde(default = "default_nuget_autocomplete")]
    pub autocomplete: String,
}

fn default_nuget_proxy() -> Option<String> {
    Some("https://api.nuget.org".to_string())
}

fn default_nuget_search() -> String {
    "https://azuresearch-usnc.nuget.org/query".to_string()
}

fn default_nuget_autocomplete() -> String {
    "https://azuresearch-usnc.nuget.org/autocomplete".to_string()
}

fn default_nuget_metadata_timeout() -> u64 {
    2
}

impl Default for NugetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_nuget_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_proxy_timeout: 2,
            metadata_ttl: 300,
            serve_stale: true,
            search_service: default_nuget_search(),
            autocomplete: default_nuget_autocomplete(),
        }
    }
}

impl NugetConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_NUGET_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_METADATA_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.metadata_proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.metadata_ttl = ttl;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NUGET_SEARCH_SERVICE") {
            if !val.is_empty() {
                self.search_service = val;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_AUTOCOMPLETE") {
            if !val.is_empty() {
                self.autocomplete = val;
            }
        }
    }
}
