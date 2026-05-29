// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ansible_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_ansible_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
}

fn default_ansible_proxy() -> Option<String> {
    Some("https://galaxy.ansible.com".to_string())
}

fn default_ansible_metadata_ttl() -> i64 {
    3600
}

impl Default for AnsibleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_ansible_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 3600,
            serve_stale: true,
        }
    }
}

impl AnsibleConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_ANSIBLE_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.metadata_ttl = ttl;
            }
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
    }
}
