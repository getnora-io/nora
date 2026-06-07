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
    /// Revalidate stale metadata with a conditional request (`If-None-Match` /
    /// `If-Modified-Since`) instead of always re-downloading the full body.
    /// Fail-open: any error falls back to a full fetch. Note: self-hosted Galaxy
    /// NG / pulp_ansible does not emit HTTP validators on the versions list, so a
    /// 304 only occurs behind a validator-adding CDN (e.g. galaxy.ansible.com);
    /// otherwise this degrades to a full fetch — never worse than before.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
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
            revalidate: true,
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
            super::super::parse_env_warn(
                "NORA_ANSIBLE_PROXY_TIMEOUT",
                &val,
                &mut self.proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_METADATA_TTL") {
            super::super::parse_env_warn("NORA_ANSIBLE_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
    }
}
