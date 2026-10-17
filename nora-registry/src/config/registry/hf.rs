// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

/// Hugging Face Hub pull-through proxy (`[hf]`), off by default while the format is built.
///
/// Only the upstream is configurable. There is deliberately no `proxy_auth`: a server-side
/// token would let the cache hand gated repositories to every NORA user, so the first
/// release proxies public repositories only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hf_proxy")]
    pub proxy: Option<String>,
    /// Seconds for one metadata request to the upstream.
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// The hosts a file request's redirect may leave the upstream's origin for, over https
    /// (a downgrade to http never): each entry and the names under it (`hf.co` holds
    /// `us.aws.cdn.hf.co`). An IP address counts only as written. The Hub sends LFS files to
    /// its CDN; any other host — a mirror's misstep, a metadata or loopback address — is
    /// refused before it is asked.
    #[serde(default = "default_hf_cdn_hosts")]
    pub cdn_hosts: Vec<String>,
}

fn default_hf_proxy() -> Option<String> {
    Some("https://huggingface.co".to_string())
}

fn default_hf_cdn_hosts() -> Vec<String> {
    vec!["hf.co".to_string(), "huggingface.co".to_string()]
}

impl Default for HfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_hf_proxy(),
            proxy_timeout: 30,
            cdn_hosts: default_hf_cdn_hosts(),
        }
    }
}

impl HfConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HF_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_HF_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_HF_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_HF_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_HF_CDN_HOSTS") {
            self.cdn_hosts = val
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect();
        }
    }

    /// The `cdn_hosts` entries that are not a bare host name or IP address (a scheme, a
    /// port, a path or a wildcard has no place there), for a configuration error.
    pub fn invalid_cdn_hosts(&self) -> Vec<String> {
        self.cdn_hosts
            .iter()
            .filter(|h| {
                h.is_empty()
                    || h.starts_with('.')
                    || h.ends_with('.')
                    || h.parse::<std::net::IpAddr>().is_err()
                        && !h.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                        })
            })
            .cloned()
            .collect()
    }
}
