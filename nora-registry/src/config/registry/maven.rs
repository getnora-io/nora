// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub proxies: Vec<MavenProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Verify client-uploaded checksums against server-computed values
    #[serde(default = "super::super::default_true")]
    pub checksum_verify: bool,
    /// Prevent overwriting released (non-SNAPSHOT) artifacts
    #[serde(default = "super::super::default_true")]
    pub immutable_releases: bool,
    /// Staleness window (seconds) for mutable metadata (maven-metadata.xml, SNAPSHOT); a
    /// non-positive value revalidates every pull. Release artifacts are always immutable.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
}

/// Maven upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MavenProxyEntry {
    Simple(String),
    Full(MavenProxy),
}

/// Maven upstream proxy with optional auth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenProxy {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
}

impl MavenProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            MavenProxyEntry::Simple(s) => s,
            MavenProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        use crate::secrets::expose_opt;
        match self {
            MavenProxyEntry::Simple(_) => None,
            MavenProxyEntry::Full(p) => expose_opt(&p.auth),
        }
    }
}

impl Default for MavenConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxies: vec![MavenProxyEntry::Simple(
                "https://repo1.maven.org/maven2".to_string(),
            )],
            proxy_timeout: 30,
            checksum_verify: true,
            immutable_releases: true,
            metadata_ttl: 300,
        }
    }
}

impl MavenConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_MAVEN_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_PROXIES") {
            self.proxies = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                    if parts.len() > 1 {
                        MavenProxyEntry::Full(MavenProxy {
                            url: parts[0].to_string(),
                            auth: Some(ProtectedString::from(parts[1])),
                        })
                    } else {
                        MavenProxyEntry::Simple(parts[0].to_string())
                    }
                })
                .collect();
        }
        if let Ok(val) = env::var("NORA_MAVEN_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_MAVEN_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_MAVEN_CHECKSUM_VERIFY") {
            self.checksum_verify = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_IMMUTABLE_RELEASES") {
            self.immutable_releases = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_METADATA_TTL") {
            super::super::parse_env_warn("NORA_MAVEN_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
    }
}
