// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

/// Composer (PHP) registry: packages uploaded to NORA, and a pull-through cache of
/// Composer repositories (Packagist by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Single upstream Composer repository (its root, where `packages.json` lives).
    /// Used only when `proxies` is empty; see [`ComposerConfig::upstreams`].
    #[serde(default = "default_composer_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    /// Ordered upstream Composer repositories. The order is the precedence: the first
    /// upstream that has a package serves all of its metadata, as Composer itself asks
    /// its repositories in order and stops at the first that has the package.
    #[serde(default)]
    pub proxies: Vec<ComposerProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Seconds a cached upstream document (`packages.json`, `p2/*.json`) is served
    /// before it is revalidated.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    /// Serve the cached copy of upstream metadata when every upstream fails.
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Revalidate stale metadata with a conditional request (`If-None-Match` /
    /// `If-Modified-Since`). Packagist answers p2 files with both validators.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
    /// A GitHub token for the archives Packagist points to on GitHub
    /// (`api.github.com/repos/…/zipball/…`), which allows an anonymous client 60
    /// requests an hour. Sent as `Authorization: Bearer` to GitHub's API host only,
    /// and never past a redirect off it.
    #[serde(default, skip_serializing)]
    pub github_token: Option<ProtectedString>,
    /// Keep each proxied version's `source` (its VCS repository). Composer falls back to
    /// cloning the source when a dist download fails, a refused one included, which
    /// reaches the VCS host without NORA. Off, a version NORA serves an archive of is
    /// listed without its source, so NORA is the only way to install it.
    #[serde(default = "super::super::default_true")]
    pub keep_source: bool,
}

/// Composer upstream: a URL, or a table with the URL and its credential.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ComposerProxyEntry {
    Simple(String),
    Full(ComposerProxy),
}

impl<'de> Deserialize<'de> for ComposerProxyEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        super::url_or_table(deserializer, Self::Simple, Self::Full)
    }
}

/// Composer upstream with an optional `user:pass` credential (HTTP Basic, as
/// Composer's own `http-basic` auth sends it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposerProxy {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
}

impl ComposerProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            ComposerProxyEntry::Simple(s) => s,
            ComposerProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        match self {
            ComposerProxyEntry::Simple(_) => None,
            ComposerProxyEntry::Full(p) => crate::secrets::expose_opt(&p.auth),
        }
    }
}

/// Default upstream: Packagist's Composer 2 repository. Single source for the serde
/// field default and the `Default` impl, so a `[composer]` table without `proxy` and no
/// table at all agree.
fn default_composer_proxy() -> Option<String> {
    Some("https://repo.packagist.org".to_string())
}

impl Default for ComposerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_composer_proxy(),
            proxy_auth: None,
            proxies: Vec::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate: true,
            github_token: None,
            keep_source: true,
        }
    }
}

impl ComposerConfig {
    /// Effective, precedence-ordered upstream list: `proxies` when non-empty, else the
    /// single `proxy` (with `proxy_auth`), else none (hosted only).
    pub fn upstreams(&self) -> Vec<ComposerProxyEntry> {
        if !self.proxies.is_empty() {
            self.proxies.clone()
        } else if let Some(url) = &self.proxy {
            vec![match &self.proxy_auth {
                Some(auth) => ComposerProxyEntry::Full(ComposerProxy {
                    url: url.clone(),
                    auth: Some(auth.clone()),
                }),
                None => ComposerProxyEntry::Simple(url.clone()),
            }]
        } else {
            Vec::new()
        }
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_COMPOSER_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_COMPOSER_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_COMPOSER_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        // `url|user:pass,url2` — the syntax of NORA_PYPI_PROXIES and NORA_MAVEN_PROXIES.
        // When set it takes precedence over NORA_COMPOSER_PROXY.
        if let Ok(val) = env::var("NORA_COMPOSER_PROXIES") {
            self.proxies = parse_proxies_env(&val);
        }
        if let Ok(val) = env::var("NORA_COMPOSER_PROXY_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_COMPOSER_PROXY_TIMEOUT",
                &val,
                &mut self.proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_COMPOSER_METADATA_TTL") {
            super::super::parse_env_warn(
                "NORA_COMPOSER_METADATA_TTL",
                &val,
                &mut self.metadata_ttl,
            );
        }
        if let Ok(val) = env::var("NORA_COMPOSER_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_COMPOSER_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_COMPOSER_KEEP_SOURCE") {
            self.keep_source = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_COMPOSER_GITHUB_TOKEN") {
            self.github_token = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
    }
}

/// Parse `url|auth,url2,url3|auth3`.
fn parse_proxies_env(val: &str) -> Vec<ComposerProxyEntry> {
    val.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| match s.trim().split_once('|') {
            Some((url, auth)) => ComposerProxyEntry::Full(ComposerProxy {
                url: url.to_string(),
                auth: Some(ProtectedString::from(auth)),
            }),
            None => ComposerProxyEntry::Simple(s.trim().to_string()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_prefer_proxies_then_the_single_proxy_then_none() {
        let c = ComposerConfig::default();
        let u = c.upstreams();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].url(), "https://repo.packagist.org");
        assert_eq!(u[0].auth(), None);

        let mut c = ComposerConfig::default();
        c.proxy_auth = Some(ProtectedString::new("user:pass".into()));
        assert_eq!(c.upstreams()[0].auth(), Some("user:pass"));

        let mut c = ComposerConfig::default();
        c.proxies =
            parse_proxies_env("https://repo.example.com/acme|u:p, https://repo.packagist.org");
        let u = c.upstreams();
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].url(), "https://repo.example.com/acme");
        assert_eq!(u[0].auth(), Some("u:p"));
        assert_eq!(u[1].url(), "https://repo.packagist.org");
        assert_eq!(u[1].auth(), None);

        let mut c = ComposerConfig::default();
        c.proxy = None;
        assert!(c.upstreams().is_empty());
    }

    #[test]
    fn a_proxy_table_reads_url_and_auth() {
        let c: ComposerConfig = toml::from_str(
            "enabled = true\nproxies = [\"https://a.example\", { url = \"https://b.example\", auth = \"u:p\" }]\n",
        )
        .unwrap();
        let u = c.upstreams();
        assert_eq!(u[0].url(), "https://a.example");
        assert_eq!(u[1].url(), "https://b.example");
        assert_eq!(u[1].auth(), Some("u:p"));
    }

    #[test]
    fn secrets_are_never_serialized() {
        let mut c = ComposerConfig::default();
        c.proxy_auth = Some(ProtectedString::new("user:secret1".into()));
        c.github_token = Some(ProtectedString::new("ghp_secret2".into()));
        c.proxies = parse_proxies_env("https://a.example|u:secret3");
        let out = toml::to_string(&c).unwrap();
        for secret in ["secret1", "secret2", "secret3"] {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
    }
}
