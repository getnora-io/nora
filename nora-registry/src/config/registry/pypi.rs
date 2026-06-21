// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    /// Single upstream — retained for back-compat (`NORA_PYPI_PROXY`, old TOML).
    /// Used only when `proxies` is empty; see [`PypiConfig::upstreams`].
    #[serde(default = "default_pypi_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    /// Ordered list of upstreams (#663). The order is the precedence: the first
    /// upstream that lists/serves a file wins, like pip's `--index-url` ahead of
    /// `--extra-index-url`.
    #[serde(default)]
    pub proxies: Vec<PypiProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
}

/// PyPI upstream proxy configuration (mirrors `MavenProxyEntry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PypiProxyEntry {
    Simple(String),
    Full(PypiProxy),
}

/// PyPI upstream proxy with optional auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiProxy {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
}

impl PypiProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            PypiProxyEntry::Simple(s) => s,
            PypiProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        use crate::secrets::expose_opt;
        match self {
            PypiProxyEntry::Simple(_) => None,
            PypiProxyEntry::Full(p) => expose_opt(&p.auth),
        }
    }
}

/// Default PyPI upstream. Single source for both the serde field-default and the
/// `Default` impl so the "table present without `proxy`" and "table omitted" paths
/// agree (`#[serde(default)]` on an `Option` yields `None`, which silently dropped
/// the upstream when `[pypi]` was present).
fn default_pypi_proxy() -> Option<String> {
    Some("https://pypi.org/simple/".to_string())
}

impl Default for PypiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_pypi_proxy(),
            proxy_auth: None,
            proxies: Vec::new(),
            proxy_timeout: 30,
        }
    }
}

impl PypiConfig {
    /// Effective, precedence-ordered upstream list.
    ///
    /// `proxies` wins if non-empty (multi-upstream, #663); otherwise the legacy
    /// single `proxy` (+ `proxy_auth`) is used so existing configs keep working;
    /// empty means "no upstream, local-only".
    pub fn upstreams(&self) -> Vec<PypiProxyEntry> {
        if !self.proxies.is_empty() {
            self.proxies.clone()
        } else if let Some(url) = &self.proxy {
            // Fold the legacy single proxy (+ optional auth) into one entry so
            // back-compat users keep their authentication (not silently dropped).
            vec![match &self.proxy_auth {
                Some(auth) => PypiProxyEntry::Full(PypiProxy {
                    url: url.clone(),
                    auth: Some(auth.clone()),
                }),
                None => PypiProxyEntry::Simple(url.clone()),
            }]
        } else {
            Vec::new()
        }
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_PYPI_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        // Multi-upstream (#663): `url|auth,url2,url3|auth3` — same syntax as
        // NORA_MAVEN_PROXIES. When set it takes precedence over NORA_PYPI_PROXY.
        if let Ok(val) = env::var("NORA_PYPI_PROXIES") {
            self.proxies = val
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                    if parts.len() > 1 {
                        PypiProxyEntry::Full(PypiProxy {
                            url: parts[0].to_string(),
                            auth: Some(ProtectedString::from(parts[1])),
                        })
                    } else {
                        PypiProxyEntry::Simple(parts[0].to_string())
                    }
                })
                .collect();
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_PYPI_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_prefers_proxies_then_legacy_then_empty() {
        // Default: legacy single proxy -> one upstream.
        let c = PypiConfig::default();
        let u = c.upstreams();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].url(), "https://pypi.org/simple/");

        // Legacy proxy + auth folds into a Full entry (auth preserved).
        let mut c = PypiConfig::default();
        c.proxy_auth = Some(ProtectedString::new("tok".into()));
        assert_eq!(c.upstreams()[0].auth(), Some("tok"));

        // Explicit proxies win over the legacy single proxy.
        let mut c = PypiConfig::default();
        c.proxies = vec![
            PypiProxyEntry::Simple("https://a/simple".into()),
            PypiProxyEntry::Simple("https://b/simple".into()),
        ];
        let u = c.upstreams();
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].url(), "https://a/simple");
        assert_eq!(u[1].url(), "https://b/simple");

        // No proxy at all -> empty (local-only).
        let mut c = PypiConfig::default();
        c.proxy = None;
        assert!(c.upstreams().is_empty());
    }

    #[test]
    fn env_proxies_parse_url_and_optional_auth() {
        let mut c = PypiConfig::default();
        // Simulate NORA_PYPI_PROXIES parsing inline (avoid global env in tests).
        let val = "https://pypi.org/simple,https://download.pytorch.org/whl/cu124|sometoken";
        c.proxies = val
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                if parts.len() > 1 {
                    PypiProxyEntry::Full(PypiProxy {
                        url: parts[0].to_string(),
                        auth: Some(ProtectedString::from(parts[1])),
                    })
                } else {
                    PypiProxyEntry::Simple(parts[0].to_string())
                }
            })
            .collect();
        assert_eq!(c.proxies.len(), 2);
        assert_eq!(c.proxies[0].url(), "https://pypi.org/simple");
        assert_eq!(c.proxies[0].auth(), None);
        assert_eq!(c.proxies[1].url(), "https://download.pytorch.org/whl/cu124");
        assert_eq!(c.proxies[1].auth(), Some("sometoken"));
    }
}
