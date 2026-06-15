// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Server and TLS configuration.

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_host")]
    pub host: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Public URL for generating pull commands (e.g., "registry.example.com")
    #[serde(default)]
    pub public_url: Option<String>,
    /// Maximum request body size in MB (default: 2048 = 2GB)
    #[serde(default = "default_body_limit_mb")]
    pub body_limit_mb: usize,
    /// Coalesce concurrent upstream fetches for the same key on a cache miss
    /// (single-flight, #595). Default `true`; set `false` to disable and let
    /// every concurrent request fetch independently (kill-switch).
    #[serde(default = "default_proxy_coalesce")]
    pub proxy_coalesce: bool,
    /// Trust upstream-provided publish dates (`published`/`time`/`created_at`/
    /// `upload_time`/etc.) when enforcing `min_release_age` curation. Default
    /// `false` (secure, ADR-8): an attacker controlling/MITM-ing an upstream
    /// registry could spoof an OLD date so a freshly-published malicious package
    /// appears old and bypasses the new-package quarantine. When `false`, NORA
    /// derives the package age from its OWN cache timestamp (mtime) instead.
    /// Set `true` to restore the legacy behavior of trusting upstream dates.
    /// NB: with `false`, age is measured from when NORA first cached the
    /// artifact (cache-age), not its real publish date — a long-published
    /// package just cached will be quarantined for `min_release_age`.
    #[serde(default = "default_trust_upstream_dates")]
    pub trust_upstream_dates: bool,
}

pub(super) fn default_server_host() -> String {
    String::from("127.0.0.1")
}

pub(super) fn default_server_port() -> u16 {
    4000
}

pub(super) fn default_body_limit_mb() -> usize {
    2048 // 2GB - enough for any Docker image
}

pub(super) fn default_proxy_coalesce() -> bool {
    true
}

pub(super) fn default_trust_upstream_dates() -> bool {
    false
}

/// TLS configuration for outbound connections to upstream registries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM-encoded CA certificate bundle (appended to system CAs)
    #[serde(default)]
    pub ca_cert: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            public_url: None,
            body_limit_mb: default_body_limit_mb(),
            proxy_coalesce: default_proxy_coalesce(),
            trust_upstream_dates: default_trust_upstream_dates(),
        }
    }
}

impl ServerConfig {
    /// Format bind address for `TcpListener::bind`.
    ///
    /// IPv6 addresses contain colons and need bracket notation (`[::]:4000`)
    /// to avoid ambiguity with the host:port separator (#569).
    pub fn bind_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Build the base URL advertised to clients (npm/docker/nuget service
    /// index, UI install commands). Single source of truth for client-facing
    /// URLs — handlers and UI must not reconstruct it inline.
    ///
    /// Returns `public_url` (trailing slash trimmed) if set, otherwise falls
    /// back to `http://{host}:{port}`. The fallback only makes sense for a
    /// routable bind address; `validate()` rejects a wildcard bind without a
    /// public_url and warns on a loopback public_url (#510, #590), so a broken
    /// URL never silently ships.
    pub fn public_base_url(&self) -> String {
        let base = self
            .public_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string())
            // Reuse bind_addr() so IPv6 literals get bracket notation
            // (`http://[::1]:4000`) — keeping the authority format consistent
            // with the listen address and avoiding drift.
            .unwrap_or_else(|| format!("http://{}", self.bind_addr()));
        debug_assert!(
            base.starts_with("http://") || base.starts_with("https://"),
            "public_base_url must carry an http(s) scheme: {base}"
        );
        base
    }

    /// Host authority (`host[:port]`) advertised to clients, without scheme.
    ///
    /// For registry references that take no URL scheme — e.g.
    /// `docker pull {host}/repo:tag`. Derived from [`Self::public_base_url`]
    /// so it shares the single source of truth.
    pub fn public_host(&self) -> String {
        let base = self.public_base_url();
        base.strip_prefix("https://")
            .or_else(|| base.strip_prefix("http://"))
            .unwrap_or(&base)
            .trim_end_matches('/')
            .to_string()
    }

    /// Path prefix the UI must prepend to its root-absolute self-links so it
    /// works when NORA is mounted under a sub-path behind a reverse proxy
    /// (`location /nora/ { proxy_pass http://nora:4000/; }`, trailing slash
    /// strips `/nora`). Derived from the path component of `public_url`, trailing
    /// slash trimmed. Empty when `public_url` is unset or has no path — a no-op
    /// for every root-vhost deploy, which is the common case.
    pub fn base_path(&self) -> String {
        let Some(url) = self.public_url.as_deref() else {
            return String::new();
        };
        // Path component without a URL crate: drop the scheme, then the authority
        // (up to the first '/'), keep the rest.
        let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
        let path = after_scheme.find('/').map_or("", |i| &after_scheme[i..]);
        path.trim_end_matches('/').to_string()
    }

    /// Apply environment variable overrides for server config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HOST") {
            self.host = val;
        }
        if let Ok(val) = env::var("NORA_PORT") {
            super::parse_env_warn("NORA_PORT", &val, &mut self.port);
        }
        if let Ok(val) = env::var("NORA_PUBLIC_URL") {
            self.public_url = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_BODY_LIMIT_MB") {
            super::parse_env_warn("NORA_BODY_LIMIT_MB", &val, &mut self.body_limit_mb);
        }
        if let Ok(val) = env::var("NORA_TRUST_UPSTREAM_DATES") {
            super::parse_env_warn(
                "NORA_TRUST_UPSTREAM_DATES",
                &val,
                &mut self.trust_upstream_dates,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(host: &str, port: u16) -> ServerConfig {
        ServerConfig {
            host: host.to_string(),
            port,
            public_url: None,
            body_limit_mb: 2048,
            proxy_coalesce: true,
            trust_upstream_dates: false,
        }
    }

    #[test]
    fn bind_addr_ipv4() {
        assert_eq!(server("0.0.0.0", 4000).bind_addr(), "0.0.0.0:4000");
        assert_eq!(server("127.0.0.1", 8080).bind_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn bind_addr_ipv6() {
        assert_eq!(server("::", 4000).bind_addr(), "[::]:4000");
        assert_eq!(server("::1", 4000).bind_addr(), "[::1]:4000");
        assert_eq!(
            server("2001:db8::1", 4000).bind_addr(),
            "[2001:db8::1]:4000"
        );
    }

    #[test]
    fn bind_addr_hostname() {
        assert_eq!(server("localhost", 4000).bind_addr(), "localhost:4000");
        assert_eq!(
            server("registry.example.com", 443).bind_addr(),
            "registry.example.com:443"
        );
    }

    #[test]
    fn public_base_url_falls_back_to_host_port() {
        // No public_url → http://{host}:{port}.
        assert_eq!(
            server("127.0.0.1", 4000).public_base_url(),
            "http://127.0.0.1:4000"
        );
    }

    #[test]
    fn public_base_url_brackets_ipv6_fallback() {
        // IPv6 literal host without public_url must be bracketed, matching
        // bind_addr() — otherwise the authority is ambiguous/malformed.
        assert_eq!(
            server("2001:db8::1", 4000).public_base_url(),
            "http://[2001:db8::1]:4000"
        );
        assert_eq!(server("::1", 4000).public_host(), "[::1]:4000");
    }

    #[test]
    fn base_path_extracts_public_url_path_or_empty() {
        // No public_url → empty (no-op for root-vhost deploys).
        assert_eq!(server("127.0.0.1", 4000).base_path(), "");

        let mut s = server("h", 4000);
        // public_url with no path → empty.
        s.public_url = Some("https://nora.example.com".into());
        assert_eq!(s.base_path(), "");
        s.public_url = Some("https://nora.example.com:8443".into());
        assert_eq!(s.base_path(), "");
        // Sub-path mount → the path prefix, trailing slash trimmed.
        s.public_url = Some("https://example.com/nora".into());
        assert_eq!(s.base_path(), "/nora");
        s.public_url = Some("https://example.com/nora/".into());
        assert_eq!(s.base_path(), "/nora");
        s.public_url = Some("https://example.com:8443/team/nora".into());
        assert_eq!(s.base_path(), "/team/nora");
    }

    #[test]
    fn public_base_url_uses_public_url_and_trims_slash() {
        let mut cfg = server("0.0.0.0", 4000);
        cfg.public_url = Some("https://registry.example.com/".to_string());
        // public_url wins over the bind address; trailing slash trimmed.
        assert_eq!(cfg.public_base_url(), "https://registry.example.com");
    }

    #[test]
    fn public_host_strips_scheme_for_docker_pull() {
        // Fallback case: scheme stripped, host:port kept.
        assert_eq!(
            server("registry.example.com", 4000).public_host(),
            "registry.example.com:4000"
        );

        // public_url case: scheme and trailing slash stripped — `docker pull`
        // takes a bare host, not a URL.
        let mut cfg = server("0.0.0.0", 4000);
        cfg.public_url = Some("https://nora.example.com/".to_string());
        assert_eq!(cfg.public_host(), "nora.example.com");

        cfg.public_url = Some("http://nora.example.com:8080".to_string());
        assert_eq!(cfg.public_host(), "nora.example.com:8080");
    }
}

impl TlsConfig {
    /// Apply environment variable overrides for TLS config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_TLS_CA_CERT") {
            self.ca_cert = if val.is_empty() { None } else { Some(val) };
        }
    }
}
