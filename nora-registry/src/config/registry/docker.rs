// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;

/// Controls behavior when a Docker image name doesn't match any configured
/// upstream prefix or known hostname.
///
/// - `Allow` (default): ask the fallback chain; a name behind a registry host that no
///   upstream serves is answered from local storage only (#1195).
/// - `Deny`: reject the request with 403, preventing unintended upstream queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Allow,
    Deny,
}

impl fmt::Display for DefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_docker_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_docker_read_timeout")]
    pub read_timeout: u64,
    #[serde(default = "default_docker_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// What to do with a name that no `prefix`, `namespaces` or registry host routes.
    /// `allow` (default) = the fallback chain (upstreams without `namespaces`, in order), or no
    /// upstream at all for a name behind a registry host that no upstream serves (#1195);
    /// `deny` = refuse with 403 `DENIED`.
    #[serde(default)]
    pub default_action: DefaultAction,
    #[serde(default = "default_docker_upstreams")]
    pub upstreams: Vec<DockerUpstream>,
}

/// One Docker upstream.
///
/// Unknown keys are rejected: a misspelt `namespaces` would otherwise leave a private
/// registry in the fallback chain, where a public upstream answers its names (#1188).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerUpstream {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
    /// Storage namespace of the copies this upstream serves (default: derived from `url`).
    #[serde(default)]
    pub namespace: Option<String>,
    /// First path segment that selects this upstream and is stripped from the name
    /// (`nora.example/ghcr/cilium/cilium` asks it for `cilium/cilium`).
    #[serde(default)]
    pub prefix: Option<String>,
    /// First path segments this upstream owns (#1188): `"team-a"` or `"team-*"`. A name
    /// whose first segment matches one is asked of this upstream only, as written, and
    /// whatever it answers is final; no other upstream is asked for it, and this upstream
    /// is asked for nothing else.
    #[serde(default)]
    pub namespaces: Vec<String>,
}

impl DockerUpstream {
    pub fn resolved_namespace(&self) -> String {
        if let Some(ref ns) = self.namespace {
            return ns.clone();
        }
        extract_docker_namespace(&self.url)
    }

    /// Whether the upstream owns namespaces, which takes it out of the fallback chain.
    pub fn is_bound(&self) -> bool {
        !self.namespaces.is_empty()
    }

    /// Whether the upstream owns a name's first path segment.
    pub fn binds(&self, first_segment: &str) -> bool {
        self.namespaces
            .iter()
            .any(|mask| namespace_mask_matches(mask, first_segment))
    }

    /// Whether a registry host in front of an image name (`quay.io/…`) names this upstream:
    /// its storage namespace, or the host of its url (#1195). A port is not compared: an image
    /// name that reaches NORA cannot carry one, `:` is refused before routing. Each of
    /// [`DOCKER_HUB_HOSTS`] names an upstream that any other of them names.
    pub fn serves_host(&self, host: &str) -> bool {
        let url_host = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("http://"))
            .unwrap_or(&self.url)
            .split(['/', ':'])
            .next()
            .unwrap_or_default();
        let named = |h: &str| {
            h.eq_ignore_ascii_case(host) || (is_docker_hub_host(h) && is_docker_hub_host(host))
        };
        named(&self.resolved_namespace()) || named(url_host)
    }
}

/// The hosts Docker Hub is named by in an image name: `docker.io`, the legacy `index.docker.io`
/// that clients still normalize to it, and `registry-1.docker.io`, the host its API answers on.
pub const DOCKER_HUB_HOSTS: [&str; 3] = ["docker.io", "index.docker.io", "registry-1.docker.io"];

/// Whether a registry host is one of [`DOCKER_HUB_HOSTS`].
pub fn is_docker_hub_host(host: &str) -> bool {
    DOCKER_HUB_HOSTS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
}

/// Whether a `namespaces` entry holds for a first path segment: `team-*` holds for every
/// segment that starts with `team-`, any other entry only for itself.
pub fn namespace_mask_matches(mask: &str, segment: &str) -> bool {
    match mask.strip_suffix('*') {
        Some(stem) => segment.starts_with(stem),
        None => segment == mask,
    }
}

/// Whether some segment is held by both masks. Two stems overlap when one starts with the
/// other; a literal is held by a stem it starts with.
fn namespace_masks_overlap(a: &str, b: &str) -> bool {
    match (a.strip_suffix('*'), b.strip_suffix('*')) {
        (Some(x), Some(y)) => x.starts_with(y) || y.starts_with(x),
        (Some(_), None) => namespace_mask_matches(a, b),
        (None, Some(_)) => namespace_mask_matches(b, a),
        (None, None) => a == b,
    }
}

/// A `namespaces` entry is a Docker path component, lowercase, with no dot (a first segment
/// with a dot is a registry host), optionally ending in a single `*` after at least one character.
fn is_valid_namespace_mask(mask: &str) -> bool {
    let stem = mask.strip_suffix('*').unwrap_or(mask);
    stem.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && stem
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Whether a curation `internal_namespaces` pattern may hold for a name whose first segment a
/// mask owns. A pattern names its first segment exactly unless it is `*`, `*suffix`, or a
/// `prefix*` without `/`, which leave the first segment open or bound only by a start.
fn internal_pattern_meets_mask(pattern: &str, mask: &str) -> bool {
    if pattern.starts_with('*') {
        return true;
    }
    // `root/**` holds for `root/…`: the root's first segment, with a segment after it.
    if let Some(root) = pattern.strip_suffix("/**") {
        let first = root.split('/').next().unwrap_or(root);
        return namespace_mask_matches(mask, first.trim_end_matches('*'));
    }
    let body = pattern.strip_suffix(".**").unwrap_or(pattern);
    match body.split_once('/') {
        Some((first, _)) => namespace_mask_matches(mask, first.trim_end_matches('*')),
        None => match body.strip_suffix('*') {
            Some(start) => namespace_masks_overlap(&format!("{start}*"), mask),
            // A whole name without `/` has no second segment, and a bound name has one.
            None => false,
        },
    }
}

/// Derive a storage namespace from a Docker registry URL.
pub fn extract_docker_namespace(url: &str) -> String {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("default")
        .split(':')
        .next()
        .unwrap_or("default");
    let host = host.strip_prefix("registry-1.").unwrap_or(host);
    let host = host.strip_prefix("registry.").unwrap_or(host);
    host.to_string()
}

fn default_docker_timeout() -> u64 {
    300
}

fn default_docker_read_timeout() -> u64 {
    60
}

fn default_docker_metadata_ttl() -> i64 {
    -1
}

/// Default Docker upstream. Single source for the serde field-default and the
/// `Default` impl so a present-but-empty `[docker]` table keeps the upstream
/// instead of silently going local-only (the npm/pypi `#[serde(default)]`
/// divergence class — a bare default on a `Vec` yields an empty list).
fn default_docker_upstreams() -> Vec<DockerUpstream> {
    vec![DockerUpstream {
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    }]
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy_timeout: 300,
            read_timeout: 60,
            metadata_ttl: -1,
            serve_stale: true,
            default_action: DefaultAction::default(),
            upstreams: default_docker_upstreams(),
        }
    }
}

/// Path segments of the Docker API that a first name segment may not take.
pub(in crate::config) const RESERVED_DOCKER_SEGMENTS: &[&str] =
    &["blobs", "manifests", "tags", "uploads", "_catalog", "v2"];

impl DockerConfig {
    /// Configuration errors in upstream `namespaces` and `prefix` patterns (fail-closed at
    /// load) and warnings (#1188). `internal_namespaces` are curation's, never proxied.
    pub(in crate::config) fn namespaces_problems(
        &self,
        internal_namespaces: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        for (i, upstream) in self.upstreams.iter().enumerate() {
            if let Some(prefix) = &upstream.prefix {
                if prefix.contains(['*', '?']) {
                    errors.push(format!(
                        "docker.upstreams[{i}]: prefix \"{prefix}\" is matched literally, not as a pattern; bind name patterns with namespaces = [\"team-*\"]"
                    ));
                }
            }
            for mask in &upstream.namespaces {
                if !is_valid_namespace_mask(mask) {
                    errors.push(format!(
                        "docker.upstreams[{i}]: namespaces entry \"{mask}\" is not a first path segment (lowercase letters, digits, '-', '_') or one followed by a single '*'"
                    ));
                    continue;
                }
                if let Some(word) = RESERVED_DOCKER_SEGMENTS
                    .iter()
                    .find(|w| namespace_mask_matches(mask, w))
                {
                    errors.push(format!(
                        "docker.upstreams[{i}]: namespaces entry \"{mask}\" holds for \"{word}\", a reserved Docker API path segment"
                    ));
                }
                for (j, other) in self.upstreams.iter().enumerate() {
                    if let Some(prefix) = &other.prefix {
                        if namespace_mask_matches(mask, prefix) {
                            errors.push(format!(
                                "docker.upstreams[{i}]: namespaces entry \"{mask}\" holds for prefix \"{prefix}\" of docker.upstreams[{j}], which routes those names first"
                            ));
                        }
                    }
                    if j > i {
                        if let Some(clash) = other
                            .namespaces
                            .iter()
                            .find(|m| namespace_masks_overlap(mask, m))
                        {
                            errors.push(format!(
                                "docker.upstreams[{i}]: namespaces entry \"{mask}\" overlaps \"{clash}\" of docker.upstreams[{j}]; a name has one owner"
                            ));
                        }
                    }
                }
                for pattern in internal_namespaces {
                    if internal_pattern_meets_mask(pattern, mask) {
                        warnings.push(format!(
                            "docker.upstreams[{i}]: namespaces entry \"{mask}\" meets curation.internal_namespaces \"{pattern}\"; a name held by both is served from local storage only and never asked of the upstream"
                        ));
                    }
                }
            }
        }
        if self.enabled
            && !self.upstreams.is_empty()
            && self.upstreams.iter().all(DockerUpstream::is_bound)
        {
            warnings.push(
                "docker.upstreams: every entry has namespaces — names outside them are served from local storage only"
                    .to_string(),
            );
        }
        (warnings, errors)
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_DOCKER_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_DOCKER_PROXY_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_DOCKER_PROXY_TIMEOUT",
                &val,
                &mut self.proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_DOCKER_READ_TIMEOUT") {
            super::super::parse_env_warn("NORA_DOCKER_READ_TIMEOUT", &val, &mut self.read_timeout);
        }
        if let Ok(val) = env::var("NORA_DOCKER_METADATA_TTL") {
            super::super::parse_env_warn("NORA_DOCKER_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_DOCKER_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_DOCKER_DEFAULT_ACTION") {
            match val.to_lowercase().as_str() {
                "deny" => self.default_action = DefaultAction::Deny,
                "allow" => self.default_action = DefaultAction::Allow,
                _ => tracing::warn!(
                    value = %val,
                    "Invalid NORA_DOCKER_DEFAULT_ACTION (expected 'allow' or 'deny'), ignoring"
                ),
            }
        }
        if let Ok(val) =
            env::var("NORA_DOCKER_PROXIES").or_else(|_| env::var("NORA_DOCKER_UPSTREAMS"))
        {
            if env::var("NORA_DOCKER_PROXIES").is_err() {
                tracing::warn!("NORA_DOCKER_UPSTREAMS is deprecated, use NORA_DOCKER_PROXIES");
            }
            self.upstreams = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(4, '|').collect();
                    let auth = parts.get(1).and_then(|a| {
                        if a.is_empty() {
                            None
                        } else {
                            Some(ProtectedString::from(*a))
                        }
                    });
                    let prefix = parts.get(2).and_then(|p| {
                        if p.is_empty() {
                            None
                        } else {
                            Some(p.to_string())
                        }
                    });
                    // `url|auth|prefix|team-*;team-b`: the fourth field lists `namespaces`.
                    let namespaces = parts
                        .get(3)
                        .map(|n| {
                            n.split(';')
                                .filter(|m| !m.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    DockerUpstream {
                        url: parts[0].to_string(),
                        auth,
                        namespace: None,
                        prefix,
                        namespaces,
                    }
                })
                .collect();
            if self.upstreams.iter().any(|u| u.auth.is_some()) {
                tracing::warn!(
                    "Docker upstream credentials passed via NORA_DOCKER_PROXIES environment variable. \
                     For production use config.toml with [[docker.upstreams]] and mount credentials from a Kubernetes Secret."
                );
            }
        }
    }
}
