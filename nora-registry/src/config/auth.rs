// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Authentication, OIDC, and trusted proxy configuration.

use serde::{Deserialize, Serialize};
use std::env;

/// CIDR-aware trusted proxy list for X-Forwarded-For validation.
///
/// Only connections from trusted proxies have their XFF/X-Real-IP headers
/// honored. Untrusted sources always use the peer (TCP) IP address.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    entries: Vec<(std::net::IpAddr, u8)>, // (network address, prefix length)
}

impl TrustedProxies {
    /// Parse a comma-separated list of IPs/CIDRs. Invalid entries are skipped with a warning.
    pub fn parse(input: &str) -> Self {
        let mut entries = Vec::new();
        for item in input.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if let Some((addr_str, prefix_str)) = item.split_once('/') {
                if let (Ok(addr), Ok(prefix)) = (
                    addr_str.parse::<std::net::IpAddr>(),
                    prefix_str.parse::<u8>(),
                ) {
                    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
                    if prefix <= max_prefix {
                        if prefix == 0 {
                            tracing::warn!(
                                value = %item,
                                "CIDR /0 matches ALL addresses in this family — all peers will be \
                                 trusted proxies (X-Forwarded-For honored, IP-based rate limiting disabled)"
                            );
                        }
                        entries.push((addr, prefix));
                    } else {
                        tracing::warn!(value = %item, "Invalid CIDR prefix length, skipping");
                    }
                } else {
                    tracing::warn!(value = %item, "Cannot parse CIDR, skipping");
                }
            } else if let Ok(addr) = item.parse::<std::net::IpAddr>() {
                let prefix = if addr.is_ipv4() { 32 } else { 128 };
                entries.push((addr, prefix));
            } else {
                tracing::warn!(value = %item, "Cannot parse IP address, skipping");
            }
        }
        Self { entries }
    }

    /// Default: loopback only (127.0.0.1 and ::1).
    pub fn default_loopback() -> Self {
        Self {
            entries: vec![
                (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 32),
                (std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128),
            ],
        }
    }

    /// Check if an IP address is within the trusted proxy list.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        self.entries.iter().any(|(network, prefix)| {
            match (network, ip) {
                (std::net::IpAddr::V4(net), std::net::IpAddr::V4(addr)) => {
                    // /0 matches all addresses in this family (RFC 4632).
                    // Must check before shift: u32::MAX << 32 overflows.
                    if *prefix == 0 {
                        return true;
                    }
                    if *prefix >= 32 {
                        return *net == addr;
                    }
                    let net_bits = u32::from(*net);
                    let addr_bits = u32::from(addr);
                    let mask = u32::MAX << (32 - prefix);
                    (net_bits & mask) == (addr_bits & mask)
                }
                (std::net::IpAddr::V6(net), std::net::IpAddr::V6(addr)) => {
                    // /0 matches all addresses in this family (RFC 4632).
                    // Must check before shift: u128::MAX << 128 overflows.
                    if *prefix == 0 {
                        return true;
                    }
                    if *prefix >= 128 {
                        return *net == addr;
                    }
                    let net_bits = u128::from(*net);
                    let addr_bits = u128::from(addr);
                    let mask = u128::MAX << (128 - prefix);
                    (net_bits & mask) == (addr_bits & mask)
                }
                _ => false, // v4 vs v6 mismatch
            }
        })
    }

    /// Returns true if any entry uses prefix /0 (matches all addresses in its family).
    pub fn has_prefix_zero(&self) -> bool {
        self.entries.iter().any(|(_, prefix)| *prefix == 0)
    }
}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self::default_loopback()
    }
}

// TrustedProxies doesn't need serde — it's parsed from a string.
// Provide a dummy Serialize/Deserialize so AuthConfig can derive them.
impl Serialize for TrustedProxies {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let parts: Vec<String> = self
            .entries
            .iter()
            .map(|(addr, prefix)| {
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if *prefix == max {
                    addr.to_string()
                } else {
                    format!("{}/{}", addr, prefix)
                }
            })
            .collect();
        parts.join(",").serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustedProxies {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::parse(&s))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Allow anonymous read access (pull/download without auth, push requires auth).
    /// Governs all registries EXCEPT Docker/OCI — Docker has its own
    /// `docker_anon_pull` switch (see below), because anonymous Docker pull
    /// changes the `/v2/` auth-challenge handshake and must be opted into
    /// explicitly so enabling anonymous Maven/raw/npm never silently exposes
    /// container images.
    #[serde(default)]
    pub anonymous_read: bool,
    /// Allow anonymous Docker/OCI pull (`docker pull` without `docker login`).
    ///
    /// Default `false` (fail-closed). Separate from `anonymous_read`: the general
    /// switch does NOT open Docker, so an operator can serve Maven/raw anonymously
    /// while keeping images private.
    ///
    /// When `true`, the `GET /v2/` ping returns `200` (no auth challenge) so the
    /// Docker client proceeds anonymously; manifest/blob/tag reads are served
    /// without auth. Writes (push/delete) are unaffected and still require auth.
    /// `GET /v2/_catalog` (cross-repo enumeration) stays authenticated — it is
    /// not part of anonymous pull. Per-image reads needed to resolve a known
    /// name (manifests, blobs, and `tags/list`) ARE served anonymously. A request
    /// that DOES carry an `Authorization` header is always validated (honest
    /// `docker login`, correct audit attribution) rather than treated as anonymous.
    ///
    /// Limitation: clients built on `containers/image` (skopeo/podman/buildah)
    /// read auth parameters only from the `/v2/` ping, so with the ping returning
    /// `200` their *authenticated* operations degrade (anonymous pull still
    /// works). Upgrade path for scoped anonymous access: a Docker Bearer-token
    /// endpoint. ENV: NORA_AUTH_DOCKER_ANON_PULL.
    #[serde(default)]
    pub docker_anon_pull: bool,
    /// Serve the browse UI and its JSON API (`/ui`, `/api/ui`) and the API
    /// docs (`/api-docs`) without authentication. Default `false`
    /// (fail-closed): the web surface enumerates every repository and
    /// package — exactly what a private deployment is hiding — so with auth
    /// enabled it requires credentials unless `anonymous_read` (which
    /// already exposes the same names through the registry read APIs) or
    /// this switch opens it. Health probes (`/health`, `/ready`) are always
    /// public. ENV: NORA_AUTH_PUBLIC_WEB_UI.
    #[serde(default)]
    pub public_web_ui: bool,
    /// Serve `/metrics` without authentication. Default `true`: Prometheus
    /// scrapers rarely carry credentials, and metric labels name registry
    /// FORMATS, not repositories. Set `false` to require auth there too
    /// (Prometheus `basic_auth` supports it). ENV: NORA_AUTH_PUBLIC_METRICS.
    #[serde(default = "default_public_metrics")]
    pub public_metrics: bool,
    #[serde(default = "default_htpasswd_file")]
    pub htpasswd_file: String,
    #[serde(default = "default_token_storage")]
    pub token_storage: String,
    /// In-memory token-verify cache TTL (seconds). Lower it to bound the
    /// cross-replica revocation window: under a multi-replica deployment a token
    /// revoked on one replica is still served from another replica's cache until
    /// its entry expires.
    /// Default 300. ENV: NORA_AUTH_TOKEN_CACHE_TTL.
    #[serde(default = "default_token_cache_ttl")]
    pub token_cache_ttl: u64,
    /// Trusted proxy IPs/CIDRs — only these sources have XFF/X-Real-IP honored.
    /// Default: 127.0.0.1,::1 (loopback only).
    /// ENV: NORA_AUTH_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8
    #[serde(default)]
    pub trusted_proxies: TrustedProxies,
    /// OIDC providers for workload identity (CI/CD zero-secret auth)
    #[serde(default)]
    pub oidc: OidcConfig,
    /// htpasswd usernames permitted to mint `admin`-role API tokens via the
    /// public `POST /api/tokens` route. Empty (default) means no account can
    /// self-mint an admin token there — set this to bootstrap admins. Read and
    /// write tokens are unaffected (GHSA-78cx-cfhm-rgmx — block role
    /// self-escalation).
    /// ENV: NORA_AUTH_ADMIN_USERS=alice,ops
    #[serde(default)]
    pub admin_users: Vec<String>,
}

/// OIDC configuration — multiple providers for workload identity auth.
///
/// ```toml
/// [auth.oidc]
/// enabled = true
///
/// [[auth.oidc.providers]]
/// name = "github-actions"
/// issuer = "https://token.actions.githubusercontent.com"
/// audience = "nora"
/// algorithms = ["RS256", "ES256"]
/// max_token_lifetime_secs = 900
/// # Restrict this issuer to artifacts whose coordinate is under `myorg/`.
/// # Segment-aware: `myorg/*` = direct children only, `myorg/**` = any depth.
/// # Per format the coordinate is: docker image (`myorg/<img>`), raw path
/// # (`myorg/<path>`), npm package (`@myorg/*`), maven group/artifact
/// # (`com/myorg/**`), pypi/cargo the normalized project/crate name.
/// # `["*"]` (the default) disables scoping for this issuer.
/// namespace_scope = ["myorg/**"]
/// # "enforce" (default) denies out-of-scope writes with 403; "audit" allows
/// # but logs+counts them (nora_auth_namespace_scope_total) for staged rollout.
/// namespace_scope_enforcement = "enforce"
///
/// [auth.oidc.providers.role_rules]
/// "repo:myorg/*:ref:refs/heads/main" = "write"
/// "repo:myorg/*" = "read"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Clock skew leeway for token validation (seconds)
    #[serde(default = "default_oidc_leeway")]
    pub leeway_secs: u64,
    /// JWKS cache TTL (seconds). Stale keys served on fetch failure.
    #[serde(default = "default_oidc_jwks_cache_secs")]
    pub jwks_cache_secs: u64,
    /// OIDC identity providers
    #[serde(default)]
    pub providers: Vec<OidcProvider>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            leeway_secs: default_oidc_leeway(),
            jwks_cache_secs: default_oidc_jwks_cache_secs(),
            providers: Vec::new(),
        }
    }
}

/// A single OIDC identity provider (e.g., GitHub Actions, GitLab CI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    /// Human-readable name for logs/debugging
    pub name: String,
    /// OIDC issuer URL (must match `iss` claim exactly)
    pub issuer: String,
    /// Explicit JWKS URI override. If not set, NORA discovers it via
    /// `{issuer}/.well-known/openid-configuration`. Use when the provider's
    /// JWKS endpoint doesn't follow the standard `/.well-known/jwks.json` path.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Expected audience (`aud` claim). If empty, audience is not validated.
    #[serde(default)]
    pub audience: String,
    /// Allowed JWT algorithms (default: RS256, ES256). Reject all others.
    #[serde(default = "default_oidc_algorithms")]
    pub algorithms: Vec<String>,
    /// Maximum token lifetime in seconds. Tokens with longer exp-iat are rejected.
    #[serde(default = "default_oidc_max_lifetime")]
    pub max_token_lifetime_secs: u64,
    /// Namespace scope — which NORA namespaces this issuer can access.
    /// ["*"] = all, ["github/*"] = only repos under github/ prefix.
    #[serde(default = "default_namespace_scope")]
    pub namespace_scope: Vec<String>,
    /// How `namespace_scope` is applied on writes: `enforce` (deny with 403,
    /// the default) or `audit` (allow the write but log and count what would
    /// have been denied). Audit mode lets operators stage a rollout — deploy in
    /// audit, watch the metric, then switch to enforce (#583).
    #[serde(default)]
    pub namespace_scope_enforcement: ScopeEnforcement,
    /// Kill switch — disable this provider without removing config
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Role rules: glob pattern on `sub` claim → role (read/write/admin).
    /// First match wins. No match = deny.
    #[serde(default)]
    pub role_rules: Vec<OidcRoleRule>,
}

/// Maps a subject pattern to a NORA role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcRoleRule {
    /// Glob pattern matched against the JWT `sub` claim
    pub pattern: String,
    /// Role to assign: "read", "write", or "admin"
    pub role: String,
}

/// How an OIDC provider's `namespace_scope` is applied on writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScopeEnforcement {
    /// Deny out-of-scope writes with HTTP 403 (default, fail-closed).
    #[default]
    Enforce,
    /// Allow out-of-scope writes but log and count them as `would_deny`. Used to
    /// stage a rollout before turning on hard denial.
    Audit,
}

pub(super) fn default_oidc_leeway() -> u64 {
    60
}

pub(super) fn default_oidc_jwks_cache_secs() -> u64 {
    3600
}

pub(super) fn default_oidc_algorithms() -> Vec<String> {
    vec!["RS256".to_string(), "ES256".to_string()]
}

pub(super) fn default_oidc_max_lifetime() -> u64 {
    900 // 15 minutes
}

pub(super) fn default_namespace_scope() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_public_metrics() -> bool {
    true
}

pub(super) fn default_htpasswd_file() -> String {
    "users.htpasswd".to_string()
}

pub(super) fn default_token_storage() -> String {
    "data/tokens".to_string()
}

pub(super) fn default_token_cache_ttl() -> u64 {
    300
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            anonymous_read: false,
            docker_anon_pull: false,
            public_web_ui: false,
            public_metrics: true,
            htpasswd_file: "users.htpasswd".to_string(),
            token_storage: "data/tokens".to_string(),
            token_cache_ttl: 300,
            trusted_proxies: TrustedProxies::default_loopback(),
            oidc: OidcConfig::default(),
            admin_users: Vec::new(),
        }
    }
}

impl AuthConfig {
    /// Apply environment variable overrides for auth config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_AUTH_PUBLIC_WEB_UI") {
            self.public_web_ui = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_PUBLIC_METRICS") {
            self.public_metrics = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_ANONYMOUS_READ") {
            self.anonymous_read = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_DOCKER_ANON_PULL") {
            self.docker_anon_pull = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_HTPASSWD_FILE") {
            self.htpasswd_file = val;
        }
        if let Ok(val) = env::var("NORA_AUTH_TOKEN_CACHE_TTL") {
            if let Ok(secs) = val.parse() {
                self.token_cache_ttl = secs;
            }
        }
        if let Ok(val) = env::var("NORA_AUTH_TRUSTED_PROXIES") {
            self.trusted_proxies = TrustedProxies::parse(&val);
        }
        if let Ok(val) = env::var("NORA_AUTH_ADMIN_USERS") {
            self.admin_users = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(val) = env::var("NORA_AUTH_OIDC_ENABLED") {
            self.oidc.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_TOKEN_STORAGE") {
            self.token_storage = val;
        }
    }
}
