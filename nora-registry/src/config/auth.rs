// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Authentication, OIDC, and trusted proxy configuration.

use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// CIDR-aware trusted proxy list for X-Forwarded-For validation.
///
/// Only connections from trusted proxies have their XFF/X-Real-IP headers
/// honored. Untrusted sources always use the peer (TCP) IP address.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, how a dual-stack socket sees
/// an IPv4 peer) is its IPv4 address, in an entry and in an address checked.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    entries: Vec<(std::net::IpAddr, u8)>, // (network address, prefix length)
    /// Set once forwarding headers from an untrusted peer have been warned
    /// about; shared by the clones the limiters and the middleware hold.
    untrusted_forwarding_warned: Arc<AtomicBool>,
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
                        let (addr, prefix) = canonical_network(addr, prefix);
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
                entries.push(canonical_network(addr, full_prefix(addr)));
            } else {
                tracing::warn!(value = %item, "Cannot parse IP address, skipping");
            }
        }
        Self::from_entries(entries)
    }

    fn from_entries(entries: Vec<(IpAddr, u8)>) -> Self {
        Self {
            entries,
            untrusted_forwarding_warned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Default: loopback only (127.0.0.1 and ::1).
    pub fn default_loopback() -> Self {
        Self::from_entries(vec![
            (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 32),
            (std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128),
        ])
    }

    /// Check if an IP address is within the trusted proxy list.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        let ip = canonical_ip(ip);
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

    /// Warn, once for this setting, that `peer` sent forwarding headers that
    /// are ignored because it is not a trusted proxy: every client behind such
    /// a proxy is then one address to the lockout and the rate limits. Names
    /// the peer and the setting, never the headers, which the client wrote.
    pub fn warn_untrusted_forwarding(&self, peer: IpAddr) {
        if self
            .untrusted_forwarding_warned
            .swap(true, Ordering::Relaxed)
        {
            return;
        }
        tracing::warn!(
            peer = %peer,
            trusted_proxies = %self.listed(),
            "X-Forwarded-For from a peer outside auth.trusted_proxies is ignored: the lockout and \
             the rate limits count every client behind this peer as the peer itself. If NORA runs \
             behind a proxy, add the proxy to auth.trusted_proxies (NORA_AUTH_TRUSTED_PROXIES)"
        );
    }

    /// Whether forwarding headers from an untrusted peer have been warned about.
    #[cfg(test)]
    pub(crate) fn warned_untrusted_forwarding(&self) -> bool {
        self.untrusted_forwarding_warned.load(Ordering::Relaxed)
    }

    /// The entries as the comma-separated list the setting is written in.
    fn listed(&self) -> String {
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
        parts.join(",")
    }
}

/// The address a client is known by, whichever way it came: an IPv4-mapped
/// IPv6 address (`::ffff:a.b.c.d`, how a dual-stack socket sees an IPv4 peer)
/// is its IPv4 address, and every other address is itself, the IPv4-compatible
/// form `::a.b.c.d` and the IPv6 loopback included. The peer, the forwarding
/// headers and `auth.trusted_proxies` all go through here
/// ([`canonical_network`]).
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    canonical_network(ip, full_prefix(ip)).0
}

/// The prefix of a network of one address.
fn full_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

/// A network given as an IPv4-mapped IPv6 address that covers only mapped
/// addresses (prefix 96 or longer) is that IPv4 network; any other network is
/// itself. The one place an IPv6 address becomes an IPv4 one.
fn canonical_network(addr: IpAddr, prefix: u8) -> (IpAddr, u8) {
    match addr {
        IpAddr::V6(v6) if prefix >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), prefix - 96),
            None => (addr, prefix),
        },
        _ => (addr, prefix),
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
        self.listed().serialize(serializer)
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
    /// X-Forwarded-For is read from the right: the client is the rightmost address that is
    /// not in this list, so every proxy hop in front of NORA belongs here.
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
/// # Required: the `aud` the jobs request. Without it a token GitHub minted for
/// # any other service would be accepted, so NORA refuses to start. To accept
/// # any `aud` instead, set `any_audience = true` (warned about at start).
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
/// [[auth.oidc.providers.role_rules]]
/// pattern = "repo:myorg/*:ref:refs/heads/main"
/// role = "write"
///
/// # A rule may narrow the provider's namespace_scope: these identities can
/// # write, but only under ci-transport/.
/// [[auth.oidc.providers.role_rules]]
/// pattern = "repo:myorg/*:pull_request"
/// role = "write"
/// namespace_scope = ["ci-transport/**"]
///
/// [[auth.oidc.providers.role_rules]]
/// pattern = "repo:myorg/*"
/// role = "read"
/// ```
///
/// GitLab CI needs a different ceiling. GitLab sets an ID token's `exp` from the
/// job timeout, whose project default is 60 minutes, so with NORA's default
/// `max_token_lifetime_secs = 900` a token from a job that does not set a short
/// `timeout:` is rejected — and until #994 that rejection was a bare 401 with no
/// reason. Raise the ceiling to cover the job timeout, or pin a short `timeout:`
/// on the jobs that push:
///
/// ```toml
/// [[auth.oidc.providers]]
/// name = "gitlab"
/// # Must equal the `iss` claim, i.e. GitLab's external_url.
/// issuer = "https://gitlab.example.com"
/// # Matches `aud` in the job: id_tokens: NORA_ID_TOKEN: aud: nora
/// audience = "nora"
/// algorithms = ["RS256"]
/// # GitLab: token lifetime = job timeout (default 60 min), so 900 would refuse it.
/// max_token_lifetime_secs = 3600
/// namespace_scope = ["myorg/**"]
///
/// # GitLab's sub is project_path:<group>/<project>:ref_type:<type>:ref:<name>
/// [[auth.oidc.providers.role_rules]]
/// pattern = "project_path:mygroup/myproject:ref_type:branch:ref:main"
/// role = "write"
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

impl OidcConfig {
    /// OIDC is a usable write path: enabled with at least one provider. When
    /// true, a missing htpasswd is the intended (OIDC-only) setup, not a
    /// misconfiguration to warn about (#996).
    pub fn is_active(&self) -> bool {
        self.enabled && !self.providers.is_empty()
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
    /// Expected audience (`aud` claim): the value the CI jobs request, e.g.
    /// `nora`. Required unless `any_audience` is set — a shared issuer such as
    /// GitHub Actions mints tokens for every repository on the host, and
    /// without this check a token minted for another service is accepted.
    #[serde(default)]
    pub audience: String,
    /// Accept a token whatever its `aud` claim, in place of `audience`. NORA
    /// warns at start for every provider that sets it.
    #[serde(default)]
    pub any_audience: bool,
    /// Allowed JWT algorithms (default: RS256, ES256). Reject all others.
    #[serde(default = "default_oidc_algorithms")]
    pub algorithms: Vec<String>,
    /// Maximum token lifetime in seconds. Tokens with longer exp-iat are rejected.
    ///
    /// The default (900) fits GitHub Actions, whose tokens are short-lived. GitLab
    /// derives the lifetime from the job timeout — 60 minutes by default — so a
    /// GitLab provider needs a ceiling that covers it (3600) or jobs that set a
    /// short `timeout:`; otherwise every push is refused with 401.
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

/// How a provider checks the `aud` claim of a token, read from `audience` and
/// `any_audience`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceCheck<'a> {
    /// The `aud` claim must name this value. An `audience` is checked even
    /// beside `any_audience = true`.
    Expect(&'a str),
    /// `any_audience = true` and no `audience`: the claim is not checked.
    Any,
    /// Neither is set. Config validation refuses it, and the validator admits
    /// no token through such a provider.
    Missing,
}

impl OidcProvider {
    /// How this provider checks the `aud` claim. Config validation and the
    /// token validator both read it, so they cannot disagree.
    pub fn audience_check(&self) -> AudienceCheck<'_> {
        if !self.audience.is_empty() {
            AudienceCheck::Expect(&self.audience)
        } else if self.any_audience {
            AudienceCheck::Any
        } else {
            AudienceCheck::Missing
        }
    }
}

/// Maps a subject pattern to a NORA role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcRoleRule {
    /// Glob pattern matched against the JWT `sub` claim
    pub pattern: String,
    /// Role to assign: "read", "write", or "admin"
    pub role: String,
    /// Narrow the provider's `namespace_scope` for identities matched by this
    /// rule (e.g. grant CI pull-request builds write access to a transport
    /// prefix only). Enforced **in addition to** the provider scope — a write
    /// must satisfy both, so the provider scope stays a hard ceiling and a
    /// rule cannot widen past it (`["*"]` here is a no-op, not a promotion).
    /// Absent = inherit the provider's scope. A rule scope is applied with
    /// the provider's `namespace_scope_enforcement`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_scope: Option<Vec<String>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Which networks are IPv4 ones: only the IPv4-mapped form `::ffff:a.b.c.d`
    /// with a prefix that covers mapped addresses only (96 or longer) is the
    /// IPv4 network it maps. The IPv4-compatible form `::a.b.c.d`, the IPv6
    /// loopback and the unspecified address stay the IPv6 networks they name.
    #[test]
    fn only_a_mapped_network_is_an_ipv4_one() {
        for (network, prefix, want, want_prefix) in [
            ("::ffff:10.0.0.1", 128, "10.0.0.1", 32),
            ("::ffff:a00:1", 128, "10.0.0.1", 32),
            ("::ffff:10.1.0.0", 112, "10.1.0.0", 16),
            ("::ffff:0.0.0.0", 96, "0.0.0.0", 0),
            ("::ffff:0.0.0.0", 95, "::ffff:0.0.0.0", 95),
            ("::a00:1", 128, "::a00:1", 128),
            ("::a00:0", 104, "::a00:0", 104),
            ("::1", 128, "::1", 128),
            ("::", 128, "::", 128),
            ("2001:db8::1", 128, "2001:db8::1", 128),
            ("10.0.0.1", 32, "10.0.0.1", 32),
            ("10.0.0.0", 8, "10.0.0.0", 8),
        ] {
            let got = canonical_network(network.parse().unwrap(), prefix);
            assert_eq!(
                got,
                (want.parse().unwrap(), want_prefix),
                "{network}/{prefix}"
            );
        }
    }

    /// The address of one client, as a table: a mapped address is its IPv4
    /// address, any other is itself.
    #[test]
    fn only_a_mapped_address_is_an_ipv4_one() {
        for (address, want) in [
            ("::ffff:10.0.0.1", "10.0.0.1"),
            ("::ffff:0.0.0.1", "0.0.0.1"),
            ("::a00:1", "::a00:1"),
            ("::1", "::1"),
            ("::", "::"),
            ("2001:db8::1", "2001:db8::1"),
            ("10.0.0.1", "10.0.0.1"),
        ] {
            assert_eq!(
                canonical_ip(address.parse().unwrap()),
                want.parse::<IpAddr>().unwrap(),
                "{address}"
            );
        }
    }

    /// An IPv6 address becomes an IPv4 one only in [`canonical_network`]
    /// (white list): the peer, the forwarding headers, the limiters and the
    /// entries take it from there, so no place keys a client by a rule of its
    /// own. Needles are built at run time so this text does not match.
    #[test]
    fn only_canonical_network_turns_an_address_into_ipv4() {
        let needles = [
            ["to_canonical", "("].concat(),
            ["to_ipv4", "("].concat(),
            ["to_ipv4", "_mapped("].concat(),
            ["Ipv4Addr::", "from(u32"].concat(),
        ];
        for (file, source) in [
            ("config/auth.rs", include_str!("auth.rs")),
            ("auth/mod.rs", include_str!("../auth/mod.rs")),
            (
                "auth/token_routes.rs",
                include_str!("../auth/token_routes.rs"),
            ),
            ("rate_limit.rs", include_str!("../rate_limit.rs")),
        ] {
            let code = source
                .split(&["#[cfg(test)]", "\nmod tests"].concat())
                .next()
                .unwrap();
            let mut function = "";
            for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
                if let Some((_, rest)) = line.split_once("fn ") {
                    function = rest
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .unwrap_or("");
                }
                for needle in &needles {
                    assert!(
                        !line.contains(needle.as_str())
                            || (file, function) == ("config/auth.rs", "canonical_network"),
                        "{file}: {function} turns an address into IPv4: {line}"
                    );
                }
            }
        }
    }

    /// The same networks written in `auth.trusted_proxies`, read the way the
    /// configuration file is: which addresses each one trusts.
    #[test]
    fn trusted_proxies_from_the_file_trust_only_their_own_family() {
        for (setting, address, trusted) in [
            ("::a00:1/128", "10.0.0.1", false),
            ("::a00:1/128", "::ffff:10.0.0.1", false),
            ("::a00:1/128", "::a00:1", true),
            ("::a00:1", "10.0.0.1", false),
            ("::1/128", "::1", true),
            ("::1/128", "0.0.0.1", false),
            ("::1", "::1", true),
            ("::1", "0.0.0.1", false),
            ("::ffff:10.0.0.1/128", "10.0.0.1", true),
            ("::ffff:10.0.0.1/128", "::ffff:10.0.0.1", true),
            ("::ffff:10.0.0.1", "10.0.0.1", true),
            ("::ffff:10.0.0.0/120", "10.0.0.7", true),
            ("::ffff:10.0.0.0/120", "10.0.1.7", false),
            ("10.0.0.0/8", "::ffff:10.2.3.4", true),
            ("10.0.0.0/8", "::a02:304", false),
            ("2001:db8::/32", "2001:db8::5", true),
            ("2001:db8::/32", "10.0.0.1", false),
        ] {
            let auth: AuthConfig =
                toml::from_str(&format!("trusted_proxies = {setting:?}")).unwrap();
            assert_eq!(
                auth.trusted_proxies.contains(address.parse().unwrap()),
                trusted,
                "{setting} trusting {address}"
            );
        }
    }

    #[test]
    fn oidc_config_is_active_only_with_enabled_and_a_provider() {
        // #996 — is_active decides whether a missing htpasswd is the intended
        // OIDC-only setup (info) or a misconfiguration (warn).
        let mut cfg = OidcConfig::default();
        assert!(!cfg.is_active(), "default (disabled) must not be active");

        cfg.enabled = true;
        assert!(
            !cfg.is_active(),
            "enabled without a provider must not be active"
        );

        let with_provider: OidcConfig = toml::from_str(
            "enabled = true\n[[providers]]\nname = \"ci\"\nissuer = \"https://issuer.example/\"",
        )
        .expect("valid oidc config");
        assert!(
            with_provider.is_active(),
            "enabled with a provider must be active"
        );
    }

    /// A network written in the IPv4-mapped form at prefix 96 or longer is the
    /// IPv4 network under it, at every such prefix: `::ffff:0.0.0.0/96` is all
    /// of IPv4, `::ffff:a.b.c.d/128` is the one address. Both forms of every
    /// address are judged alike.
    #[test]
    fn a_mapped_network_is_its_ipv4_network_at_every_prefix() {
        let addresses: Vec<IpAddr> = [
            "203.0.113.0",
            "203.0.113.1",
            "203.0.113.128",
            "203.0.113.255",
            "203.0.112.255",
            "203.0.114.0",
            "10.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        for prefix in 96..=128u8 {
            let mapped = TrustedProxies::parse(&format!("::ffff:203.0.113.0/{prefix}"));
            let ipv4 = TrustedProxies::parse(&format!("203.0.113.0/{}", prefix - 96));
            for &addr in &addresses {
                let IpAddr::V4(v4) = addr else { unreachable!() };
                let as_mapped = IpAddr::V6(v4.to_ipv6_mapped());
                assert_eq!(
                    mapped.contains(addr),
                    ipv4.contains(addr),
                    "/{prefix}: {addr}"
                );
                assert_eq!(
                    mapped.contains(as_mapped),
                    ipv4.contains(addr),
                    "/{prefix}: {as_mapped}"
                );
            }
        }
        let all_of_ipv4 = TrustedProxies::parse("::ffff:0.0.0.0/96");
        for addr in &addresses {
            assert!(all_of_ipv4.contains(*addr), "{addr}");
        }
        assert!(!all_of_ipv4.contains("2001:db8::1".parse().unwrap()));
        let one = TrustedProxies::parse("::ffff:203.0.113.1/128");
        assert!(one.contains("203.0.113.1".parse().unwrap()));
        assert!(!one.contains("203.0.113.0".parse().unwrap()));
    }
}
