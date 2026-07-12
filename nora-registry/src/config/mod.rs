// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! NORA registry configuration module.
//!
//! Configuration is loaded with three-tier priority: ENV > config file > defaults.
//! Each subsystem (server, storage, auth, registries, etc.) is defined in its own
//! submodule for maintainability.

mod audit_cfg;
mod auth;
mod circuit_breaker;
mod curation;
mod gc;
mod rate_limit;
mod registries;
pub mod registry;
mod retention;
mod server;
mod signing_cfg;
mod storage;

// Infrastructure configs
pub use self::audit_cfg::AuditConfig;
pub use self::signing_cfg::SigningConfig;
// Re-exports maintain API surface: `crate::config::OidcRoleRule` etc. used by test code in auth/, circuit_breaker/
#[allow(unused_imports)]
pub use self::auth::{
    AuthConfig, OidcConfig, OidcProvider, OidcRoleRule, ScopeEnforcement, TrustedProxies,
};
#[allow(unused_imports)]
pub use self::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerOverride};
pub use self::curation::{
    CurationConfig, CurationMode, CurationOnFailure, RegistryCurationOverride,
};
pub use self::gc::GcConfig;
pub use self::rate_limit::RateLimitConfig;
pub use self::registries::{EnableSpec, RegistriesSection};
pub use self::retention::{RetentionConfig, RetentionRule};
pub use self::server::{ServerConfig, TlsConfig};
pub use self::storage::{StorageConfig, StorageMode};

// Registry configs (re-exported from registry/ submodule tree)
pub use self::registry::*;

// Secrets config lives in crate::secrets — just re-export
pub use crate::secrets::SecretsConfig;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;

use crate::registry_type::RegistryType;

// --- Shared defaults (used by submodules via `super::default_*`) ---

/// Returns `true` — used as serde default for boolean fields that should default to enabled.
pub(crate) fn default_true() -> bool {
    true
}

/// Default proxy timeout in seconds (30s).
pub(crate) fn default_timeout() -> u64 {
    30
}

/// Default metadata TTL in seconds (300s = 5 minutes).
pub(crate) fn default_metadata_ttl() -> i64 {
    300
}

/// Encode "user:pass" into a Basic Auth header value, e.g. "Basic dXNlcjpwYXNz".
pub fn basic_auth_header(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

/// Parse an env var value into `target`, warning on failure (#537).
///
/// If `val` parses successfully, `*target` is updated. If parsing fails,
/// a `warn!` is emitted with the variable name and invalid value, and
/// `*target` is left unchanged (keeps the TOML/default value).
pub(crate) fn parse_env_warn<T: std::str::FromStr + std::fmt::Display>(
    name: &str,
    val: &str,
    target: &mut T,
) {
    match val.parse::<T>() {
        Ok(parsed) => {
            *target = parsed;
        }
        Err(_) => {
            tracing::warn!(
                var = name,
                value = val,
                "env override ignored: failed to parse value"
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub maven: MavenConfig,
    #[serde(default)]
    pub npm: NpmConfig,
    #[serde(default)]
    pub pypi: PypiConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub go: GoConfig,
    #[serde(default)]
    pub cargo: CargoConfig,
    #[serde(default)]
    pub raw: RawConfig,
    #[serde(default)]
    pub gems: GemsConfig,
    #[serde(default)]
    pub terraform: TerraformConfig,
    #[serde(default)]
    pub ansible: AnsibleConfig,
    #[serde(default)]
    pub nuget: NugetConfig,
    #[serde(default)]
    pub pub_dart: PubDartConfig,
    #[serde(default)]
    pub conan: ConanConfig,
    #[serde(default)]
    pub rpm: RpmConfig,
    #[serde(default)]
    pub deb: DebConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub gc: GcConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub curation: CurationConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    /// Declarative registry selection: `[registries] enable = ["docker", "npm"]`
    #[serde(default)]
    pub registries: Option<RegistriesSection>,
}

impl Config {
    /// Returns the set of enabled registry types.
    ///
    /// Resolution priority (three tiers):
    /// 1. `NORA_REGISTRIES_ENABLE` env var (highest)
    /// 2. `[registries].enable` from TOML config
    /// 3. Legacy per-registry `enabled` flags (backward compatible)
    pub fn enabled_registries(&self) -> HashSet<RegistryType> {
        // Tier 1: NORA_REGISTRIES_ENABLE env var
        if let Ok(val) = env::var("NORA_REGISTRIES_ENABLE") {
            if !val.is_empty() {
                let spec = EnableSpec::from_env_str(&val);
                match spec.resolve() {
                    Ok(set) => {
                        Self::warn_legacy_env_vars_if_present();
                        tracing::info!(
                            registries = ?set.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                            "Registry selection from NORA_REGISTRIES_ENABLE"
                        );
                        return set;
                    }
                    Err(e) => {
                        tracing::error!("NORA_REGISTRIES_ENABLE is invalid: {} — falling back", e);
                    }
                }
            }
        }

        // Tier 2: [registries].enable from TOML
        if let Some(ref section) = self.registries {
            if let Some(ref spec) = section.enable {
                match spec.resolve() {
                    Ok(set) => {
                        Self::warn_legacy_env_vars_if_present();
                        tracing::info!(
                            registries = ?set.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                            "Registry selection from [registries].enable"
                        );
                        return set;
                    }
                    Err(e) => {
                        tracing::error!(
                            "[registries].enable is invalid: {} — falling back to legacy",
                            e
                        );
                    }
                }
            }
        }

        // Tier 3: legacy per-registry enabled flags
        self.enabled_registries_legacy()
    }

    /// Legacy registry resolution from individual `*.enabled` flags.
    fn enabled_registries_legacy(&self) -> HashSet<RegistryType> {
        let mut set = HashSet::new();
        if self.docker.enabled {
            set.insert(RegistryType::Docker);
        }
        if self.maven.enabled {
            set.insert(RegistryType::Maven);
        }
        if self.npm.enabled {
            set.insert(RegistryType::Npm);
        }
        if self.cargo.enabled {
            set.insert(RegistryType::Cargo);
        }
        if self.pypi.enabled {
            set.insert(RegistryType::PyPI);
        }
        if self.go.enabled {
            set.insert(RegistryType::Go);
        }
        if self.raw.enabled {
            set.insert(RegistryType::Raw);
        }
        if self.gems.enabled {
            set.insert(RegistryType::Gems);
        }
        if self.terraform.enabled {
            set.insert(RegistryType::Terraform);
        }
        if self.ansible.enabled {
            set.insert(RegistryType::Ansible);
        }
        if self.nuget.enabled {
            set.insert(RegistryType::Nuget);
        }
        if self.pub_dart.enabled {
            set.insert(RegistryType::PubDart);
        }
        if self.conan.enabled {
            set.insert(RegistryType::Conan);
        }
        if self.rpm.enabled {
            set.insert(RegistryType::Rpm);
        }
        if self.deb.enabled {
            set.insert(RegistryType::Deb);
        }
        if set.is_empty() {
            tracing::warn!("No registries enabled! All registries are disabled.");
        }
        set
    }

    /// Whether `rt` is an enabled registry with at least one upstream proxy configured.
    ///
    /// The `match` is exhaustive over [`RegistryType`], so adding a variant is a
    /// compile error until its proxy shape is declared here — the single source of
    /// truth for "is this an enabled proxy?". Raw has no upstream and is always false.
    /// Per-registry shapes differ: most carry `proxy: Option<String>`, PyPI also has a
    /// multi-upstream `proxies` list, Maven uses `proxies`, Docker uses `upstreams`.
    fn is_enabled_proxy(&self, rt: RegistryType) -> bool {
        match rt {
            RegistryType::Docker => self.docker.enabled && !self.docker.upstreams.is_empty(),
            RegistryType::Maven => self.maven.enabled && !self.maven.proxies.is_empty(),
            RegistryType::Npm => self.npm.enabled && self.npm.proxy.is_some(),
            RegistryType::Cargo => self.cargo.enabled && self.cargo.proxy.is_some(),
            RegistryType::PyPI => {
                self.pypi.enabled && (self.pypi.proxy.is_some() || !self.pypi.proxies.is_empty())
            }
            RegistryType::Go => self.go.enabled && self.go.proxy.is_some(),
            RegistryType::Raw => false, // raw file storage has no upstream
            RegistryType::Gems => self.gems.enabled && self.gems.proxy.is_some(),
            RegistryType::Terraform => self.terraform.enabled && self.terraform.proxy.is_some(),
            RegistryType::Ansible => self.ansible.enabled && self.ansible.proxy.is_some(),
            RegistryType::Nuget => self.nuget.enabled && self.nuget.proxy.is_some(),
            RegistryType::PubDart => self.pub_dart.enabled && self.pub_dart.proxy.is_some(),
            RegistryType::Conan => self.conan.enabled && self.conan.proxy.is_some(),
            RegistryType::Rpm => false, // hosted-only, no upstream
            RegistryType::Deb => false, // hosted-only, no upstream
        }
    }

    /// The effective quarantine mode for `rt`: the per-registry override if set,
    /// else the global `curation.quarantine`, else `Off`.
    ///
    /// The `match` is exhaustive over [`RegistryType`] and the precedence is
    /// byte-identical to the handler resolution (`per.or(global)`, e.g.
    /// `registry/docker.rs::resolve_quarantine`), so config validation and the
    /// runtime DigestStore gate compute the SAME value and cannot diverge — that
    /// divergence was the #765 bug (docker dropped from the hand-rolled chains).
    /// `Raw` has no curation override and no quarantine-enforcing path → always
    /// `Off` (counting it would be a phantom control: `any_quarantine_active`
    /// true while nothing enforces).
    fn quarantine_mode_for(&self, rt: RegistryType) -> crate::digest_quarantine::QuarantineMode {
        use crate::digest_quarantine::QuarantineMode;
        let global = self.curation.quarantine.as_ref();
        let per = match rt {
            RegistryType::Docker => self.curation.docker.quarantine.as_ref(),
            RegistryType::Maven => self.curation.maven.quarantine.as_ref(),
            RegistryType::Npm => self.curation.npm.quarantine.as_ref(),
            RegistryType::Cargo => self.curation.cargo.quarantine.as_ref(),
            RegistryType::PyPI => self.curation.pypi.quarantine.as_ref(),
            RegistryType::Go => self.curation.go.quarantine.as_ref(),
            RegistryType::Gems => self.curation.gems.quarantine.as_ref(),
            RegistryType::Terraform => self.curation.terraform.quarantine.as_ref(),
            RegistryType::Ansible => self.curation.ansible.quarantine.as_ref(),
            RegistryType::Nuget => self.curation.nuget.quarantine.as_ref(),
            RegistryType::PubDart => self.curation.pub_dart.quarantine.as_ref(),
            RegistryType::Conan => self.curation.conan.quarantine.as_ref(),
            // Raw, RPM, and Debian are hosted-only: no curation override, no
            // quarantine gate in their handlers (quarantine gates proxy downloads).
            RegistryType::Raw | RegistryType::Rpm | RegistryType::Deb => {
                return QuarantineMode::Off
            }
        };
        per.or(global).cloned().unwrap_or(QuarantineMode::Off)
    }

    /// Whether any registry has an effective quarantine mode other than `Off`.
    ///
    /// Single source of truth for both config validation (the #741 min-release-age
    /// guard and the enforce "at least one control" check) and the runtime
    /// DigestStore gate in `main.rs`. Because it folds [`Self::quarantine_mode_for`]
    /// over [`RegistryType::all`], a per-registry quarantine (e.g. docker-only)
    /// counts everywhere it should: the durable store is loaded iff some registry
    /// actually enforces, closing the #765 fail-open where a docker-only quarantine
    /// got an empty (non-durable) store.
    pub(crate) fn any_quarantine_active(&self) -> bool {
        use crate::digest_quarantine::QuarantineMode;
        RegistryType::all()
            .iter()
            .any(|&rt| self.quarantine_mode_for(rt) != QuarantineMode::Off)
    }

    /// Warn if legacy NORA_*_ENABLED env vars are set while using the new
    /// `[registries].enable` or `NORA_REGISTRIES_ENABLE`.
    fn warn_legacy_env_vars_if_present() {
        let legacy_vars = [
            "NORA_DOCKER_ENABLED",
            "NORA_MAVEN_ENABLED",
            "NORA_NPM_ENABLED",
            "NORA_CARGO_ENABLED",
            "NORA_PYPI_ENABLED",
            "NORA_GO_ENABLED",
            "NORA_RAW_ENABLED",
            "NORA_GEMS_ENABLED",
            "NORA_TF_ENABLED",
            "NORA_ANSIBLE_ENABLED",
            "NORA_NUGET_ENABLED",
            "NORA_PUB_ENABLED",
            "NORA_CONAN_ENABLED",
        ];
        let found: Vec<&str> = legacy_vars
            .iter()
            .filter(|v| env::var(v).is_ok())
            .copied()
            .collect();
        if !found.is_empty() {
            tracing::warn!(
                vars = ?found,
                "Legacy NORA_*_ENABLED env vars are set but ignored — \
                 [registries].enable or NORA_REGISTRIES_ENABLE takes precedence"
            );
        }
    }

    /// Warn if credentials are configured via config.toml (not env vars)
    pub fn warn_plaintext_credentials(&self) {
        // Docker upstreams
        for (i, upstream) in self.docker.upstreams.iter().enumerate() {
            if upstream.auth.is_some()
                && std::env::var("NORA_DOCKER_PROXIES").is_err()
                && std::env::var("NORA_DOCKER_UPSTREAMS").is_err()
            {
                tracing::warn!(
                    upstream_index = i,
                    url = %upstream.url,
                    "Docker upstream credentials in config.toml are plaintext — consider NORA_DOCKER_PROXIES env var"
                );
            }
        }
        // Maven proxies
        for proxy in &self.maven.proxies {
            if proxy.auth().is_some() && std::env::var("NORA_MAVEN_PROXIES").is_err() {
                tracing::warn!(
                    url = %proxy.url(),
                    "Maven proxy credentials in config.toml are plaintext — consider NORA_MAVEN_PROXIES env var"
                );
            }
        }
        // Go
        if self.go.proxy_auth.is_some() && std::env::var("NORA_GO_PROXY_AUTH").is_err() {
            tracing::warn!("Go proxy credentials in config.toml are plaintext — consider NORA_GO_PROXY_AUTH env var");
        }
        // npm
        if self.npm.proxy_auth.is_some() && std::env::var("NORA_NPM_PROXY_AUTH").is_err() {
            tracing::warn!("npm proxy credentials in config.toml are plaintext — consider NORA_NPM_PROXY_AUTH env var");
        }
        // PyPI
        if self.pypi.proxy_auth.is_some() && std::env::var("NORA_PYPI_PROXY_AUTH").is_err() {
            tracing::warn!("PyPI proxy credentials in config.toml are plaintext — consider NORA_PYPI_PROXY_AUTH env var");
        }
        // PyPI multi-upstream proxies (#663)
        for proxy in &self.pypi.proxies {
            if proxy.auth().is_some() && std::env::var("NORA_PYPI_PROXIES").is_err() {
                tracing::warn!(
                    url = %proxy.url(),
                    "PyPI upstream credentials in config.toml are plaintext — consider NORA_PYPI_PROXIES env var"
                );
            }
        }
        // Cargo
        if self.cargo.proxy_auth.is_some() && std::env::var("NORA_CARGO_PROXY_AUTH").is_err() {
            tracing::warn!("Cargo proxy credentials in config.toml are plaintext — consider NORA_CARGO_PROXY_AUTH env var");
        }
        // Auth posture: a silently-unauthenticated instance must not look safe.
        // The zero-config default is auth.enabled=false, which accepts BOTH reads
        // and writes from anyone; surface it loudly so it is a deliberate choice.
        if !self.auth.enabled {
            tracing::warn!(
                "auth.enabled=false — NORA is accepting UNAUTHENTICATED reads AND writes. \
                 Set auth.enabled=true (with htpasswd/tokens/OIDC) before exposing this instance."
            );
        } else if self.auth.anonymous_read {
            tracing::warn!(
                "auth.anonymous_read=true — pulls/downloads are served without authentication \
                 (writes still require a token); ensure this is intended for this deployment."
            );
        }
        // Independent of anonymous_read: anonymous Docker pull serves container
        // images to anyone (push still requires auth). Surface it on its own.
        if self.auth.enabled && self.auth.docker_anon_pull {
            tracing::warn!(
                "auth.docker_anon_pull=true — Docker/OCI images are served on anonymous \
                 `docker pull` without authentication (push still requires a token); ensure this \
                 is intended for this deployment."
            );
        }
    }

    /// Collect all configured upstream hostnames for leak detection (#386).
    ///
    /// Returns `(registry_name, hostname)` pairs extracted from proxy URLs.
    /// Used once at startup to pre-compile substring searchers.
    pub fn upstream_hostnames(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();

        let extract_host = |url: &str| -> Option<String> {
            let without_scheme = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url);
            let host = without_scheme.split('/').next()?;
            let host = host.split(':').next()?;
            if host.is_empty() || host == "localhost" || host == "127.0.0.1" {
                return None;
            }
            Some(host.to_lowercase())
        };

        // Simple proxy: Option<String>
        let simple = [
            ("npm", self.npm.proxy.as_deref()),
            ("cargo", self.cargo.proxy.as_deref()),
            ("go", self.go.proxy.as_deref()),
            ("gems", self.gems.proxy.as_deref()),
            ("terraform", self.terraform.proxy.as_deref()),
            ("ansible", self.ansible.proxy.as_deref()),
            ("nuget", self.nuget.proxy.as_deref()),
            ("pub", self.pub_dart.proxy.as_deref()),
            ("conan", self.conan.proxy.as_deref()),
        ];
        for (name, url) in simple {
            if let Some(url) = url {
                if let Some(host) = extract_host(url) {
                    result.push((name.to_string(), host));
                }
            }
        }

        // NuGet extra search/autocomplete URLs
        if let Some(host) = extract_host(&self.nuget.search_service) {
            result.push(("nuget".to_string(), host));
        }
        if let Some(host) = extract_host(&self.nuget.autocomplete) {
            result.push(("nuget".to_string(), host));
        }

        // Docker upstreams: Vec<DockerUpstream>
        for upstream in &self.docker.upstreams {
            if let Some(host) = extract_host(&upstream.url) {
                result.push(("docker".to_string(), host));
            }
        }

        // Maven proxies: Vec<MavenProxyEntry>
        for proxy in &self.maven.proxies {
            if let Some(host) = extract_host(proxy.url()) {
                result.push(("maven".to_string(), host));
            }
        }

        // PyPI upstreams: Vec<PypiProxyEntry> via upstreams() so the multi-upstream
        // list (#663) AND the legacy single `proxy` are both registered with the
        // leak detector — otherwise a secondary upstream's host (e.g. an internal
        // mirror with embedded credentials) would be invisible to leak scanning.
        for up in self.pypi.upstreams() {
            if let Some(host) = extract_host(up.url()) {
                result.push(("pypi".to_string(), host));
            }
        }

        // Deduplicate
        result.sort();
        result.dedup();
        result
    }

    /// Validate configuration and return (warnings, errors).
    ///
    /// Warnings are logged but do not prevent startup.
    /// Errors indicate a fatal misconfiguration and should cause a panic.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
        self.validate_with_config_path(env::var("NORA_CONFIG_PATH").ok())
    }

    /// True if `host` is a loopback address (the 127.0.0.0/8 block or ::1) or
    /// the `localhost` hostname (case-insensitive). Used to warn when a service
    /// index would be built from a loopback bind address, unreachable by remote
    /// clients (#590). Callers passing a URL host must strip IPv6 brackets first
    /// (`url::host_str()` returns "[::1]", which does not parse as an `IpAddr`).
    pub(crate) fn is_loopback_host(host: &str) -> bool {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
    }

    /// Validate configuration with explicit config_path to avoid env var
    /// dependency in tests (env vars are process-global, tests run in parallel).
    pub fn validate_with_config_path(
        &self,
        config_path: Option<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // 1. Port must not be 0
        if self.server.port == 0 {
            errors.push("server.port must not be 0".to_string());
        }

        // 1b. Wildcard host requires public_url (non-routable address → broken client URLs)
        {
            let host = &self.server.host;
            let is_wildcard = host == "0.0.0.0" || host == "::" || host == "0:0:0:0:0:0:0:0";

            if is_wildcard && self.server.public_url.is_none() {
                errors.push(format!(
                    "NORA_PUBLIC_URL is required when host is '{}' (not routable). \
                     Set: NORA_PUBLIC_URL=http://your-registry:{}",
                    host, self.server.port
                ));
            }
        }

        // 1c. Validate public_url format if set
        if let Some(ref url_str) = self.server.public_url {
            match reqwest::Url::parse(url_str) {
                Ok(parsed) => {
                    let scheme = parsed.scheme();
                    if scheme != "http" && scheme != "https" {
                        errors.push(format!(
                            "NORA_PUBLIC_URL must use http:// or https:// scheme, got: '{}'",
                            scheme
                        ));
                    }
                    // public_url explicitly set to a loopback host is also broken for
                    // remote clients — the operator configured the footgun directly (#590).
                    // host_str() returns IPv6 literals with brackets ("[::1]"), which do
                    // not parse as an IpAddr — strip them before the loopback check.
                    if let Some(h) = parsed.host_str() {
                        let h = h.trim_start_matches('[').trim_end_matches(']');
                        if Self::is_loopback_host(h) {
                            warnings.push(format!(
                                "NORA_PUBLIC_URL points at loopback ('{}') — clients behind a \
                                 reverse proxy cannot reach it. Use the externally-reachable \
                                 hostname, e.g. https://registry.example.com",
                                h
                            ));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "NORA_PUBLIC_URL is not a valid URL: '{}' — {}",
                        url_str, e
                    ));
                }
            }
        }

        // 2. Storage path must not be empty when mode = Local
        if self.storage.mode == StorageMode::Local && self.storage.path.trim().is_empty() {
            errors.push("storage.path must not be empty when storage mode is local".to_string());
        }

        // 3. Bucket must not be empty when mode = S3 or GCS
        if matches!(self.storage.mode, StorageMode::S3 | StorageMode::Gcs)
            && self.storage.bucket.trim().is_empty()
        {
            errors.push(
                "storage.bucket must not be empty when storage mode is s3 or gcs".to_string(),
            );
        }

        // 4. Rate limit values must be > 0 when rate limiting is enabled
        if self.rate_limit.enabled {
            if self.rate_limit.auth_rps == 0 {
                warnings
                    .push("rate_limit.auth_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.auth_burst == 0 {
                warnings
                    .push("rate_limit.auth_burst is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.upload_rps == 0 {
                warnings
                    .push("rate_limit.upload_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.upload_burst == 0 {
                warnings.push(
                    "rate_limit.upload_burst is 0 while rate limiting is enabled".to_string(),
                );
            }
            if self.rate_limit.general_rps == 0 {
                warnings
                    .push("rate_limit.general_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.general_burst == 0 {
                warnings.push(
                    "rate_limit.general_burst is 0 while rate limiting is enabled".to_string(),
                );
            }
        }

        // 5. Body limit must be > 0
        if self.server.body_limit_mb == 0 {
            warnings
                .push("server.body_limit_mb is 0, no request bodies will be accepted".to_string());
        }

        // 6. Relative paths — may resolve unexpectedly.
        // The storage.path hint is scoped to explicit-config starts, to avoid noise
        // on the relative default of a bare `nora serve`.
        if config_path.is_some()
            && self.storage.mode == StorageMode::Local
            && !self.storage.path.starts_with('/')
        {
            warnings.push(format!(
                "storage.path=\"{}\" is relative — will resolve from CWD. Use absolute path for predictable behavior",
                self.storage.path
            ));
        }
        // The token_storage hint fires whenever auth is enabled with a relative
        // path, regardless of config source: env-only (systemd) starts have
        // config_path=None yet are exactly where a relative token_storage resolves
        // outside ReadWritePaths and breaks token writes (#816).
        if self.auth.enabled && !self.auth.token_storage.starts_with('/') {
            warnings.push(format!(
                "auth.token_storage=\"{}\" is relative — will resolve from CWD (under systemd it \
                 resolves outside ReadWritePaths and token writes fail). Set an absolute path, e.g. \
                 NORA_AUTH_TOKEN_STORAGE=/var/lib/nora/tokens",
                self.auth.token_storage
            ));
        }

        // 7. Trusted proxies /0 — security footgun
        if self.auth.trusted_proxies.has_prefix_zero() {
            warnings.push(
                "auth.trusted_proxies contains a /0 CIDR — all peers are trusted proxies. \
                 X-Forwarded-For will be honored from any source, disabling IP-based brute-force protection"
                    .to_string(),
            );
        }

        // 8. "Enabled but empty" — subsystems that silently do nothing
        if self.gc.enabled && self.gc.dry_run {
            warnings.push(
                "gc.enabled=true with gc.dry_run=true — GC will run but never delete anything. Set gc.dry_run=false to actually free space".to_string(),
            );
        }
        if self.retention.enabled && self.retention.dry_run && !self.retention.rules.is_empty() {
            warnings.push(
                "retention.enabled=true with retention.dry_run=true — retention will run but never delete anything. Set retention.dry_run=false to actually enforce policies".to_string(),
            );
        }
        if self.retention.enabled && self.retention.rules.is_empty() {
            warnings.push(
                "retention.enabled=true but no retention rules configured — retention scheduler will run but do nothing. Add [retention.rules] or set retention.enabled=false".to_string(),
            );
        }

        // 8. Curation validation.
        // Compute once: is any first-seen quarantine active (global or per-registry)?
        // Used by both the enforce "at least one control" check and the
        // min-release-age age-control requirement below.
        // Exhaustive over RegistryType via any_quarantine_active (a compiler-enforced
        // match): the hand-rolled OR-chain here previously omitted docker, so a
        // docker-only [curation.docker] quarantine read as "inactive" and falsely
        // failed this validation (#765). Counts a registry iff its effective mode
        // (per-registry override .or(global)) is not Off — the same value the
        // handlers and the main.rs store gate use.
        let quarantine_active = self.any_quarantine_active();

        // Enforce mode must have at least ONE active control, otherwise it blocks
        // nothing. An allowlist is one option, not the only one — a blocklist,
        // min-release-age, an active quarantine, namespace isolation, or integrity
        // checking each make enforce meaningful, so a deny-list-only / age-only /
        // quarantine-only policy is valid (#740).
        if self.curation.mode == CurationMode::Enforce {
            let any_control = self.curation.allowlist_path.is_some()
                || self.curation.blocklist_path.is_some()
                || self.curation.min_release_age.is_some()
                || quarantine_active
                || !self.curation.internal_namespaces.is_empty()
                || self.curation.require_integrity;
            if !any_control {
                errors.push(
                    "curation.mode=enforce but no active control is configured — enforce would block nothing. Set at least one of: allowlist_path, blocklist_path, min_release_age, quarantine, internal_namespaces, or require_integrity.".to_string(),
                );
            }
            if let Some(ref path) = self.curation.allowlist_path {
                if !std::path::Path::new(path).exists() {
                    errors.push(format!(
                        "curation.allowlist_path=\"{}\" does not exist (required for enforce mode)",
                        path
                    ));
                }
            }
        }
        if self.curation.bypass_token.is_some() && env::var("NORA_CURATION_BYPASS_TOKEN").is_err() {
            warnings.push(
                "curation.bypass_token is set in config file — consider using NORA_CURATION_BYPASS_TOKEN env var instead".to_string(),
            );
        }
        if self.curation.mode == CurationMode::Audit && self.curation.allowlist_path.is_none() {
            warnings.push(
                "curation.mode=audit but no allowlist_path configured — no allowlist filter will be active".to_string(),
            );
        }
        if self.curation.on_failure != CurationOnFailure::Closed {
            errors.push(
                "curation.on_failure=\"open\" is not implemented and would silently degrade to fail-closed. Remove the setting or set on_failure=\"closed\" explicitly. This field will be removed in v0.9".to_string(),
            );
        }
        // min_release_age on a proxy registry requires an active quarantine. On the
        // proxy path the upstream publish date is unsigned/spoofable AND, for most
        // registries, not resolvable at all (the date-bearing upstream metadata is
        // not cached at the curation point — the same root cause as #741), so
        // min-age DEFERS (Skip). server.trust_upstream_dates yields a real date only
        // where the registry caches one (npm); for pypi/cargo/nuget/gems/… it stays
        // None and min-age silently does nothing — so trust is NOT a sufficient age
        // control, only the unspoofable quarantine is. Refuse min-age on an enabled
        // proxy without a quarantine (curation-minage-real-age-defer, #741).
        {
            // Exhaustive over RegistryType via is_enabled_proxy (a compiler-enforced
            // match): adding a registry variant forces a new arm, so this guard can
            // never silently forget one again. The hand-rolled list here previously
            // omitted docker, leaving a docker-only proxy with min_release_age and no
            // quarantine unwarned (#741 follow-up).
            let any_enabled_proxy = RegistryType::all()
                .iter()
                .any(|&rt| self.is_enabled_proxy(rt));
            if self.curation.min_release_age.is_some() && !quarantine_active && any_enabled_proxy {
                errors.push(
                    "curation.min_release_age is set with an enabled proxy registry but no age control would be active: on the proxy path an upstream publish date is unsigned/spoofable and is not resolved for most registries, so min-release-age silently does nothing without a quarantine. Enable curation.quarantine=\"observe\"|\"enforce\" (the unspoofable first-seen age control). server.trust_upstream_dates enhances min-release-age with real upstream dates where a registry caches one (e.g. npm) but is NOT a substitute for the quarantine. (#741)".to_string(),
                );
            }
        }

        // 9. Docker upstream prefix validation
        {
            const RESERVED_PREFIXES: &[&str] =
                &["blobs", "manifests", "tags", "uploads", "_catalog", "v2"];
            let mut seen_prefixes = std::collections::HashSet::new();
            for (i, upstream) in self.docker.upstreams.iter().enumerate() {
                if let Some(ref prefix) = upstream.prefix {
                    if prefix.is_empty() {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix must not be empty (omit the field instead)",
                            i
                        ));
                    } else if prefix.contains('/') {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" must not contain '/'",
                            i, prefix
                        ));
                    } else if prefix != &prefix.to_lowercase() {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" must be lowercase (Docker names are lowercase)",
                            i, prefix
                        ));
                    } else if RESERVED_PREFIXES.contains(&prefix.as_str()) {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" is a reserved Docker API path segment",
                            i, prefix
                        ));
                    } else if !seen_prefixes.insert(prefix.clone()) {
                        errors.push(format!(
                            "docker.upstreams[{}]: duplicate prefix \"{}\"",
                            i, prefix
                        ));
                    }
                }
            }
        }

        // 9b. Docker default_action=deny without any prefixed upstream is a no-op trap
        if self.docker.default_action == DefaultAction::Deny
            && self.docker.enabled
            && !self.docker.upstreams.iter().any(|u| u.prefix.is_some())
        {
            warnings.push(
                "docker.default_action=\"deny\" but no upstream has a prefix configured — \
                 all requests will be denied. Add prefix= to at least one [[docker.upstreams]]"
                    .to_string(),
            );
        }

        // 10. [registries].enable validation
        if let Some(ref section) = self.registries {
            if let Some(ref spec) = section.enable {
                if let Err(e) = spec.resolve() {
                    errors.push(format!("[registries].enable: {}", e));
                }
            }
        }

        (warnings, errors)
    }

    /// Load configuration with priority: ENV > config file > defaults
    ///
    /// Config file resolution order:
    /// 1. `NORA_CONFIG_PATH` env var (fatal if set but file not found)
    /// 2. `config.toml` in current working directory (optional)
    /// 3. Built-in defaults
    pub fn load() -> Self {
        // 1. Start with defaults
        // 2. Override with config file if exists
        let mut config: Config = if let Ok(config_path) = env::var("NORA_CONFIG_PATH") {
            let content = fs::read_to_string(&config_path).unwrap_or_else(|e| {
                panic!(
                    "NORA_CONFIG_PATH={} but file cannot be read: {}",
                    config_path, e
                );
            });
            let cfg = toml::from_str(&content).unwrap_or_else(|e| {
                panic!(
                    "NORA_CONFIG_PATH={} contains invalid TOML: {}",
                    config_path, e
                );
            });
            tracing::info!(path = %config_path, "Loaded config from NORA_CONFIG_PATH");
            cfg
        } else {
            match fs::read_to_string("config.toml") {
                Ok(content) => match toml::from_str(&content) {
                    Ok(cfg) => {
                        tracing::info!("Loaded config from config.toml");
                        cfg
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "config.toml exists but contains invalid TOML, using defaults");
                        Config::default()
                    }
                },
                Err(_) => Config::default(),
            }
        };

        // 3. Override with ENV vars (highest priority)
        if let Err(e) = config.apply_env_overrides() {
            panic!("Fatal env override error: {}", e);
        }

        // 4. Validate configuration
        let (warnings, errors) = config.validate();
        for w in &warnings {
            tracing::warn!("Config validation: {}", w);
        }
        if !errors.is_empty() {
            for e in &errors {
                tracing::error!("Config validation: {}", e);
            }
            panic!("Fatal configuration errors: {}", errors.join("; "));
        }

        config
    }

    /// Non-panicking config reload for SIGHUP handler.
    /// Returns Err on invalid file/TOML/validation instead of panicking.
    pub fn try_load() -> Result<Self, String> {
        let mut config: Config = if let Ok(config_path) = env::var("NORA_CONFIG_PATH") {
            let content = fs::read_to_string(&config_path)
                .map_err(|e| format!("Cannot read {}: {}", config_path, e))?;
            toml::from_str(&content)
                .map_err(|e| format!("Invalid TOML in {}: {}", config_path, e))?
        } else {
            match fs::read_to_string("config.toml") {
                Ok(content) => toml::from_str(&content)
                    .map_err(|e| format!("Invalid TOML in config.toml: {}", e))?,
                Err(_) => Config::default(),
            }
        };
        config.apply_env_overrides()?;
        let (_, errors) = config.validate();
        if !errors.is_empty() {
            return Err(format!("Validation errors: {}", errors.join("; ")));
        }
        Ok(config)
    }

    /// Apply environment variable overrides.
    ///
    /// Returns `Err` if a security-critical enum (curation mode, quarantine mode,
    /// audit mode, storage mode) has an unrecognized value — typos must not silently
    /// disable security or misconfigure storage.
    fn apply_env_overrides(&mut self) -> Result<(), String> {
        // Server + TLS
        self.server.apply_env_overrides();
        self.tls.apply_env_overrides();

        // Storage (fail-closed: unknown NORA_STORAGE_MODE is fatal)
        self.storage.apply_env_overrides()?;

        // Auth
        self.auth.apply_env_overrides();

        // Registry configs (each handles its own NORA_*_ENABLED + format-specific vars)
        self.docker.apply_env_overrides();
        self.maven.apply_env_overrides();
        self.npm.apply_env_overrides();
        self.pypi.apply_env_overrides();
        self.go.apply_env_overrides();
        self.cargo.apply_env_overrides();
        self.raw.apply_env_overrides();
        self.gems.apply_env_overrides();
        self.terraform.apply_env_overrides();
        self.ansible.apply_env_overrides();
        self.nuget.apply_env_overrides();
        self.pub_dart.apply_env_overrides();
        self.conan.apply_env_overrides();
        self.rpm.apply_env_overrides();
        self.deb.apply_env_overrides();

        // Rate limit, GC, retention
        self.rate_limit.apply_env_overrides();
        self.signing.apply_env_overrides();
        self.gc.apply_env_overrides();
        self.retention.apply_env_overrides();

        // Secrets — SecretsConfig lives in crate::secrets, no apply_env_overrides method
        if let Ok(val) = env::var("NORA_SECRETS_PROVIDER") {
            self.secrets.provider = val;
        }
        if let Ok(val) = env::var("NORA_SECRETS_CLEAR_ENV") {
            self.secrets.clear_env = val.to_lowercase() == "true" || val == "1";
        }

        // Security-critical: parse errors are fatal (fail-fatal security enums)
        self.curation.apply_env_overrides()?;
        self.circuit_breaker.apply_env_overrides();
        self.audit.apply_env_overrides()?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::digest_quarantine::QuarantineMode;
    use crate::secrets::ProtectedString;
    use std::sync::{LazyLock, Mutex};

    /// Serializes tests that manipulate `NORA_CURATION_*` env vars.
    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn test_rate_limit_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.auth_rps, 1);
        assert_eq!(config.auth_burst, 5);
        assert_eq!(config.upload_rps, 200);
        assert_eq!(config.upload_burst, 500);
        assert_eq!(config.general_rps, 100);
        assert_eq!(config.general_burst, 200);
    }

    #[test]
    fn test_rate_limit_from_toml() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [rate_limit]
            auth_rps = 10
            upload_burst = 1000
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.rate_limit.auth_rps, 10);
        assert_eq!(config.rate_limit.upload_burst, 1000);
        assert_eq!(config.rate_limit.auth_burst, 5); // default
    }

    #[test]
    fn test_basic_auth_header() {
        let header = basic_auth_header("user:pass");
        assert_eq!(header, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_basic_auth_header_empty() {
        let header = basic_auth_header("");
        assert!(header.starts_with("Basic "));
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.server.body_limit_mb, 2048);
        assert!(config.server.public_url.is_none());
        assert_eq!(config.storage.path, "data/storage");
        assert_eq!(config.storage.mode, StorageMode::Local);
        assert_eq!(config.storage.bucket, "registry");
        assert_eq!(config.storage.s3_region, "us-east-1");
        assert!(!config.auth.enabled);
        assert_eq!(config.auth.htpasswd_file, "users.htpasswd");
        assert_eq!(config.auth.token_storage, "data/tokens");
    }

    #[test]
    fn test_maven_config_default() {
        let m = MavenConfig::default();
        assert_eq!(m.proxy_timeout, 30);
        assert_eq!(m.proxies.len(), 1);
        assert_eq!(m.proxies[0].url(), "https://repo1.maven.org/maven2");
        assert!(m.proxies[0].auth().is_none());
    }

    #[test]
    fn test_npm_config_default() {
        let n = NpmConfig::default();
        assert_eq!(n.proxy, Some("https://registry.npmjs.org".to_string()));
        assert!(n.proxy_auth.is_none());
        assert_eq!(n.proxy_timeout, 30);
        assert_eq!(n.metadata_ttl, 300);
    }

    #[test]
    fn test_pypi_config_default() {
        let p = PypiConfig::default();
        assert_eq!(p.proxy, Some("https://pypi.org/simple/".to_string()));
        assert!(p.proxy_auth.is_none());
        assert_eq!(p.proxy_timeout, 30);
    }

    #[test]
    fn test_docker_config_default() {
        let d = DockerConfig::default();
        assert_eq!(d.proxy_timeout, 300);
        assert_eq!(d.upstreams.len(), 1);
        assert_eq!(d.upstreams[0].url, "https://registry-1.docker.io");
        assert!(d.upstreams[0].auth.is_none());
    }

    #[test]
    fn test_raw_config_default() {
        let r = RawConfig::default();
        assert!(r.enabled);
        assert_eq!(r.max_file_size, 104_857_600);
    }

    #[test]
    fn test_auth_config_default() {
        let a = AuthConfig::default();
        assert!(!a.enabled);
        assert!(!a.anonymous_read);
        assert_eq!(a.htpasswd_file, "users.htpasswd");
        assert_eq!(a.token_storage, "data/tokens");
    }

    #[test]
    fn test_auth_anonymous_read_from_toml() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            anonymous_read = true
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.auth.enabled);
        assert!(config.auth.anonymous_read);
    }

    #[test]
    fn test_env_override_anonymous_read() {
        let mut config = Config::default();
        std::env::set_var("NORA_AUTH_ANONYMOUS_READ", "true");
        config.apply_env_overrides().unwrap();
        assert!(config.auth.anonymous_read);
        std::env::remove_var("NORA_AUTH_ANONYMOUS_READ");
    }

    #[test]
    fn test_docker_anon_pull_defaults_false() {
        // Fail-closed: absent from config => off, and independent of anonymous_read.
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            anonymous_read = true
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.auth.anonymous_read);
        assert!(
            !config.auth.docker_anon_pull,
            "docker_anon_pull must NOT be implied by anonymous_read"
        );
    }

    #[test]
    fn test_docker_anon_pull_from_toml() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            docker_anon_pull = true
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.auth.docker_anon_pull);
        assert!(!config.auth.anonymous_read);
    }

    #[test]
    fn test_env_override_docker_anon_pull() {
        let mut config = Config::default();
        std::env::set_var("NORA_AUTH_DOCKER_ANON_PULL", "true");
        config.apply_env_overrides().unwrap();
        assert!(config.auth.docker_anon_pull);
        std::env::remove_var("NORA_AUTH_DOCKER_ANON_PULL");
    }

    #[test]
    fn test_maven_proxy_entry_simple() {
        let entry = MavenProxyEntry::Simple("https://repo.example.com".to_string());
        assert_eq!(entry.url(), "https://repo.example.com");
        assert!(entry.auth().is_none());
    }

    #[test]
    fn test_maven_proxy_entry_full() {
        let entry = MavenProxyEntry::Full(MavenProxy {
            url: "https://private.repo.com".to_string(),
            auth: Some(ProtectedString::from("user:secret")),
        });
        assert_eq!(entry.url(), "https://private.repo.com");
        assert_eq!(entry.auth(), Some("user:secret"));
    }

    #[test]
    fn test_maven_proxy_entry_full_no_auth() {
        let entry = MavenProxyEntry::Full(MavenProxy {
            url: "https://repo.com".to_string(),
            auth: None,
        });
        assert_eq!(entry.url(), "https://repo.com");
        assert!(entry.auth().is_none());
    }

    #[test]
    fn test_storage_mode_default() {
        let mode = StorageMode::default();
        assert_eq!(mode, StorageMode::Local);
    }

    #[test]
    fn test_env_override_server() {
        let mut config = Config::default();
        std::env::set_var("NORA_HOST", "0.0.0.0");
        std::env::set_var("NORA_PORT", "8080");
        std::env::set_var("NORA_PUBLIC_URL", "registry.example.com");
        std::env::set_var("NORA_BODY_LIMIT_MB", "4096");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(
            config.server.public_url,
            Some("registry.example.com".to_string())
        );
        assert_eq!(config.server.body_limit_mb, 4096);
        std::env::remove_var("NORA_HOST");
        std::env::remove_var("NORA_PORT");
        std::env::remove_var("NORA_PUBLIC_URL");
        std::env::remove_var("NORA_BODY_LIMIT_MB");
    }

    #[test]
    fn test_env_override_storage() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_STORAGE_MODE", "s3");
        std::env::set_var("NORA_STORAGE_PATH", "/data/nora");
        std::env::set_var("NORA_STORAGE_BUCKET", "my-bucket");
        std::env::set_var("NORA_STORAGE_S3_REGION", "eu-west-1");
        std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "true");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.storage.mode, StorageMode::S3);
        assert_eq!(config.storage.path, "/data/nora");
        assert_eq!(config.storage.bucket, "my-bucket");
        assert_eq!(config.storage.s3_region, "eu-west-1");
        assert!(config.storage.s3_virtual_hosted);
        std::env::remove_var("NORA_STORAGE_MODE");
        std::env::remove_var("NORA_STORAGE_PATH");
        std::env::remove_var("NORA_STORAGE_BUCKET");
        std::env::remove_var("NORA_STORAGE_S3_REGION");
        std::env::remove_var("NORA_STORAGE_S3_VIRTUAL_HOSTED");
    }

    #[test]
    fn test_env_override_storage_virtual_hosted_default_off() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        config.apply_env_overrides().unwrap();
        assert!(!config.storage.s3_virtual_hosted);
        std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "false");
        config.apply_env_overrides().unwrap();
        assert!(!config.storage.s3_virtual_hosted);
        std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "1");
        config.apply_env_overrides().unwrap();
        assert!(config.storage.s3_virtual_hosted);
        std::env::remove_var("NORA_STORAGE_S3_VIRTUAL_HOSTED");
    }

    #[test]
    fn test_env_override_storage_mode_local() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_STORAGE_MODE", "local");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.storage.mode, StorageMode::Local);
        std::env::remove_var("NORA_STORAGE_MODE");
    }

    #[test]
    fn test_env_override_storage_mode_case_insensitive() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_STORAGE_MODE", "S3");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.storage.mode, StorageMode::S3);
        std::env::remove_var("NORA_STORAGE_MODE");
    }

    #[test]
    fn test_env_override_storage_mode_rejects_unknown() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_STORAGE_MODE", "redis");
        let result = config.apply_env_overrides();
        assert!(result.is_err(), "unknown storage mode must be rejected");
        assert!(result.unwrap_err().contains("NORA_STORAGE_MODE"));
        std::env::remove_var("NORA_STORAGE_MODE");
    }

    #[test]
    fn test_parse_env_warn_valid_u16() {
        let mut port: u16 = 5000;
        parse_env_warn("NORA_PORT", "8080", &mut port);
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_env_warn_invalid_keeps_original() {
        let mut port: u16 = 5000;
        parse_env_warn("NORA_PORT", "not-a-number", &mut port);
        assert_eq!(port, 5000, "invalid parse must keep original value");
    }

    #[test]
    fn test_parse_env_warn_empty_keeps_original() {
        let mut timeout: u64 = 30;
        parse_env_warn("NORA_TIMEOUT", "", &mut timeout);
        assert_eq!(timeout, 30, "empty string must keep original value");
    }

    #[test]
    fn test_env_override_auth() {
        let mut config = Config::default();
        std::env::set_var("NORA_AUTH_ENABLED", "true");
        std::env::set_var("NORA_AUTH_HTPASSWD_FILE", "/etc/nora/users");
        std::env::set_var("NORA_AUTH_TOKEN_STORAGE", "/data/tokens");
        config.apply_env_overrides().unwrap();
        assert!(config.auth.enabled);
        assert_eq!(config.auth.htpasswd_file, "/etc/nora/users");
        assert_eq!(config.auth.token_storage, "/data/tokens");
        std::env::remove_var("NORA_AUTH_ENABLED");
        std::env::remove_var("NORA_AUTH_HTPASSWD_FILE");
        std::env::remove_var("NORA_AUTH_TOKEN_STORAGE");
    }

    #[test]
    fn test_env_override_maven_proxies() {
        let mut config = Config::default();
        std::env::set_var(
            "NORA_MAVEN_PROXIES",
            "https://repo1.com,https://repo2.com|user:pass",
        );
        config.apply_env_overrides().unwrap();
        assert_eq!(config.maven.proxies.len(), 2);
        assert_eq!(config.maven.proxies[0].url(), "https://repo1.com");
        assert!(config.maven.proxies[0].auth().is_none());
        assert_eq!(config.maven.proxies[1].url(), "https://repo2.com");
        assert_eq!(config.maven.proxies[1].auth(), Some("user:pass"));
        std::env::remove_var("NORA_MAVEN_PROXIES");
    }

    #[test]
    fn test_env_override_maven_checksum_and_immutable() {
        let mut config = Config::default();
        assert!(config.maven.checksum_verify); // default true
        assert!(config.maven.immutable_releases); // default true
        std::env::set_var("NORA_MAVEN_CHECKSUM_VERIFY", "false");
        std::env::set_var("NORA_MAVEN_IMMUTABLE_RELEASES", "false");
        config.apply_env_overrides().unwrap();
        assert!(!config.maven.checksum_verify);
        assert!(!config.maven.immutable_releases);
        std::env::remove_var("NORA_MAVEN_CHECKSUM_VERIFY");
        std::env::remove_var("NORA_MAVEN_IMMUTABLE_RELEASES");
    }

    #[test]
    fn test_s3_default_url() {
        let config = Config::default();
        assert_eq!(config.storage.s3_url, "http://127.0.0.1:9000");
    }

    #[test]
    fn test_env_override_npm() {
        let mut config = Config::default();
        std::env::set_var("NORA_NPM_PROXY", "https://npm.company.com");
        std::env::set_var("NORA_NPM_PROXY_AUTH", "user:token");
        std::env::set_var("NORA_NPM_PROXY_TIMEOUT", "60");
        std::env::set_var("NORA_NPM_METADATA_TTL", "600");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            config.npm.proxy,
            Some("https://npm.company.com".to_string())
        );
        assert_eq!(
            crate::secrets::expose_opt(&config.npm.proxy_auth),
            Some("user:token")
        );
        assert_eq!(config.npm.proxy_timeout, 60);
        assert_eq!(config.npm.metadata_ttl, 600);
        std::env::remove_var("NORA_NPM_PROXY");
        std::env::remove_var("NORA_NPM_PROXY_AUTH");
        std::env::remove_var("NORA_NPM_PROXY_TIMEOUT");
        std::env::remove_var("NORA_NPM_METADATA_TTL");
    }

    #[test]
    fn test_env_override_raw() {
        let mut config = Config::default();
        std::env::set_var("NORA_RAW_ENABLED", "false");
        std::env::set_var("NORA_RAW_MAX_FILE_SIZE", "524288000");
        std::env::set_var("NORA_RAW_CACHE_CONTROL", "no-cache");
        config.apply_env_overrides().unwrap();
        assert!(!config.raw.enabled);
        assert_eq!(config.raw.max_file_size, 524288000);
        assert_eq!(config.raw.cache_control, "no-cache");
        std::env::remove_var("NORA_RAW_ENABLED");
        std::env::remove_var("NORA_RAW_MAX_FILE_SIZE");
        std::env::remove_var("NORA_RAW_CACHE_CONTROL");
    }

    #[test]
    fn test_env_override_rate_limit() {
        let mut config = Config::default();
        std::env::set_var("NORA_RATE_LIMIT_ENABLED", "false");
        std::env::set_var("NORA_RATE_LIMIT_AUTH_RPS", "10");
        std::env::set_var("NORA_RATE_LIMIT_GENERAL_BURST", "500");
        config.apply_env_overrides().unwrap();
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.auth_rps, 10);
        assert_eq!(config.rate_limit.general_burst, 500);
        std::env::remove_var("NORA_RATE_LIMIT_ENABLED");
        std::env::remove_var("NORA_RATE_LIMIT_AUTH_RPS");
        std::env::remove_var("NORA_RATE_LIMIT_GENERAL_BURST");
    }

    #[test]
    fn test_config_from_toml_full() {
        let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 8080
            public_url = "nora.example.com"
            body_limit_mb = 4096

            [storage]
            mode = "s3"
            path = "/data"
            s3_url = "http://s3.example.com:9000"
            bucket = "artifacts"
            s3_region = "eu-central-1"

            [auth]
            enabled = true
            htpasswd_file = "/etc/nora/users.htpasswd"

            [raw]
            enabled = false
            max_file_size = 500000000
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(
            config.server.public_url,
            Some("nora.example.com".to_string())
        );
        assert_eq!(config.server.body_limit_mb, 4096);
        assert_eq!(config.storage.mode, StorageMode::S3);
        assert_eq!(config.storage.s3_url, "http://s3.example.com:9000");
        assert_eq!(config.storage.bucket, "artifacts");
        assert!(config.auth.enabled);
        assert!(!config.raw.enabled);
        assert_eq!(config.raw.max_file_size, 500000000);
    }

    #[test]
    fn test_config_from_toml_minimal() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        // Defaults should be filled
        assert_eq!(config.storage.path, "data/storage");
        assert_eq!(config.maven.proxies.len(), 1);
        assert_eq!(
            config.npm.proxy,
            Some("https://registry.npmjs.org".to_string())
        );
        assert_eq!(config.docker.upstreams.len(), 1);
        assert!(config.raw.enabled);
        assert!(!config.auth.enabled);
    }

    #[test]
    fn test_config_from_toml_partial() {
        // Missing host and port in [server] — should use defaults
        let toml = r#"
            [server]
            [storage]
            mode = "local"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.storage.path, "data/storage");

        // Missing [server] entirely — should use defaults
        let toml = r#"
            [storage]
            mode = "local"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 4000);

        // Missing [storage] entirely — should use defaults
        let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 8080
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.storage.mode, StorageMode::Local);
    }

    /// Assert that a config section's field-level serde-default path equals its
    /// `Default` impl — i.e. writing `[section]` with no keys behaves the same as
    /// omitting the section entirely. A bare `#[serde(default)]` on an `Option`
    /// field yields `None`, which silently diverges from a `Default` impl that
    /// returns `Some(..)` (the npm/pypi proxy bug). Comparison via
    /// `serde_json::Value` tolerates `ProtectedString` secrets (`skip_serializing`
    /// → absent on both sides) and auto-covers future fields.
    fn assert_serde_default_eq_default<T>(section: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Default,
    {
        let from_empty: T = toml::from_str("").unwrap_or_else(|e| {
            panic!(
                "[{section}] empty table must deserialize — every field needs a serde default: {e}"
            )
        });
        assert_eq!(
            serde_json::to_value(&from_empty).unwrap(),
            serde_json::to_value(T::default()).unwrap(),
            "[{section}]: serde field-defaults diverge from the Default impl — a present-but-empty \
             [{section}] table behaves differently from omitting the section",
        );
    }

    /// Invariant (whole class, not just the leaves that were caught): for EVERY
    /// config section, the field-level `#[serde(default)]` path and the `Default`
    /// impl must agree, so `[section]` with no keys == omitting `[section]`. The
    /// only way to drift is a `serde(default = ...)`/`Default` mismatch — this
    /// fails loudly if it ever happens. Previously this only covered
    /// server/storage, which let the npm/pypi `proxy` divergence through.
    #[test]
    fn test_serde_defaults_match_default_impl() {
        assert_serde_default_eq_default::<ServerConfig>("server");
        assert_serde_default_eq_default::<StorageConfig>("storage");
        // All 13 registries — this is where the proxy-default class lives.
        assert_serde_default_eq_default::<MavenConfig>("maven");
        assert_serde_default_eq_default::<NpmConfig>("npm");
        assert_serde_default_eq_default::<PypiConfig>("pypi");
        assert_serde_default_eq_default::<DockerConfig>("docker");
        assert_serde_default_eq_default::<GoConfig>("go");
        assert_serde_default_eq_default::<CargoConfig>("cargo");
        assert_serde_default_eq_default::<RawConfig>("raw");
        assert_serde_default_eq_default::<GemsConfig>("gems");
        assert_serde_default_eq_default::<TerraformConfig>("terraform");
        assert_serde_default_eq_default::<AnsibleConfig>("ansible");
        assert_serde_default_eq_default::<NugetConfig>("nuget");
        assert_serde_default_eq_default::<PubDartConfig>("pub_dart");
        assert_serde_default_eq_default::<ConanConfig>("conan");
        assert_serde_default_eq_default::<RpmConfig>("rpm");
        assert_serde_default_eq_default::<DebConfig>("deb");
        assert_serde_default_eq_default::<SigningConfig>("signing");

        // Whole-Config fallback agrees with deserializing an empty file.
        let from_empty_cfg: Config = toml::from_str("").unwrap();
        assert_eq!(from_empty_cfg.server, ServerConfig::default());
    }

    /// The config shipped in the container image (deploy/config.docker.toml,
    /// loaded via NORA_CONFIG_PATH) must be valid for THIS struct and yield the
    /// intended container defaults — so the image is zero-config out of the box
    /// without baking config values as env (#719). A renamed/typo'd key would
    /// otherwise fall back to a default silently, reintroducing the bug. Host is
    /// deliberately absent (the container sets it via NORA_HOST).
    #[test]
    fn test_shipped_docker_config_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/config.docker.toml");
        let content =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let config: Config = toml::from_str(&content).unwrap();
        assert_eq!(config.server.port, 4000);
        assert_eq!(
            config.server.public_url.as_deref(),
            Some("http://localhost:4000")
        );
        assert_eq!(config.storage.mode, StorageMode::Local);
        assert_eq!(config.storage.path, "/data/storage");
        assert_eq!(config.auth.token_storage, "/data/tokens");
    }

    #[test]
    fn test_config_toml_docker_upstreams() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [docker]
            proxy_timeout = 120

            [[docker.upstreams]]
            url = "https://mirror.gcr.io"

            [[docker.upstreams]]
            url = "https://private.registry.io"
            auth = "user:pass"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.docker.proxy_timeout, 120);
        assert_eq!(config.docker.upstreams.len(), 2);
        assert!(config.docker.upstreams[0].auth.is_none());
        assert_eq!(
            crate::secrets::expose_opt(&config.docker.upstreams[1].auth),
            Some("user:pass")
        );
    }

    #[test]
    fn test_validate_default_config_ok() {
        let config = Config::default();
        let (warnings, errors) = config.validate();
        assert!(
            errors.is_empty(),
            "default config should have no errors: {:?}",
            errors
        );
        assert!(
            warnings.is_empty(),
            "default config should have no warnings: {:?}",
            warnings
        );
    }

    #[test]
    fn test_is_loopback_host() {
        // loopback forms (caller strips IPv6 brackets before calling)
        assert!(Config::is_loopback_host("127.0.0.1"));
        assert!(Config::is_loopback_host("127.1.2.3")); // whole 127.0.0.0/8
        assert!(Config::is_loopback_host("::1"));
        assert!(Config::is_loopback_host("localhost"));
        assert!(Config::is_loopback_host("LocalHost")); // case-insensitive (#590 review)
                                                        // not loopback
        assert!(!Config::is_loopback_host("0.0.0.0")); // wildcard → handled as error elsewhere
        assert!(!Config::is_loopback_host("192.168.1.10"));
        assert!(!Config::is_loopback_host("8.8.8.8"));
        assert!(!Config::is_loopback_host("registry.example.com"));
    }

    #[test]
    fn test_validate_public_url_loopback_warns() {
        // public_url explicitly pointing at loopback is broken for remote clients (#590):
        // a warning, not an error, since local-only use is valid. Tested through
        // validate() (not is_loopback_host directly) to cover the real host_str() path,
        // including IPv6 literals whose brackets must be stripped (#590 review).
        for url in [
            "http://localhost:4000",
            "http://127.0.0.1:4000",
            "http://[::1]:4000",
        ] {
            let mut config = Config::default();
            config.server.public_url = Some(url.to_string());
            let (warnings, errors) = config.validate_with_config_path(None);
            assert!(
                errors.is_empty(),
                "loopback public_url '{url}' is a warning, not an error: {:?}",
                errors
            );
            assert!(
                warnings.iter().any(|w| w.contains("loopback")),
                "expected loopback warning for public_url '{url}': {:?}",
                warnings
            );
        }
    }

    #[test]
    fn test_validate_port_zero() {
        let mut config = Config::default();
        config.server.port = 0;
        let (_, errors) = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("port"));
    }

    #[test]
    fn test_validate_empty_storage_path_local() {
        let mut config = Config::default();
        config.storage.mode = StorageMode::Local;
        config.storage.path = String::new();
        let (_, errors) = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("storage.path"));
    }

    #[test]
    fn test_validate_whitespace_storage_path_local() {
        let mut config = Config::default();
        config.storage.mode = StorageMode::Local;
        config.storage.path = "   ".to_string();
        let (_, errors) = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("storage.path"));
    }

    #[test]
    fn test_validate_empty_bucket_s3() {
        let mut config = Config::default();
        config.storage.mode = StorageMode::S3;
        config.storage.bucket = String::new();
        let (_, errors) = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("storage.bucket"));
    }

    #[test]
    fn test_validate_empty_storage_path_s3_ok() {
        // Empty path is fine when mode is S3
        let mut config = Config::default();
        config.storage.mode = StorageMode::S3;
        config.storage.path = String::new();
        let (_, errors) = config.validate();
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_rate_limit_zero_rps() {
        let mut config = Config::default();
        config.rate_limit.enabled = true;
        config.rate_limit.auth_rps = 0;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("auth_rps"));
    }

    #[test]
    fn test_validate_rate_limit_disabled_zero_ok() {
        // Zero rate limit values are fine when rate limiting is disabled
        let mut config = Config::default();
        config.rate_limit.enabled = false;
        config.rate_limit.auth_rps = 0;
        config.rate_limit.auth_burst = 0;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_rate_limit_all_zeros() {
        let mut config = Config::default();
        config.rate_limit.enabled = true;
        config.rate_limit.auth_rps = 0;
        config.rate_limit.auth_burst = 0;
        config.rate_limit.upload_rps = 0;
        config.rate_limit.upload_burst = 0;
        config.rate_limit.general_rps = 0;
        config.rate_limit.general_burst = 0;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 6);
    }

    #[test]
    fn test_validate_body_limit_zero() {
        let mut config = Config::default();
        config.server.body_limit_mb = 0;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("body_limit_mb"));
    }

    #[test]
    fn test_validate_multiple_errors() {
        let mut config = Config::default();
        config.server.port = 0;
        config.storage.mode = StorageMode::Local;
        config.storage.path = String::new();
        let (_, errors) = config.validate();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn test_validate_warnings_and_errors_together() {
        let mut config = Config::default();
        config.server.port = 0;
        config.server.body_limit_mb = 0;
        config.rate_limit.enabled = true;
        config.rate_limit.auth_rps = 0;
        let (warnings, errors) = config.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(warnings.len(), 2); // body_limit + auth_rps
    }
    #[test]
    fn test_validate_gc_enabled_dry_run() {
        let mut config = Config::default();
        config.gc.enabled = true;
        config.gc.dry_run = true;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("gc.dry_run"));
    }

    #[test]
    fn test_validate_gc_enabled_no_dry_run_ok() {
        let mut config = Config::default();
        config.gc.enabled = true;
        config.gc.dry_run = false;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_retention_enabled_empty_rules() {
        let mut config = Config::default();
        config.retention.enabled = true;
        config.retention.rules = Vec::new();
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("retention"));
    }

    #[test]
    fn test_validate_retention_enabled_with_rules_ok() {
        let mut config = Config::default();
        config.retention.enabled = true;
        config.retention.rules = vec![RetentionRule {
            registry: "docker".to_string(),
            keep_last: Some(5),
            older_than_days: None,
            exclude_tags: Vec::new(),
        }];
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_relative_paths_with_config_path() {
        let mut config = Config::default();
        config.auth.enabled = true;
        // default paths are relative: "data/storage", "data/tokens"
        let (warnings, _) =
            config.validate_with_config_path(Some("/tmp/test-config.toml".to_string()));
        assert!(
            warnings.iter().any(|w| w.contains("storage.path")),
            "should warn about relative storage.path"
        );
        assert!(
            warnings.iter().any(|w| w.contains("token_storage")),
            "should warn about relative token_storage"
        );
    }

    #[test]
    fn test_relative_token_storage_warns_without_config_path() {
        // #816: env-only (systemd) starts have config_path=None. A relative
        // token_storage with auth enabled must still warn — that is exactly the
        // case that escapes the sandbox and breaks token writes.
        let mut config = Config::default();
        config.auth.enabled = true; // default token_storage = "data/tokens" (relative)
        let (warnings, _) = config.validate_with_config_path(None);
        assert!(
            warnings.iter().any(|w| w.contains("token_storage")),
            "relative token_storage must warn even with no config file (env-only deploy)"
        );
        // The storage.path hint stays scoped to explicit-config starts (no noise on
        // the bare-serve relative default).
        assert!(
            !warnings.iter().any(|w| w.contains("storage.path")),
            "storage.path hint should remain gated behind an explicit config file"
        );
    }

    #[test]
    fn test_validate_absolute_paths_no_warning() {
        let mut config = Config::default();
        config.storage.path = "/data/storage".to_string();
        config.auth.enabled = true;
        config.auth.token_storage = "/data/tokens".to_string();
        let (warnings, _) =
            config.validate_with_config_path(Some("/tmp/test-config.toml".to_string()));
        assert!(
            !warnings.iter().any(|w| w.contains("storage.path")),
            "should not warn about absolute storage.path"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("token_storage")),
            "should not warn about absolute token_storage"
        );
    }

    #[test]
    fn test_env_override_docker_proxies_and_backward_compat() {
        // Test new NORA_DOCKER_PROXIES name
        std::env::remove_var("NORA_DOCKER_UPSTREAMS");
        std::env::set_var(
            "NORA_DOCKER_PROXIES",
            "https://mirror.gcr.io,https://private.io|token123",
        );
        let mut config = Config::default();
        config.apply_env_overrides().unwrap();
        assert_eq!(config.docker.upstreams.len(), 2);
        assert_eq!(config.docker.upstreams[0].url, "https://mirror.gcr.io");
        assert!(config.docker.upstreams[0].auth.is_none());
        assert_eq!(config.docker.upstreams[1].url, "https://private.io");
        assert_eq!(
            crate::secrets::expose_opt(&config.docker.upstreams[1].auth),
            Some("token123")
        );
        std::env::remove_var("NORA_DOCKER_PROXIES");

        // Test backward compat: old NORA_DOCKER_UPSTREAMS still works
        std::env::remove_var("NORA_DOCKER_PROXIES");
        std::env::set_var("NORA_DOCKER_UPSTREAMS", "https://legacy.io|secret");
        let mut config2 = Config::default();
        config2.apply_env_overrides().unwrap();
        assert_eq!(config2.docker.upstreams.len(), 1);
        assert_eq!(config2.docker.upstreams[0].url, "https://legacy.io");
        assert_eq!(
            crate::secrets::expose_opt(&config2.docker.upstreams[0].auth),
            Some("secret")
        );
        std::env::remove_var("NORA_DOCKER_UPSTREAMS");
    }

    #[test]
    fn test_env_override_go_proxy() {
        let mut config = Config::default();
        std::env::set_var("NORA_GO_PROXY", "https://goproxy.company.com");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            config.go.proxy,
            Some("https://goproxy.company.com".to_string()),
        );
        std::env::remove_var("NORA_GO_PROXY");
    }

    #[test]
    fn test_env_override_go_proxy_auth() {
        let mut config = Config::default();
        std::env::set_var("NORA_GO_PROXY_AUTH", "user:pass");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            crate::secrets::expose_opt(&config.go.proxy_auth),
            Some("user:pass")
        );
        std::env::remove_var("NORA_GO_PROXY_AUTH");
    }

    #[test]
    fn test_cargo_config_default() {
        let c = CargoConfig::default();
        assert_eq!(c.proxy, Some("https://crates.io".to_string()));
        assert_eq!(c.proxy_timeout, 30);
    }

    #[test]
    fn test_config_file_sets_s3_mode_without_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Regression test for issue #4: config.toml mode="s3" must work
        // without NORA_STORAGE_MODE env var (previously overridden by
        // Dockerfile ENV NORA_STORAGE_MODE=local)
        std::env::remove_var("NORA_STORAGE_MODE");

        let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 4000

            [storage]
            mode = "s3"
            s3_url = "http://s3.example.com:9000"
            bucket = "nora"
        "#;

        let mut config: Config = toml::from_str(toml).unwrap();
        config.apply_env_overrides().unwrap();
        assert_eq!(
            config.storage.mode,
            StorageMode::S3,
            "config.toml mode=s3 must not be overridden when NORA_STORAGE_MODE is unset"
        );
    }

    // ========================================================================
    // Curation config tests
    // ========================================================================

    #[test]
    fn test_curation_config_default() {
        let c = CurationConfig::default();
        assert_eq!(c.mode, CurationMode::Off);
        assert_eq!(c.on_failure, CurationOnFailure::Closed);
        assert!(c.allowlist_path.is_none());
        assert!(c.blocklist_path.is_none());
        assert!(c.bypass_token.is_none());
        assert!(!c.require_integrity);
    }

    #[test]
    fn test_curation_config_from_toml() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            mode = "audit"
            on_failure = "open"
            require_integrity = true
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.curation.mode, CurationMode::Audit);
        assert_eq!(config.curation.on_failure, CurationOnFailure::Open);
        assert!(config.curation.require_integrity);
        assert_eq!(config.curation.quarantine, None);
    }

    #[test]
    fn test_curation_quarantine_from_toml() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            quarantine = "enforce"
            quarantine_ttl = "14d"

            [curation.docker]
            quarantine = "observe"
            quarantine_ttl = "7d"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.curation.quarantine, Some(QuarantineMode::Enforce));
        assert_eq!(config.curation.quarantine_ttl, Some("14d".to_string()));
        assert_eq!(
            config.curation.docker.quarantine,
            Some(QuarantineMode::Observe)
        );
        assert_eq!(
            config.curation.docker.quarantine_ttl,
            Some("7d".to_string())
        );
        // Other registries should be None
        assert_eq!(config.curation.npm.quarantine, None);
    }

    #[test]
    fn test_curation_config_missing_defaults_to_off() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.curation.mode, CurationMode::Off);
    }

    #[test]
    fn test_curation_env_override_mode() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_MODE", "enforce");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.curation.mode, CurationMode::Enforce);
        std::env::remove_var("NORA_CURATION_MODE");
    }

    #[test]
    fn test_curation_env_override_on_failure() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_ON_FAILURE", "open");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.curation.on_failure, CurationOnFailure::Open);
        std::env::remove_var("NORA_CURATION_ON_FAILURE");
    }

    #[test]
    fn test_curation_on_failure_open_emits_error() {
        let mut config = Config::default();
        config.curation.on_failure = CurationOnFailure::Open;
        let (_warnings, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("on_failure=\"open\" is not implemented")),
            "expected hard error for on_failure=open"
        );
    }

    #[test]
    fn test_curation_env_override_paths() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_ALLOWLIST_PATH", "/etc/nora/allow.json");
        std::env::set_var("NORA_CURATION_BLOCKLIST_PATH", "/etc/nora/block.json");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            config.curation.allowlist_path,
            Some("/etc/nora/allow.json".to_string())
        );
        assert_eq!(
            config.curation.blocklist_path,
            Some("/etc/nora/block.json".to_string())
        );
        std::env::remove_var("NORA_CURATION_ALLOWLIST_PATH");
        std::env::remove_var("NORA_CURATION_BLOCKLIST_PATH");
    }

    #[test]
    fn test_curation_env_override_bypass_token() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_BYPASS_TOKEN", "secret-bypass");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            crate::secrets::expose_opt(&config.curation.bypass_token),
            Some("secret-bypass")
        );
        std::env::remove_var("NORA_CURATION_BYPASS_TOKEN");
    }

    #[test]
    fn test_curation_env_override_require_integrity() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_REQUIRE_INTEGRITY", "true");
        config.apply_env_overrides().unwrap();
        assert!(config.curation.require_integrity);
        std::env::remove_var("NORA_CURATION_REQUIRE_INTEGRITY");
    }

    #[test]
    fn test_curation_env_override_quarantine() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_QUARANTINE", "observe");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.curation.quarantine, Some(QuarantineMode::Observe));
        std::env::remove_var("NORA_CURATION_QUARANTINE");
    }

    #[test]
    fn test_curation_env_override_quarantine_ttl() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_QUARANTINE_TTL", "14d");
        config.apply_env_overrides().unwrap();
        assert_eq!(config.curation.quarantine_ttl, Some("14d".to_string()));
        std::env::remove_var("NORA_CURATION_QUARANTINE_TTL");
    }

    #[test]
    fn test_curation_env_override_per_registry_quarantine() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_DOCKER_QUARANTINE", "enforce");
        std::env::set_var("NORA_CURATION_DOCKER_QUARANTINE_TTL", "7d");
        config.apply_env_overrides().unwrap();
        assert_eq!(
            config.curation.docker.quarantine,
            Some(QuarantineMode::Enforce)
        );
        assert_eq!(
            config.curation.docker.quarantine_ttl,
            Some("7d".to_string())
        );
        // Global should remain None
        assert_eq!(config.curation.quarantine, None);
        std::env::remove_var("NORA_CURATION_DOCKER_QUARANTINE");
        std::env::remove_var("NORA_CURATION_DOCKER_QUARANTINE_TTL");
    }

    #[test]
    fn test_quarantine_toml_rejects_typo() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            quarantine = "eforce"
        "#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err(), "typo 'eforce' should be rejected by serde");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown variant"),
            "error should mention unknown variant: {err}"
        );
    }

    #[test]
    fn test_curation_mode_env_rejects_typo() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_MODE", "enforec");
        let result = config.apply_env_overrides();
        assert!(result.is_err(), "typo 'enforec' should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("NORA_CURATION_MODE"),
            "error should name the env var: {err}"
        );
        std::env::remove_var("NORA_CURATION_MODE");
    }

    #[test]
    fn test_quarantine_env_rejects_typo() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_QUARANTINE", "enfocre");
        let result = config.apply_env_overrides();
        assert!(result.is_err(), "typo 'enfocre' should be rejected");
        std::env::remove_var("NORA_CURATION_QUARANTINE");
    }

    #[test]
    fn test_curation_mode_fromstr() {
        assert_eq!("off".parse::<CurationMode>().unwrap(), CurationMode::Off);
        assert_eq!(
            "audit".parse::<CurationMode>().unwrap(),
            CurationMode::Audit
        );
        assert_eq!(
            "enforce".parse::<CurationMode>().unwrap(),
            CurationMode::Enforce
        );
        assert_eq!(
            "ENFORCE".parse::<CurationMode>().unwrap(),
            CurationMode::Enforce
        );
        assert!("typo".parse::<CurationMode>().is_err());
        assert!("".parse::<CurationMode>().is_err());
    }

    #[test]
    fn test_validate_curation_enforce_no_controls() {
        // Enforce with no control of any kind enforces nothing → error (#740).
        let mut config = Config::default();
        config.curation.mode = CurationMode::Enforce;
        config.curation.allowlist_path = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("no active control is configured")),
            "enforce with no controls should be an error"
        );
    }

    #[test]
    fn test_validate_curation_enforce_blocklist_only_ok() {
        // #740: enforce must NOT require an allowlist — a blocklist alone is a valid
        // control. A deny-list-only (or min-age-only / quarantine-only) policy is legit.
        let mut config = Config::default();
        config.curation.mode = CurationMode::Enforce;
        config.curation.allowlist_path = None;
        config.curation.blocklist_path = Some("/etc/nora/blocklist.json".to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("no active control is configured")),
            "a blocklist alone should satisfy enforce — no allowlist required"
        );
    }

    #[test]
    fn test_validate_minage_proxy_without_date_source_or_quarantine_rejected() {
        // min_release_age on an enabled proxy registry with neither
        // trust_upstream_dates nor an active quarantine = no age control would be
        // active => rejected (curation-minage-real-age-defer, #741).
        let mut config = Config::default();
        config.npm.enabled = true;
        config.npm.proxy = Some("https://registry.npmjs.org".to_string());
        config.curation.min_release_age = Some("7d".to_string());
        config.server.trust_upstream_dates = false;
        config.curation.quarantine = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("no age control would be active")),
            "min-age on a proxy with neither trust nor quarantine must be rejected"
        );
    }

    #[test]
    fn test_validate_minage_proxy_with_quarantine_ok() {
        // Escape hatch 1: an active quarantine is the unspoofable age control.
        let mut config = Config::default();
        config.npm.enabled = true;
        config.npm.proxy = Some("https://registry.npmjs.org".to_string());
        config.curation.min_release_age = Some("7d".to_string());
        config.server.trust_upstream_dates = false;
        config.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("no age control would be active")),
            "an active quarantine should satisfy the age-control requirement"
        );
    }

    #[test]
    fn test_validate_minage_proxy_trust_alone_still_rejected() {
        // trust_upstream_dates is NOT a sufficient substitute for the quarantine: it
        // yields a real date only where a registry caches one (npm); for pypi/cargo/
        // nuget/gems/… publish_date stays None and min-age silently does nothing, so
        // min-age on a proxy still requires an active quarantine. (#741)
        let mut config = Config::default();
        config.npm.enabled = true;
        config.npm.proxy = Some("https://registry.npmjs.org".to_string());
        config.curation.min_release_age = Some("7d".to_string());
        config.server.trust_upstream_dates = true;
        config.curation.quarantine = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("no age control would be active")),
            "trust alone (no quarantine) must still be rejected — trust is not a substitute"
        );
    }

    #[test]
    fn test_is_enabled_proxy_counts_docker_and_excludes_raw() {
        // #765: docker was dropped from the any_enabled_proxy chain. The exhaustive
        // helper must count docker (enabled + has upstream) and never count raw.
        let mut config = Config::default();
        // Config::default() already carries the registry-1.docker.io upstream.
        assert!(
            config.is_enabled_proxy(RegistryType::Docker),
            "enabled docker with an upstream is a proxy"
        );
        config.docker.upstreams = vec![];
        assert!(
            !config.is_enabled_proxy(RegistryType::Docker),
            "docker without upstreams is not a proxy"
        );
        assert!(
            !config.is_enabled_proxy(RegistryType::Raw),
            "raw has no upstream and is never a proxy"
        );
    }

    #[test]
    fn test_quarantine_mode_for_docker_precedence_and_raw_off() {
        // Per-registry override wins over global (.or precedence, matching
        // docker.rs::resolve_quarantine); raw is always Off (no enforcement path).
        let mut config = Config::default();
        config.curation.quarantine = Some(QuarantineMode::Off);
        config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
        assert_eq!(
            config.quarantine_mode_for(RegistryType::Docker),
            QuarantineMode::Enforce,
            "docker override Enforce beats global Off"
        );
        assert_eq!(
            config.quarantine_mode_for(RegistryType::Npm),
            QuarantineMode::Off,
            "npm with no override inherits global Off"
        );
        // raw stays Off even under a global Enforce — counting it would be a phantom control.
        config.curation.quarantine = Some(QuarantineMode::Enforce);
        assert_eq!(
            config.quarantine_mode_for(RegistryType::Raw),
            QuarantineMode::Off,
            "raw must never report an active quarantine"
        );
    }

    #[test]
    fn test_any_quarantine_active_counts_docker_only_override() {
        // #765 core: a docker-only [curation.docker] quarantine, no global, must count.
        // The main.rs DigestStore gate depends on this — otherwise it builds an
        // empty() (non-durable) store and serves young digests early after restart.
        let mut config = Config::default();
        config.curation.quarantine = None;
        config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
        assert!(
            config.any_quarantine_active(),
            "docker-only quarantine override must count as active"
        );
    }

    #[test]
    fn test_any_quarantine_active_false_when_global_fully_overridden_off() {
        // A global Enforce with EVERY registry overridden to Off enforces nothing,
        // so quarantine is not active. (The old flat-OR counted the global term and
        // wrongly reported active — which would suppress the #741 min-age guard.)
        let mut config = Config::default();
        config.curation.quarantine = Some(QuarantineMode::Enforce);
        for o in [
            &mut config.curation.docker,
            &mut config.curation.maven,
            &mut config.curation.npm,
            &mut config.curation.cargo,
            &mut config.curation.pypi,
            &mut config.curation.go,
            &mut config.curation.gems,
            &mut config.curation.terraform,
            &mut config.curation.ansible,
            &mut config.curation.nuget,
            &mut config.curation.pub_dart,
            &mut config.curation.conan,
        ] {
            o.quarantine = Some(QuarantineMode::Off);
        }
        assert!(
            !config.any_quarantine_active(),
            "global Enforce fully overridden to Off everywhere enforces nothing"
        );
    }

    #[test]
    fn test_validate_minage_docker_only_quarantine_ok() {
        // #765: a docker-only quarantine must SATISFY the #741 min-age guard. The
        // old quarantine_active chain omitted docker and falsely rejected this config.
        let mut config = Config::default();
        config.curation.min_release_age = Some("7d".to_string());
        config.server.trust_upstream_dates = false;
        config.curation.quarantine = None;
        config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("no age control would be active")),
            "a docker-only quarantine should satisfy the age-control requirement (#765)"
        );
    }

    #[test]
    fn test_validate_curation_enforce_missing_allowlist_file() {
        let mut config = Config::default();
        config.curation.mode = CurationMode::Enforce;
        config.curation.allowlist_path = Some("/nonexistent/allow.json".to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("does not exist")),
            "enforce with missing allowlist file should be an error"
        );
    }

    #[test]
    fn test_validate_curation_audit_no_allowlist_warning() {
        let mut config = Config::default();
        config.curation.mode = CurationMode::Audit;
        let (warnings, errors) = config.validate_with_config_path(None);
        assert!(errors.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("no allowlist_path")),
            "audit without allowlist should be a warning"
        );
    }

    #[test]
    fn test_validate_curation_off_no_warnings() {
        let config = Config::default();
        let (warnings, errors) = config.validate_with_config_path(None);
        assert!(errors.is_empty());
        assert!(
            !warnings.iter().any(|w| w.contains("curation")),
            "mode=off should produce no curation warnings"
        );
    }

    #[test]
    fn test_curation_mode_display() {
        assert_eq!(CurationMode::Off.to_string(), "off");
        assert_eq!(CurationMode::Audit.to_string(), "audit");
        assert_eq!(CurationMode::Enforce.to_string(), "enforce");
    }

    // ========================================================================
    // EnableSpec + [registries] tests
    // ========================================================================

    #[test]
    fn test_enable_spec_single_all() {
        let spec = EnableSpec::Single("all".to_string());
        let set = spec.resolve().unwrap();
        assert_eq!(set.len(), RegistryType::all().len());
        for rt in RegistryType::all() {
            assert!(set.contains(rt), "missing {:?}", rt);
        }
    }

    #[test]
    fn test_enable_spec_single_registry() {
        let spec = EnableSpec::Single("docker".to_string());
        let set = spec.resolve().unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&RegistryType::Docker));
    }

    #[test]
    fn test_enable_spec_list_explicit() {
        let spec = EnableSpec::List(vec![
            "docker".to_string(),
            "npm".to_string(),
            "pypi".to_string(),
        ]);
        let set = spec.resolve().unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&RegistryType::Docker));
        assert!(set.contains(&RegistryType::Npm));
        assert!(set.contains(&RegistryType::PyPI));
    }

    #[test]
    fn test_enable_spec_all_minus() {
        let spec = EnableSpec::List(vec!["all".to_string(), "-maven".to_string()]);
        let set = spec.resolve().unwrap();
        assert_eq!(set.len(), RegistryType::all().len() - 1);
        assert!(!set.contains(&RegistryType::Maven));
        assert!(set.contains(&RegistryType::Docker));
    }

    #[test]
    fn test_enable_spec_all_minus_multiple() {
        let spec = EnableSpec::List(vec![
            "all".to_string(),
            "-maven".to_string(),
            "-conan".to_string(),
        ]);
        let set = spec.resolve().unwrap();
        assert_eq!(set.len(), RegistryType::all().len() - 2);
        assert!(!set.contains(&RegistryType::Maven));
        assert!(!set.contains(&RegistryType::Conan));
    }

    #[test]
    fn test_enable_spec_unknown_error() {
        let spec = EnableSpec::Single("bogus".to_string());
        assert!(spec.resolve().is_err());
    }

    #[test]
    fn test_enable_spec_exclusion_without_all() {
        let spec = EnableSpec::List(vec!["docker".to_string(), "-maven".to_string()]);
        let err = spec.resolve().unwrap_err();
        assert!(err.contains("require \"all\""), "got: {}", err);
    }

    #[test]
    fn test_enable_spec_empty_error() {
        let spec = EnableSpec::List(vec![]);
        assert!(spec.resolve().is_err());
    }

    #[test]
    fn test_enable_spec_aliases() {
        let spec = EnableSpec::Single("rubygems".to_string());
        let set = spec.resolve().unwrap();
        assert!(set.contains(&RegistryType::Gems));

        let spec2 = EnableSpec::Single("dart".to_string());
        let set2 = spec2.resolve().unwrap();
        assert!(set2.contains(&RegistryType::PubDart));

        let spec3 = EnableSpec::Single("pub_dart".to_string());
        let set3 = spec3.resolve().unwrap();
        assert!(set3.contains(&RegistryType::PubDart));
    }

    #[test]
    fn test_enable_spec_all_with_inclusions_error() {
        let spec = EnableSpec::List(vec!["all".to_string(), "docker".to_string()]);
        let err = spec.resolve().unwrap_err();
        assert!(err.contains("cannot be combined"), "got: {}", err);
    }

    #[test]
    fn test_registries_toml_list() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["docker", "npm"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.registries.is_some());
        let section = config.registries.as_ref().unwrap();
        assert_eq!(
            section.enable,
            Some(EnableSpec::List(vec![
                "docker".to_string(),
                "npm".to_string()
            ]))
        );
        let set = config.enabled_registries();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&RegistryType::Docker));
        assert!(set.contains(&RegistryType::Npm));
    }

    #[test]
    fn test_registries_toml_string() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = "all"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        let set = config.enabled_registries();
        assert_eq!(set.len(), RegistryType::all().len());
    }

    #[test]
    fn test_registries_toml_absent() {
        // No [registries] section → legacy mode
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.registries.is_none());
        // Legacy: 7 core enabled by default
        let set = config.enabled_registries();
        assert_eq!(set.len(), 7);
        assert!(set.contains(&RegistryType::Docker));
        assert!(set.contains(&RegistryType::Maven));
        assert!(!set.contains(&RegistryType::Gems)); // new registries default disabled
    }

    #[test]
    fn test_registries_toml_empty_section() {
        // [registries] without enable → legacy mode
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.registries.is_some());
        assert!(config.registries.as_ref().unwrap().enable.is_none());
        // Falls through to legacy
        let set = config.enabled_registries();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn test_env_overrides_toml_registries() {
        // NORA_REGISTRIES_ENABLE should take precedence over [registries].enable
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["docker", "npm"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        std::env::set_var("NORA_REGISTRIES_ENABLE", "cargo,pypi");
        let set = config.enabled_registries();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&RegistryType::Cargo));
        assert!(set.contains(&RegistryType::PyPI));
        assert!(!set.contains(&RegistryType::Docker));
        std::env::remove_var("NORA_REGISTRIES_ENABLE");
    }

    #[test]
    fn test_from_env_str_parsing() {
        let spec = EnableSpec::from_env_str("docker, npm , pypi");
        assert_eq!(
            spec,
            EnableSpec::List(vec![
                "docker".to_string(),
                "npm".to_string(),
                "pypi".to_string()
            ])
        );

        // Single value
        let spec2 = EnableSpec::from_env_str("all");
        assert_eq!(spec2, EnableSpec::Single("all".to_string()));

        // Uppercase → lowercase
        let spec3 = EnableSpec::from_env_str("Docker,NPM");
        assert_eq!(
            spec3,
            EnableSpec::List(vec!["docker".to_string(), "npm".to_string()])
        );

        // With exclusions
        let spec4 = EnableSpec::from_env_str("all,-maven,-conan");
        assert_eq!(
            spec4,
            EnableSpec::List(vec![
                "all".to_string(),
                "-maven".to_string(),
                "-conan".to_string()
            ])
        );
    }

    #[test]
    fn test_validate_unknown_registry_in_enable() {
        let mut config = Config::default();
        config.registries = Some(RegistriesSection {
            enable: Some(EnableSpec::List(vec![
                "docker".to_string(),
                "bogus".to_string(),
            ])),
        });
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("[registries].enable")),
            "should report validation error: {:?}",
            errors
        );
    }

    #[test]
    fn test_registries_toml_all_minus() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["all", "-maven", "-conan"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        let set = config.enabled_registries();
        assert_eq!(set.len(), RegistryType::all().len() - 2);
        assert!(!set.contains(&RegistryType::Maven));
        assert!(!set.contains(&RegistryType::Conan));
        assert!(set.contains(&RegistryType::Docker));
    }

    #[test]
    fn test_upstream_hostnames_extracts_from_defaults() {
        let config = Config::default();
        let hosts = config.upstream_hostnames();
        // Default config has proxy URLs for several registries
        let hostnames: Vec<&str> = hosts.iter().map(|(_, h)| h.as_str()).collect();
        assert!(hostnames.contains(&"crates.io"), "cargo default missing");
        assert!(
            hostnames.contains(&"api.nuget.org"),
            "nuget default missing"
        );
        assert!(
            hostnames.contains(&"azuresearch-usnc.nuget.org"),
            "nuget search default missing"
        );
        assert!(
            hostnames.contains(&"proxy.golang.org"),
            "go default missing"
        );
        // localhost should be excluded
        assert!(!hostnames.contains(&"localhost"));
        assert!(!hostnames.contains(&"127.0.0.1"));
    }

    #[test]
    fn test_upstream_hostnames_deduplicates() {
        let config = Config::default();
        let hosts = config.upstream_hostnames();
        let mut seen = std::collections::HashSet::new();
        for pair in &hosts {
            assert!(seen.insert(pair), "duplicate: {:?}", pair);
        }
    }

    #[test]
    fn test_upstream_hostnames_docker_upstreams() {
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            path = "/tmp/nora-test"

            [docker]
            enabled = true

            [[docker.upstreams]]
            url = "https://registry-1.docker.io"

            [[docker.upstreams]]
            url = "https://ghcr.io"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        let hosts = config.upstream_hostnames();
        let docker_hosts: Vec<&str> = hosts
            .iter()
            .filter(|(r, _)| r == "docker")
            .map(|(_, h)| h.as_str())
            .collect();
        assert!(docker_hosts.contains(&"registry-1.docker.io"));
        assert!(docker_hosts.contains(&"ghcr.io"));
    }

    #[test]
    fn test_upstream_hostnames_pypi_multi_upstream() {
        // #663: every configured pypi upstream host must reach the leak detector,
        // not just the legacy single `proxy`. A secondary upstream (e.g. an internal
        // mirror carrying credentials) was previously invisible to leak scanning.
        let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            path = "/tmp/nora-test"

            [[pypi.proxies]]
            url = "https://pypi.org/simple"

            [[pypi.proxies]]
            url = "https://internal-nexus.corp/pypi"
            auth = "secret-token"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        let hosts = config.upstream_hostnames();
        let pypi_hosts: Vec<&str> = hosts
            .iter()
            .filter(|(r, _)| r == "pypi")
            .map(|(_, h)| h.as_str())
            .collect();
        assert!(
            pypi_hosts.contains(&"pypi.org"),
            "primary upstream registered"
        );
        assert!(
            pypi_hosts.contains(&"internal-nexus.corp"),
            "secondary upstream host must be registered with the leak detector"
        );
    }

    #[test]
    fn test_storage_config_debug_redacts_credentials() {
        let config = StorageConfig {
            mode: StorageMode::Local,
            path: String::new(),
            s3_url: String::new(),
            bucket: String::new(),
            s3_access_key: Some(ProtectedString::from("AKIAIOSFODNN7EXAMPLE")),
            s3_secret_key: Some(ProtectedString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )),
            s3_region: String::new(),
            s3_virtual_hosted: false,
            gcs_service_account_path: None,
            gcs_base_url: None,
        };
        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
            "Debug output must not contain access key"
        );
        assert!(
            !debug_output.contains("wJalrXUtnFEMI"),
            "Debug output must not contain secret key"
        );
        assert!(
            debug_output.contains("REDACTED"),
            "Debug output should show REDACTED for credential fields"
        );
    }

    // ========================================================================
    // Wildcard host + public_url validation (#510)
    // ========================================================================

    #[test]
    fn test_validate_wildcard_host_requires_public_url() {
        for host in &["0.0.0.0", "::", "0:0:0:0:0:0:0:0"] {
            let mut config = Config::default();
            config.server.host = host.to_string();
            config.server.public_url = None;
            let (_, errors) = config.validate_with_config_path(None);
            assert!(
                errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
                "host='{}' without public_url should produce NORA_PUBLIC_URL error, got: {:?}",
                host,
                errors
            );
        }
    }

    #[test]
    fn test_validate_wildcard_host_with_public_url_ok() {
        let mut config = Config::default();
        config.server.host = "0.0.0.0".to_string();
        config.server.public_url = Some("http://registry.example.com:4000".to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            !errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
            "0.0.0.0 with valid public_url should not error: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_non_wildcard_host_no_public_url_ok() {
        let mut config = Config::default();
        config.server.host = "192.168.1.10".to_string();
        config.server.public_url = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.is_empty(),
            "non-wildcard host without public_url should have no errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_public_url_rejects_bad_scheme() {
        for scheme_url in &["ftp://registry.example.com", "javascript://alert(1)"] {
            let mut config = Config::default();
            config.server.public_url = Some(scheme_url.to_string());
            let (_, errors) = config.validate_with_config_path(None);
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("http://") || e.contains("https://")),
                "public_url='{}' should be rejected for bad scheme: {:?}",
                scheme_url,
                errors
            );
        }
    }

    #[test]
    fn test_validate_public_url_rejects_garbage() {
        let mut config = Config::default();
        config.server.public_url = Some("not-a-url".to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("not a valid URL")),
            "garbage public_url should produce validation error: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_public_url_accepts_valid() {
        for url in &[
            "http://registry:4000",
            "https://nora.example.com",
            "http://10.0.0.1:4000",
            "https://nora.example.com:8443/",
        ] {
            let mut config = Config::default();
            config.server.public_url = Some(url.to_string());
            let (_, errors) = config.validate_with_config_path(None);
            assert!(
                !errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
                "valid public_url='{}' should not produce errors: {:?}",
                url,
                errors
            );
        }
    }

    // --- TrustedProxies: prefix=0 overflow fix (#525) ---

    #[test]
    fn test_trusted_proxies_prefix_zero_v4() {
        let proxies = TrustedProxies::parse("0.0.0.0/0");
        assert!(proxies.contains("192.168.1.1".parse().unwrap()));
        assert!(proxies.contains("10.0.0.1".parse().unwrap()));
        assert!(proxies.contains("255.255.255.255".parse().unwrap()));
        assert!(proxies.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_prefix_zero_v6() {
        let proxies = TrustedProxies::parse("::/0");
        assert!(proxies.contains("::1".parse().unwrap()));
        assert!(proxies.contains("fe80::1".parse().unwrap()));
        assert!(proxies.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_prefix_zero_no_cross_family() {
        // 0.0.0.0/0 must NOT match IPv6 addresses
        let v4_all = TrustedProxies::parse("0.0.0.0/0");
        assert!(!v4_all.contains("::1".parse().unwrap()));
        assert!(!v4_all.contains("2001:db8::1".parse().unwrap()));

        // ::/0 must NOT match IPv4 addresses
        let v6_all = TrustedProxies::parse("::/0");
        assert!(!v6_all.contains("127.0.0.1".parse().unwrap()));
        assert!(!v6_all.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_prefix_zero_non_canonical_network() {
        // Non-zero network address with /0 still matches everything in that family
        let proxies = TrustedProxies::parse("192.168.1.1/0");
        assert!(proxies.contains("10.0.0.1".parse().unwrap()));
        assert!(proxies.contains("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_prefix_zero_parse_accepted() {
        // /0 must not be dropped by parse()
        let proxies = TrustedProxies::parse("0.0.0.0/0");
        assert!(proxies.has_prefix_zero());

        let proxies = TrustedProxies::parse("::/0");
        assert!(proxies.has_prefix_zero());

        // Normal CIDR must not trigger has_prefix_zero
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert!(!proxies.has_prefix_zero());
    }

    #[test]
    fn test_trusted_proxies_existing_behavior_unchanged() {
        // Verify existing prefix values still work correctly
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert!(proxies.contains("10.255.255.255".parse().unwrap()));
        assert!(!proxies.contains("11.0.0.1".parse().unwrap()));

        let proxies = TrustedProxies::parse("192.168.1.0/24");
        assert!(proxies.contains("192.168.1.100".parse().unwrap()));
        assert!(!proxies.contains("192.168.2.1".parse().unwrap()));

        // Exact match (no CIDR)
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert!(proxies.contains("10.0.0.1".parse().unwrap()));
        assert!(!proxies.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_validate_warns_on_prefix_zero() {
        let mut config = Config::default();
        config.auth.trusted_proxies = TrustedProxies::parse("0.0.0.0/0");
        let (warnings, _) = config.validate_with_config_path(None);
        assert!(
            warnings.iter().any(|w| w.contains("/0 CIDR")),
            "validate() should warn about /0 in trusted_proxies: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_no_warn_on_normal_proxies() {
        let mut config = Config::default();
        config.auth.trusted_proxies = TrustedProxies::parse("10.0.0.0/8,192.168.1.0/24");
        let (warnings, _) = config.validate_with_config_path(None);
        assert!(
            !warnings.iter().any(|w| w.contains("/0 CIDR")),
            "validate() should not warn about normal CIDRs: {:?}",
            warnings
        );
    }

    mod proptest_trusted_proxies {
        use super::*;
        use proptest::prelude::*;

        /// Reference implementation for CIDR matching (avoids the shift overflow).
        fn cidr_matches_reference(net: u32, addr: u32, prefix: u8) -> bool {
            if prefix == 0 {
                return true;
            }
            if prefix >= 32 {
                return net == addr;
            }
            // Right-shift is safe for prefix 1..=31
            (net >> (32 - prefix)) == (addr >> (32 - prefix))
        }

        fn cidr_matches_reference_v6(net: u128, addr: u128, prefix: u8) -> bool {
            if prefix == 0 {
                return true;
            }
            if prefix >= 128 {
                return net == addr;
            }
            (net >> (128 - prefix)) == (addr >> (128 - prefix))
        }

        proptest! {
            #[test]
            fn cidr_v4_matches_oracle(
                net_raw in any::<u32>(),
                addr_raw in any::<u32>(),
                prefix in 0u8..=32,
            ) {
                let net = std::net::Ipv4Addr::from(net_raw);
                let addr = std::net::Ipv4Addr::from(addr_raw);
                let cidr = format!("{}/{}", net, prefix);
                let proxies = TrustedProxies::parse(&cidr);
                let actual = proxies.contains(std::net::IpAddr::V4(addr));
                let expected = cidr_matches_reference(net_raw, addr_raw, prefix);
                prop_assert_eq!(actual, expected,
                    "CIDR {} vs addr {}: expected={}, actual={}",
                    cidr, addr, expected, actual);
            }

            #[test]
            fn cidr_v6_matches_oracle(
                net_raw in any::<u128>(),
                addr_raw in any::<u128>(),
                prefix in 0u8..=128,
            ) {
                let net = std::net::Ipv6Addr::from(net_raw);
                let addr = std::net::Ipv6Addr::from(addr_raw);
                let cidr = format!("{}/{}", net, prefix);
                let proxies = TrustedProxies::parse(&cidr);
                let actual = proxies.contains(std::net::IpAddr::V6(addr));
                let expected = cidr_matches_reference_v6(net_raw, addr_raw, prefix);
                prop_assert_eq!(actual, expected,
                    "CIDR {} vs addr {}: expected={}, actual={}",
                    cidr, addr, expected, actual);
            }
        }
    }
}
