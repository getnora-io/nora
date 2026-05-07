// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;

use crate::registry_type::RegistryType;

pub use crate::secrets::SecretsConfig;

/// Encode "user:pass" into a Basic Auth header value, e.g. "Basic dXNlcjpwYXNz".
pub fn basic_auth_header(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
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
    /// Declarative registry selection: `[registries] enable = ["docker", "npm"]`
    #[serde(default)]
    pub registries: Option<RegistriesSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Public URL for generating pull commands (e.g., "registry.example.com")
    #[serde(default)]
    pub public_url: Option<String>,
    /// Maximum request body size in MB (default: 2048 = 2GB)
    #[serde(default = "default_body_limit_mb")]
    pub body_limit_mb: usize,
}

fn default_body_limit_mb() -> usize {
    2048 // 2GB - enough for any Docker image
}

/// TLS configuration for outbound connections to upstream registries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM-encoded CA certificate bundle (appended to system CAs)
    #[serde(default)]
    pub ca_cert: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageMode {
    #[default]
    Local,
    S3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub mode: StorageMode,
    #[serde(default = "default_storage_path")]
    pub path: String,
    #[serde(default = "default_s3_url")]
    pub s3_url: String,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    /// S3 access key (optional, uses anonymous access if not set)
    #[serde(default, skip_serializing)]
    pub s3_access_key: Option<String>,
    /// S3 secret key (optional, uses anonymous access if not set)
    #[serde(default, skip_serializing)]
    pub s3_secret_key: Option<String>,
    /// S3 region (default: us-east-1)
    #[serde(default = "default_s3_region")]
    pub s3_region: String,
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_storage_path() -> String {
    "data/storage".to_string()
}

fn default_s3_url() -> String {
    "http://127.0.0.1:9000".to_string()
}

fn default_bucket() -> String {
    "registry".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub proxies: Vec<MavenProxyEntry>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Verify client-uploaded checksums against server-computed values
    #[serde(default = "default_true")]
    pub checksum_verify: bool,
    /// Prevent overwriting released (non-SNAPSHOT) artifacts
    #[serde(default = "default_true")]
    pub immutable_releases: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>, // "user:pass" for basic auth
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Metadata cache TTL in seconds (default: 300 = 5 min). Set to 0 to cache forever.
    #[serde(default = "default_metadata_ttl")]
    pub metadata_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>, // "user:pass" for basic auth
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

/// Cargo registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Upstream Cargo registry (crates.io API)
    #[serde(default = "default_cargo_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

fn default_cargo_proxy() -> Option<String> {
    Some("https://crates.io".to_string())
}

impl Default for CargoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_cargo_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

/// Go module proxy configuration (GOPROXY protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Upstream Go module proxy URL (default: https://proxy.golang.org)
    #[serde(default = "default_go_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>, // "user:pass" for basic auth
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Separate timeout for .zip downloads (default: 120s, zips can be large)
    #[serde(default = "default_go_zip_timeout")]
    pub proxy_timeout_zip: u64,
    /// Maximum module zip size in bytes (default: 100MB)
    #[serde(default = "default_go_max_zip_size")]
    pub max_zip_size: u64,
}

fn default_go_proxy() -> Option<String> {
    Some("https://proxy.golang.org".to_string())
}

fn default_go_zip_timeout() -> u64 {
    120
}

fn default_go_max_zip_size() -> u64 {
    104_857_600 // 100MB
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_go_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_zip: 120,
            max_zip_size: 104_857_600,
        }
    }
}

/// Docker registry configuration with upstream proxy support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_docker_timeout")]
    pub proxy_timeout: u64,
    #[serde(default)]
    pub upstreams: Vec<DockerUpstream>,
}

/// Docker upstream registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerUpstream {
    pub url: String,
    #[serde(default)]
    pub auth: Option<String>, // "user:pass" for basic auth
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
    #[serde(default)]
    pub auth: Option<String>, // "user:pass" for basic auth
}

impl MavenProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            MavenProxyEntry::Simple(s) => s,
            MavenProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        match self {
            MavenProxyEntry::Simple(_) => None,
            MavenProxyEntry::Full(p) => p.auth.as_deref(),
        }
    }
}

/// Raw repository configuration for simple file storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_raw_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64, // in bytes
}

/// RubyGems proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream RubyGems registry (default: https://rubygems.org)
    #[serde(default = "default_gems_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Index cache TTL in seconds (default: 300 = 5 min)
    #[serde(default = "default_metadata_ttl")]
    pub index_ttl: u64,
}

fn default_gems_proxy() -> Option<String> {
    Some("https://rubygems.org".to_string())
}

impl Default for GemsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_gems_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            index_ttl: 300,
        }
    }
}

/// Terraform provider/module proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream Terraform registry (default: https://registry.terraform.io)
    #[serde(default = "default_terraform_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Separate timeout for binary downloads (default: 120s)
    #[serde(default = "default_go_zip_timeout")]
    pub proxy_timeout_download: u64,
}

fn default_terraform_proxy() -> Option<String> {
    Some("https://registry.terraform.io".to_string())
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_terraform_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_download: 120,
        }
    }
}

/// Ansible Galaxy collection proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream Galaxy server (default: https://galaxy.ansible.com)
    #[serde(default = "default_ansible_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

fn default_ansible_proxy() -> Option<String> {
    Some("https://galaxy.ansible.com".to_string())
}

impl Default for AnsibleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_ansible_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

/// NuGet V3 proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NugetConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream NuGet API (default: https://api.nuget.org)
    #[serde(default = "default_nuget_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Metadata cache TTL in seconds (default: 300 = 5 min)
    #[serde(default = "default_metadata_ttl")]
    pub metadata_ttl: u64,
    /// Upstream NuGet search service URL
    #[serde(default = "default_nuget_search")]
    pub search_service: String,
    /// Upstream NuGet autocomplete service URL
    #[serde(default = "default_nuget_autocomplete")]
    pub autocomplete: String,
}

fn default_nuget_proxy() -> Option<String> {
    Some("https://api.nuget.org".to_string())
}

fn default_nuget_search() -> String {
    "https://azuresearch-usnc.nuget.org/query".to_string()
}

fn default_nuget_autocomplete() -> String {
    "https://azuresearch-usnc.nuget.org/autocomplete".to_string()
}

impl Default for NugetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_nuget_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            search_service: default_nuget_search(),
            autocomplete: default_nuget_autocomplete(),
        }
    }
}

/// Dart/Flutter pub registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubDartConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream pub registry (default: https://pub.dev)
    #[serde(default = "default_pub_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

fn default_pub_proxy() -> Option<String> {
    Some("https://pub.dev".to_string())
}

impl Default for PubDartConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_pub_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

/// Conan V2 proxy configuration (C/C++ packages)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConanConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream Conan registry (default: https://center2.conan.io)
    #[serde(default = "default_conan_proxy")]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
    /// Separate timeout for binary downloads (default: 120s)
    #[serde(default = "default_go_zip_timeout")]
    pub proxy_timeout_download: u64,
    /// Metadata cache TTL in seconds (default: 300 = 5 min)
    #[serde(default = "default_metadata_ttl")]
    pub metadata_ttl: u64,
}

fn default_conan_proxy() -> Option<String> {
    Some("https://center2.conan.io".to_string())
}

impl Default for ConanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_conan_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_download: 120,
            metadata_ttl: 300,
        }
    }
}

fn default_docker_timeout() -> u64 {
    300
}

fn default_raw_enabled() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    104_857_600 // 100MB
}

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
                    if *prefix >= 32 {
                        return *net == addr;
                    }
                    let net_bits = u32::from(*net);
                    let addr_bits = u32::from(addr);
                    let mask = u32::MAX << (32 - prefix);
                    (net_bits & mask) == (addr_bits & mask)
                }
                (std::net::IpAddr::V6(net), std::net::IpAddr::V6(addr)) => {
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
    /// Allow anonymous read access (pull/download without auth, push requires auth)
    #[serde(default)]
    pub anonymous_read: bool,
    #[serde(default = "default_htpasswd_file")]
    pub htpasswd_file: String,
    #[serde(default = "default_token_storage")]
    pub token_storage: String,
    /// Trusted proxy IPs/CIDRs — only these sources have XFF/X-Real-IP honored.
    /// Default: 127.0.0.1,::1 (loopback only).
    /// ENV: NORA_AUTH_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8
    #[serde(default)]
    pub trusted_proxies: TrustedProxies,
}

fn default_htpasswd_file() -> String {
    "users.htpasswd".to_string()
}

fn default_token_storage() -> String {
    "data/tokens".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_metadata_ttl() -> u64 {
    300 // 5 minutes
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
        }
    }
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: Some("https://registry.npmjs.org".to_string()),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
        }
    }
}

impl Default for PypiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: Some("https://pypi.org/simple/".to_string()),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy_timeout: 300,
            upstreams: vec![DockerUpstream {
                url: "https://registry-1.docker.io".to_string(),
                auth: None,
            }],
        }
    }
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_size: 104_857_600, // 100MB
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            anonymous_read: false,
            htpasswd_file: "users.htpasswd".to_string(),
            token_storage: "data/tokens".to_string(),
            trusted_proxies: TrustedProxies::default_loopback(),
        }
    }
}

/// Rate limiting configuration
///
/// Controls request rate limits for different endpoint types.
///
/// # Example
/// ```toml
/// [rate_limit]
/// auth_rps = 1
/// auth_burst = 5
/// upload_rps = 200
/// upload_burst = 500
/// general_rps = 100
/// general_burst = 200
/// ```
///
/// # Environment Variables
/// - `NORA_RATE_LIMIT_AUTH_RPS` - Auth requests per second
/// - `NORA_RATE_LIMIT_AUTH_BURST` - Auth burst size
/// - `NORA_RATE_LIMIT_UPLOAD_RPS` - Upload requests per second
/// - `NORA_RATE_LIMIT_UPLOAD_BURST` - Upload burst size
/// - `NORA_RATE_LIMIT_GENERAL_RPS` - General requests per second
/// - `NORA_RATE_LIMIT_GENERAL_BURST` - General burst size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting (default: true). Set `NORA_RATE_LIMIT_ENABLED=false` to disable.
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_auth_rps")]
    pub auth_rps: u64,
    #[serde(default = "default_auth_burst")]
    pub auth_burst: u32,
    #[serde(default = "default_upload_rps")]
    pub upload_rps: u64,
    #[serde(default = "default_upload_burst")]
    pub upload_burst: u32,
    #[serde(default = "default_general_rps")]
    pub general_rps: u64,
    #[serde(default = "default_general_burst")]
    pub general_burst: u32,
}

fn default_rate_limit_enabled() -> bool {
    true
}
fn default_auth_rps() -> u64 {
    1
}
fn default_auth_burst() -> u32 {
    5
}
fn default_upload_rps() -> u64 {
    200
}
fn default_upload_burst() -> u32 {
    500
}
fn default_general_rps() -> u64 {
    100
}
fn default_general_burst() -> u32 {
    200
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            auth_rps: default_auth_rps(),
            auth_burst: default_auth_burst(),
            upload_rps: default_upload_rps(),
            upload_burst: default_upload_burst(),
            general_rps: default_general_rps(),
            general_burst: default_general_burst(),
        }
    }
}

// ============================================================================
// GC Configuration
// ============================================================================

/// Garbage collection configuration.
///
/// # Environment Variables
/// - `NORA_GC_ENABLED` — enable/disable background GC (default: false)
/// - `NORA_GC_INTERVAL` — interval in seconds between GC runs (default: 86400)
/// - `NORA_GC_DRY_RUN` — if true, only report orphans without deleting (default: false)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gc_interval")]
    pub interval: u64,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_gc_interval() -> u64 {
    86400 // 24 hours
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 86400,
            dry_run: false,
        }
    }
}

// ============================================================================
// Retention Configuration
// ============================================================================

/// A single retention rule applied to a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRule {
    /// Registry name (e.g., "docker", "maven", "npm", "pypi", "cargo") or "*" for all
    pub registry: String,
    /// Keep the N most recent versions
    #[serde(default)]
    pub keep_last: Option<u32>,
    /// Only delete versions older than N days
    #[serde(default)]
    pub older_than_days: Option<u32>,
    /// Glob patterns that protect versions from deletion
    #[serde(default)]
    pub exclude_tags: Vec<String>,
}

/// Retention policies configuration.
///
/// # Environment Variables
/// - `NORA_RETENTION_ENABLED` — enable/disable background retention (default: false)
/// - `NORA_RETENTION_INTERVAL` — interval in seconds between runs (default: 86400)
/// - `NORA_RETENTION_DRY_RUN` — if true, only report what would be deleted (default: false)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Enable background retention scheduler
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between retention runs (default: 86400 = 24h)
    #[serde(default = "default_retention_interval")]
    pub interval: u64,
    /// If true, only log what would be deleted without actually deleting (default: false)
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub rules: Vec<RetentionRule>,
}

fn default_retention_interval() -> u64 {
    86400 // 24 hours
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 86400,
            dry_run: false,
            rules: Vec::new(),
        }
    }
}

// ============================================================================
// Curation Configuration
// ============================================================================

/// Curation operating mode.
///
/// - `off` — curation disabled, all requests pass through (default)
/// - `audit` — evaluate filters and log decisions, but never block
/// - `enforce` — evaluate filters and block requests that match a deny rule
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationMode {
    #[default]
    Off,
    Audit,
    Enforce,
}

impl std::fmt::Display for CurationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurationMode::Off => write!(f, "off"),
            CurationMode::Audit => write!(f, "audit"),
            CurationMode::Enforce => write!(f, "enforce"),
        }
    }
}

/// Behavior when a curation filter returns an error or panics.
///
/// - `closed` — treat as blocked (fail-safe, default)
/// - `open` — treat as allowed (fail-open)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationOnFailure {
    #[default]
    Closed,
    Open,
}

/// Curation layer configuration.
///
/// # Environment Variables
/// - `NORA_CURATION_MODE` — off/audit/enforce (default: off)
/// - `NORA_CURATION_ON_FAILURE` — closed/open (default: closed)
/// - `NORA_CURATION_ALLOWLIST_PATH` — path to allowlist JSON file
/// - `NORA_CURATION_BLOCKLIST_PATH` — path to blocklist JSON file
/// - `NORA_CURATION_BYPASS_TOKEN` — token to bypass curation checks
/// - `NORA_CURATION_REQUIRE_INTEGRITY` — require integrity metadata (default: false)
/// - `NORA_CURATION_INTERNAL_NAMESPACES` — comma-separated glob patterns
/// - `NORA_CURATION_MIN_RELEASE_AGE` — minimum release age (e.g., "7d", "24h", "1w")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurationConfig {
    #[serde(default)]
    pub mode: CurationMode,
    #[serde(default)]
    pub on_failure: CurationOnFailure,
    #[serde(default)]
    pub allowlist_path: Option<String>,
    #[serde(default)]
    pub blocklist_path: Option<String>,
    /// Token to bypass curation. Should only be set via env var, not config file.
    #[serde(default, skip_serializing)]
    pub bypass_token: Option<String>,
    #[serde(default)]
    pub require_integrity: bool,
    /// Glob patterns for internal namespaces that must never be proxied upstream.
    /// Always active regardless of curation mode (security boundary).
    #[serde(default)]
    pub internal_namespaces: Vec<String>,
    /// Minimum release age before a package is allowed (e.g., "7d", "24h", "1w").
    /// Packages published less than this duration ago are blocked.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// Per-registry curation overrides. Overrides `min_release_age` per registry.
    #[serde(default)]
    pub npm: RegistryCurationOverride,
    #[serde(default)]
    pub pypi: RegistryCurationOverride,
    #[serde(default)]
    pub cargo: RegistryCurationOverride,
    #[serde(default)]
    pub go: RegistryCurationOverride,
    #[serde(default)]
    pub docker: RegistryCurationOverride,
    #[serde(default)]
    pub maven: RegistryCurationOverride,
    #[serde(default)]
    pub gems: RegistryCurationOverride,
    #[serde(default)]
    pub terraform: RegistryCurationOverride,
    #[serde(default)]
    pub ansible: RegistryCurationOverride,
    #[serde(default)]
    pub nuget: RegistryCurationOverride,
    #[serde(rename = "pub", default)]
    pub pub_dart: RegistryCurationOverride,
    #[serde(default)]
    pub conan: RegistryCurationOverride,
}

/// Per-registry curation override (used within `[curation.{registry}]`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryCurationOverride {
    /// Override min_release_age for this specific registry.
    #[serde(default)]
    pub min_release_age: Option<String>,
}

impl Default for CurationConfig {
    fn default() -> Self {
        Self {
            mode: CurationMode::Off,
            on_failure: CurationOnFailure::Closed,
            allowlist_path: None,
            blocklist_path: None,
            bypass_token: None,
            require_integrity: false,
            internal_namespaces: Vec::new(),
            min_release_age: None,
            npm: RegistryCurationOverride::default(),
            pypi: RegistryCurationOverride::default(),
            cargo: RegistryCurationOverride::default(),
            go: RegistryCurationOverride::default(),
            docker: RegistryCurationOverride::default(),
            maven: RegistryCurationOverride::default(),
            gems: RegistryCurationOverride::default(),
            terraform: RegistryCurationOverride::default(),
            ansible: RegistryCurationOverride::default(),
            nuget: RegistryCurationOverride::default(),
            pub_dart: RegistryCurationOverride::default(),
            conan: RegistryCurationOverride::default(),
        }
    }
}

// ============================================================================
// Circuit Breaker
// ============================================================================

fn default_cb_enabled() -> bool {
    false
}
fn default_cb_threshold() -> u32 {
    5
}
fn default_cb_reset_timeout() -> u64 {
    30
}

/// Upstream proxy circuit breaker configuration.
///
/// Experimental — disabled by default. When enabled, tracks per-registry
/// upstream failures and fails fast (503) when a registry is known to be down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker (default: false)
    #[serde(default = "default_cb_enabled")]
    pub enabled: bool,
    /// Number of consecutive failures before opening the circuit (default: 5)
    #[serde(default = "default_cb_threshold")]
    pub failure_threshold: u32,
    /// Seconds to wait before probing a failed upstream (default: 30)
    #[serde(default = "default_cb_reset_timeout")]
    pub reset_timeout: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_cb_enabled(),
            failure_threshold: default_cb_threshold(),
            reset_timeout: default_cb_reset_timeout(),
        }
    }
}

// ============================================================================
// Registries Section (nginx-style enable)
// ============================================================================

/// Top-level `[registries]` section for declarative registry selection.
///
/// # Example
/// ```toml
/// [registries]
/// enable = ["docker", "npm", "pypi"]
///
/// # Or enable all except some:
/// # enable = ["all", "-maven"]
///
/// # Or enable everything:
/// # enable = "all"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistriesSection {
    #[serde(default)]
    pub enable: Option<EnableSpec>,
}

/// What registries to enable — a single string or list of strings.
///
/// Supports:
/// - `"all"` — all 13 registries
/// - `"docker"` — single registry
/// - `["docker", "npm", "pypi"]` — explicit list
/// - `["all", "-maven"]` — all except maven
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum EnableSpec {
    /// Single string: `enable = "all"` or `enable = "docker"`
    Single(String),
    /// List of strings: `enable = ["docker", "npm"]`
    List(Vec<String>),
}

impl EnableSpec {
    /// Parse from comma-separated env var string.
    /// E.g. `"docker,npm,pypi"` or `"all,-maven"`.
    pub fn from_env_str(s: &str) -> Self {
        let items: Vec<String> = s
            .split(',')
            .map(|item| item.trim().to_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        match items.len() {
            1 => {
                // Safety: we just checked len() == 1
                let item = items.into_iter().next().unwrap_or_default();
                EnableSpec::Single(item)
            }
            _ => EnableSpec::List(items),
        }
    }

    /// Resolve the spec into a concrete set of RegistryTypes.
    ///
    /// Rules:
    /// - `"all"` → all 13 registries
    /// - `"-name"` → exclusion (only valid when `"all"` is present)
    /// - `"name"` → inclusion
    /// - Unknown name → Err
    /// - Empty result → Err
    pub fn resolve(&self) -> Result<HashSet<RegistryType>, String> {
        let items = match self {
            EnableSpec::Single(s) => vec![s.clone()],
            EnableSpec::List(v) => v.clone(),
        };

        if items.is_empty() {
            return Err("registries.enable must not be empty".to_string());
        }

        let has_all = items.iter().any(|s| s == "all");
        let exclusions: Vec<&str> = items
            .iter()
            .filter(|s| s.starts_with('-'))
            .map(|s| s.as_str())
            .collect();
        let inclusions: Vec<&str> = items
            .iter()
            .filter(|s| *s != "all" && !s.starts_with('-'))
            .map(|s| s.as_str())
            .collect();

        // Exclusions without "all" is an error
        if !exclusions.is_empty() && !has_all {
            return Err(format!(
                "exclusion entries ({}) require \"all\" in the list",
                exclusions.join(", ")
            ));
        }

        // "all" with inclusions is ambiguous
        if has_all && !inclusions.is_empty() {
            return Err(format!(
                "\"all\" cannot be combined with inclusions ({}); use \"all\" with exclusions like \"-maven\"",
                inclusions.join(", ")
            ));
        }

        if has_all {
            // Start with all, then remove exclusions
            let mut set: HashSet<RegistryType> = RegistryType::all().iter().copied().collect();
            for ex in &exclusions {
                let name = &ex[1..]; // strip leading '-'
                match RegistryType::from_str_opt(name) {
                    Some(rt) => {
                        set.remove(&rt);
                    }
                    None => {
                        return Err(format!("unknown registry in exclusion: \"{}\"", ex));
                    }
                }
            }
            if set.is_empty() {
                return Err("all registries excluded — at least one must be enabled".to_string());
            }
            Ok(set)
        } else {
            // Explicit inclusion list
            let mut set = HashSet::new();
            for name in &inclusions {
                match RegistryType::from_str_opt(name) {
                    Some(rt) => {
                        set.insert(rt);
                    }
                    None => {
                        return Err(format!("unknown registry: \"{}\"", name));
                    }
                }
            }
            if set.is_empty() {
                return Err("registries.enable must not be empty".to_string());
            }
            Ok(set)
        }
    }
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
        if set.is_empty() {
            tracing::warn!("No registries enabled! All registries are disabled.");
        }
        set
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
            "NORA_TERRAFORM_ENABLED",
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
        // Cargo
        if self.cargo.proxy_auth.is_some() && std::env::var("NORA_CARGO_PROXY_AUTH").is_err() {
            tracing::warn!("Cargo proxy credentials in config.toml are plaintext — consider NORA_CARGO_PROXY_AUTH env var");
        }
    }

    /// Validate configuration and return (warnings, errors).
    ///
    /// Warnings are logged but do not prevent startup.
    /// Errors indicate a fatal misconfiguration and should cause a panic.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
        self.validate_with_config_path(env::var("NORA_CONFIG_PATH").ok())
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

        // 2. Storage path must not be empty when mode = Local
        if self.storage.mode == StorageMode::Local && self.storage.path.trim().is_empty() {
            errors.push("storage.path must not be empty when storage mode is local".to_string());
        }

        // 3. S3 bucket must not be empty when mode = S3
        if self.storage.mode == StorageMode::S3 && self.storage.bucket.trim().is_empty() {
            errors.push("storage.bucket must not be empty when storage mode is s3".to_string());
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

        // 6. Relative paths with explicit config — may resolve unexpectedly
        if config_path.is_some() {
            if self.storage.mode == StorageMode::Local && !self.storage.path.starts_with('/') {
                warnings.push(format!(
                    "storage.path=\"{}\" is relative — will resolve from CWD. Use absolute path for predictable behavior",
                    self.storage.path
                ));
            }
            if self.auth.enabled && !self.auth.token_storage.starts_with('/') {
                warnings.push(format!(
                    "auth.token_storage=\"{}\" is relative — will resolve from CWD. Use absolute path for predictable behavior",
                    self.auth.token_storage
                ));
            }
        }

        // 7. "Enabled but empty" — subsystems that silently do nothing
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

        // 8. Curation validation
        if self.curation.mode == CurationMode::Enforce && self.curation.allowlist_path.is_none() {
            errors.push(
                "curation.mode=enforce requires curation.allowlist_path to be set".to_string(),
            );
        }
        if self.curation.mode == CurationMode::Enforce {
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
            warnings.push(
                "curation.on_failure is not yet implemented — the setting is parsed but has no effect. All filter errors are treated as closed (blocked). This field will be removed in v0.9".to_string(),
            );
        }

        // 9. [registries].enable validation
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
        config.apply_env_overrides();

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

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Server config
        if let Ok(val) = env::var("NORA_HOST") {
            self.server.host = val;
        }
        if let Ok(val) = env::var("NORA_PORT") {
            if let Ok(port) = val.parse() {
                self.server.port = port;
            }
        }
        if let Ok(val) = env::var("NORA_PUBLIC_URL") {
            self.server.public_url = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_BODY_LIMIT_MB") {
            if let Ok(mb) = val.parse() {
                self.server.body_limit_mb = mb;
            }
        }

        // TLS config
        if let Ok(val) = env::var("NORA_TLS_CA_CERT") {
            self.tls.ca_cert = if val.is_empty() { None } else { Some(val) };
        }

        // Storage config
        if let Ok(val) = env::var("NORA_STORAGE_MODE") {
            self.storage.mode = match val.to_lowercase().as_str() {
                "s3" => StorageMode::S3,
                _ => StorageMode::Local,
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_PATH") {
            self.storage.path = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_URL") {
            self.storage.s3_url = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_BUCKET") {
            self.storage.bucket = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_ACCESS_KEY") {
            self.storage.s3_access_key = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_SECRET_KEY") {
            self.storage.s3_secret_key = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_REGION") {
            self.storage.s3_region = val;
        }

        // Auth config
        if let Ok(val) = env::var("NORA_AUTH_ENABLED") {
            self.auth.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_ANONYMOUS_READ") {
            self.auth.anonymous_read = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_HTPASSWD_FILE") {
            self.auth.htpasswd_file = val;
        }
        if let Ok(val) = env::var("NORA_AUTH_TRUSTED_PROXIES") {
            self.auth.trusted_proxies = TrustedProxies::parse(&val);
        }

        // Registry enabled flags
        if let Ok(val) = env::var("NORA_DOCKER_ENABLED") {
            self.docker.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_ENABLED") {
            self.maven.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NPM_ENABLED") {
            self.npm.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CARGO_ENABLED") {
            self.cargo.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_PYPI_ENABLED") {
            self.pypi.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GO_ENABLED") {
            self.go.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GEMS_ENABLED") {
            self.gems.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_TERRAFORM_ENABLED") {
            self.terraform.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_ENABLED") {
            self.ansible.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NUGET_ENABLED") {
            self.nuget.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_PUB_ENABLED") {
            self.pub_dart.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CONAN_ENABLED") {
            self.conan.enabled = val.to_lowercase() == "true" || val == "1";
        }

        // Maven config — supports "url1,url2" or "url1|auth1,url2|auth2"
        if let Ok(val) = env::var("NORA_MAVEN_PROXIES") {
            self.maven.proxies = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                    if parts.len() > 1 {
                        MavenProxyEntry::Full(MavenProxy {
                            url: parts[0].to_string(),
                            auth: Some(parts[1].to_string()),
                        })
                    } else {
                        MavenProxyEntry::Simple(parts[0].to_string())
                    }
                })
                .collect();
        }
        if let Ok(val) = env::var("NORA_MAVEN_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.maven.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_MAVEN_CHECKSUM_VERIFY") {
            self.maven.checksum_verify = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_IMMUTABLE_RELEASES") {
            self.maven.immutable_releases = val.to_lowercase() == "true" || val == "1";
        }

        // npm config
        if let Ok(val) = env::var("NORA_NPM_PROXY") {
            self.npm.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.npm.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_NPM_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.npm.metadata_ttl = ttl;
            }
        }

        // npm proxy auth
        if let Ok(val) = env::var("NORA_NPM_PROXY_AUTH") {
            self.npm.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }

        // PyPI config
        if let Ok(val) = env::var("NORA_PYPI_PROXY") {
            self.pypi.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.pypi.proxy_timeout = timeout;
            }
        }

        // PyPI proxy auth
        if let Ok(val) = env::var("NORA_PYPI_PROXY_AUTH") {
            self.pypi.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }

        // Docker config
        if let Ok(val) = env::var("NORA_DOCKER_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.docker.proxy_timeout = timeout;
            }
        }
        // NORA_DOCKER_PROXIES format: "url1,url2" or "url1|auth1,url2|auth2"
        // Backward compat: NORA_DOCKER_UPSTREAMS still works but is deprecated
        if let Ok(val) =
            env::var("NORA_DOCKER_PROXIES").or_else(|_| env::var("NORA_DOCKER_UPSTREAMS"))
        {
            if env::var("NORA_DOCKER_PROXIES").is_err() {
                tracing::warn!("NORA_DOCKER_UPSTREAMS is deprecated, use NORA_DOCKER_PROXIES");
            }
            self.docker.upstreams = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                    DockerUpstream {
                        url: parts[0].to_string(),
                        auth: parts.get(1).map(|a| a.to_string()),
                    }
                })
                .collect();
            if self.docker.upstreams.iter().any(|u| u.auth.is_some()) {
                tracing::warn!(
                    "Docker upstream credentials passed via NORA_DOCKER_PROXIES environment variable. \
                     For production use config.toml with [[docker.upstreams]] and mount credentials from a Kubernetes Secret."
                );
            }
        }

        // Go config
        if let Ok(val) = env::var("NORA_GO_PROXY") {
            self.go.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_AUTH") {
            self.go.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.go.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT_ZIP") {
            if let Ok(timeout) = val.parse() {
                self.go.proxy_timeout_zip = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_GO_MAX_ZIP_SIZE") {
            if let Ok(size) = val.parse() {
                self.go.max_zip_size = size;
            }
        }

        // Cargo config
        if let Ok(val) = env::var("NORA_CARGO_PROXY") {
            self.cargo.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CARGO_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.cargo.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_CARGO_PROXY_AUTH") {
            self.cargo.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }

        // Raw config
        if let Ok(val) = env::var("NORA_RAW_ENABLED") {
            self.raw.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RAW_MAX_FILE_SIZE") {
            if let Ok(size) = val.parse() {
                self.raw.max_file_size = size;
            }
        }

        // Gems config
        if let Ok(val) = env::var("NORA_GEMS_PROXY") {
            self.gems.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_AUTH") {
            self.gems.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GEMS_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.gems.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_GEMS_INDEX_TTL") {
            if let Ok(ttl) = val.parse() {
                self.gems.index_ttl = ttl;
            }
        }

        // Terraform config
        if let Ok(val) = env::var("NORA_TERRAFORM_PROXY") {
            self.terraform.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_TERRAFORM_PROXY_AUTH") {
            self.terraform.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_TERRAFORM_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.terraform.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_TERRAFORM_PROXY_TIMEOUT_DOWNLOAD") {
            if let Ok(timeout) = val.parse() {
                self.terraform.proxy_timeout_download = timeout;
            }
        }

        // Ansible Galaxy config
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY") {
            self.ansible.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY_AUTH") {
            self.ansible.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_ANSIBLE_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.ansible.proxy_timeout = timeout;
            }
        }

        // NuGet config
        if let Ok(val) = env::var("NORA_NUGET_PROXY") {
            self.nuget.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_AUTH") {
            self.nuget.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.nuget.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.nuget.metadata_ttl = ttl;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_SEARCH_SERVICE") {
            if !val.is_empty() {
                self.nuget.search_service = val;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_AUTOCOMPLETE") {
            if !val.is_empty() {
                self.nuget.autocomplete = val;
            }
        }

        // pub.dev config
        if let Ok(val) = env::var("NORA_PUB_PROXY") {
            self.pub_dart.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PUB_PROXY_AUTH") {
            self.pub_dart.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PUB_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.pub_dart.proxy_timeout = timeout;
            }
        }

        // Conan proxy config
        if let Ok(val) = env::var("NORA_CONAN_PROXY") {
            self.conan.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_AUTH") {
            self.conan.proxy_auth = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.conan.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_TIMEOUT_DOWNLOAD") {
            if let Ok(timeout) = val.parse() {
                self.conan.proxy_timeout_download = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_CONAN_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.conan.metadata_ttl = ttl;
            }
        }

        // Token storage
        if let Ok(val) = env::var("NORA_AUTH_TOKEN_STORAGE") {
            self.auth.token_storage = val;
        }

        // Rate limit config
        if let Ok(val) = env::var("NORA_RATE_LIMIT_ENABLED") {
            self.rate_limit.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_AUTH_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.rate_limit.auth_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_AUTH_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.rate_limit.auth_burst = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_UPLOAD_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.rate_limit.upload_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_UPLOAD_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.rate_limit.upload_burst = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_GENERAL_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.rate_limit.general_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_GENERAL_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.rate_limit.general_burst = v;
            }
        }

        // GC config
        if let Ok(val) = env::var("NORA_GC_ENABLED") {
            self.gc.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GC_INTERVAL") {
            if let Ok(v) = val.parse() {
                self.gc.interval = v;
            }
        }
        if let Ok(val) = env::var("NORA_GC_DRY_RUN") {
            self.gc.dry_run = val.to_lowercase() == "true" || val == "1";
        }

        // Retention scheduler config
        if let Ok(val) = env::var("NORA_RETENTION_ENABLED") {
            self.retention.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RETENTION_INTERVAL") {
            if let Ok(v) = val.parse() {
                self.retention.interval = v;
            }
        }
        if let Ok(val) = env::var("NORA_RETENTION_DRY_RUN") {
            self.retention.dry_run = val.to_lowercase() == "true" || val == "1";
        }

        // Secrets config
        if let Ok(val) = env::var("NORA_SECRETS_PROVIDER") {
            self.secrets.provider = val;
        }
        if let Ok(val) = env::var("NORA_SECRETS_CLEAR_ENV") {
            self.secrets.clear_env = val.to_lowercase() == "true" || val == "1";
        }

        // Curation config
        if let Ok(val) = env::var("NORA_CURATION_MODE") {
            self.curation.mode = match val.to_lowercase().as_str() {
                "audit" => CurationMode::Audit,
                "enforce" => CurationMode::Enforce,
                _ => CurationMode::Off,
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_ON_FAILURE") {
            self.curation.on_failure = match val.to_lowercase().as_str() {
                "open" => CurationOnFailure::Open,
                _ => CurationOnFailure::Closed,
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_ALLOWLIST_PATH") {
            self.curation.allowlist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BLOCKLIST_PATH") {
            self.curation.blocklist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BYPASS_TOKEN") {
            self.curation.bypass_token = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_REQUIRE_INTEGRITY") {
            self.curation.require_integrity = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CURATION_INTERNAL_NAMESPACES") {
            self.curation.internal_namespaces = if val.is_empty() {
                Vec::new()
            } else {
                val.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_MIN_RELEASE_AGE") {
            self.curation.min_release_age = if val.is_empty() { None } else { Some(val) };
        }

        // Circuit breaker config
        if let Ok(val) = env::var("NORA_CB_ENABLED") {
            self.circuit_breaker.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CB_THRESHOLD") {
            if let Ok(v) = val.parse() {
                self.circuit_breaker.failure_threshold = v;
            }
        }
        if let Ok(val) = env::var("NORA_CB_RESET_TIMEOUT") {
            if let Ok(v) = val.parse() {
                self.circuit_breaker.reset_timeout = v;
            }
        }

        // Per-registry curation overrides
        for (env_suffix, field) in [
            ("NPM", &mut self.curation.npm),
            ("PYPI", &mut self.curation.pypi),
            ("CARGO", &mut self.curation.cargo),
            ("GO", &mut self.curation.go),
            ("DOCKER", &mut self.curation.docker),
            ("MAVEN", &mut self.curation.maven),
            ("GEMS", &mut self.curation.gems),
            ("TERRAFORM", &mut self.curation.terraform),
            ("ANSIBLE", &mut self.curation.ansible),
            ("NUGET", &mut self.curation.nuget),
            ("PUB", &mut self.curation.pub_dart),
            ("CONAN", &mut self.curation.conan),
        ] {
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_MIN_RELEASE_AGE", env_suffix)) {
                field.min_release_age = if val.is_empty() { None } else { Some(val) };
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: String::from("127.0.0.1"),
                port: 4000,
                public_url: None,
                body_limit_mb: 2048,
            },
            storage: StorageConfig {
                mode: StorageMode::Local,
                path: String::from("data/storage"),
                s3_url: String::from("http://127.0.0.1:9000"),
                bucket: String::from("registry"),
                s3_access_key: None,
                s3_secret_key: None,
                s3_region: String::from("us-east-1"),
            },
            maven: MavenConfig::default(),
            npm: NpmConfig::default(),
            pypi: PypiConfig::default(),
            go: GoConfig::default(),
            cargo: CargoConfig::default(),
            docker: DockerConfig::default(),
            raw: RawConfig::default(),
            gems: GemsConfig::default(),
            terraform: TerraformConfig::default(),
            ansible: AnsibleConfig::default(),
            nuget: NugetConfig::default(),
            pub_dart: PubDartConfig::default(),
            conan: ConanConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            secrets: SecretsConfig::default(),
            gc: GcConfig::default(),
            retention: RetentionConfig::default(),
            curation: CurationConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            tls: TlsConfig::default(),
            registries: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        config.apply_env_overrides();
        assert!(config.auth.anonymous_read);
        std::env::remove_var("NORA_AUTH_ANONYMOUS_READ");
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
            auth: Some("user:secret".to_string()),
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
        config.apply_env_overrides();
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
        let mut config = Config::default();
        std::env::set_var("NORA_STORAGE_MODE", "s3");
        std::env::set_var("NORA_STORAGE_PATH", "/data/nora");
        std::env::set_var("NORA_STORAGE_BUCKET", "my-bucket");
        std::env::set_var("NORA_STORAGE_S3_REGION", "eu-west-1");
        config.apply_env_overrides();
        assert_eq!(config.storage.mode, StorageMode::S3);
        assert_eq!(config.storage.path, "/data/nora");
        assert_eq!(config.storage.bucket, "my-bucket");
        assert_eq!(config.storage.s3_region, "eu-west-1");
        std::env::remove_var("NORA_STORAGE_MODE");
        std::env::remove_var("NORA_STORAGE_PATH");
        std::env::remove_var("NORA_STORAGE_BUCKET");
        std::env::remove_var("NORA_STORAGE_S3_REGION");
    }

    #[test]
    fn test_env_override_auth() {
        let mut config = Config::default();
        std::env::set_var("NORA_AUTH_ENABLED", "true");
        std::env::set_var("NORA_AUTH_HTPASSWD_FILE", "/etc/nora/users");
        std::env::set_var("NORA_AUTH_TOKEN_STORAGE", "/data/tokens");
        config.apply_env_overrides();
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
        config.apply_env_overrides();
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
        config.apply_env_overrides();
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
        config.apply_env_overrides();
        assert_eq!(
            config.npm.proxy,
            Some("https://npm.company.com".to_string())
        );
        assert_eq!(config.npm.proxy_auth, Some("user:token".to_string()));
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
        config.apply_env_overrides();
        assert!(!config.raw.enabled);
        assert_eq!(config.raw.max_file_size, 524288000);
        std::env::remove_var("NORA_RAW_ENABLED");
        std::env::remove_var("NORA_RAW_MAX_FILE_SIZE");
    }

    #[test]
    fn test_env_override_rate_limit() {
        let mut config = Config::default();
        std::env::set_var("NORA_RATE_LIMIT_ENABLED", "false");
        std::env::set_var("NORA_RATE_LIMIT_AUTH_RPS", "10");
        std::env::set_var("NORA_RATE_LIMIT_GENERAL_BURST", "500");
        config.apply_env_overrides();
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
            config.docker.upstreams[1].auth,
            Some("user:pass".to_string())
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
        config.apply_env_overrides();
        assert_eq!(config.docker.upstreams.len(), 2);
        assert_eq!(config.docker.upstreams[0].url, "https://mirror.gcr.io");
        assert!(config.docker.upstreams[0].auth.is_none());
        assert_eq!(config.docker.upstreams[1].url, "https://private.io");
        assert_eq!(
            config.docker.upstreams[1].auth,
            Some("token123".to_string())
        );
        std::env::remove_var("NORA_DOCKER_PROXIES");

        // Test backward compat: old NORA_DOCKER_UPSTREAMS still works
        std::env::remove_var("NORA_DOCKER_PROXIES");
        std::env::set_var("NORA_DOCKER_UPSTREAMS", "https://legacy.io|secret");
        let mut config2 = Config::default();
        config2.apply_env_overrides();
        assert_eq!(config2.docker.upstreams.len(), 1);
        assert_eq!(config2.docker.upstreams[0].url, "https://legacy.io");
        assert_eq!(config2.docker.upstreams[0].auth, Some("secret".to_string()));
        std::env::remove_var("NORA_DOCKER_UPSTREAMS");
    }

    #[test]
    fn test_env_override_go_proxy() {
        let mut config = Config::default();
        std::env::set_var("NORA_GO_PROXY", "https://goproxy.company.com");
        config.apply_env_overrides();
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
        config.apply_env_overrides();
        assert_eq!(config.go.proxy_auth, Some("user:pass".to_string()));
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
        config.apply_env_overrides();
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
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_MODE", "enforce");
        config.apply_env_overrides();
        assert_eq!(config.curation.mode, CurationMode::Enforce);
        std::env::remove_var("NORA_CURATION_MODE");
    }

    #[test]
    fn test_curation_env_override_on_failure() {
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_ON_FAILURE", "open");
        config.apply_env_overrides();
        assert_eq!(config.curation.on_failure, CurationOnFailure::Open);
        std::env::remove_var("NORA_CURATION_ON_FAILURE");
    }

    #[test]
    fn test_curation_on_failure_open_emits_warning() {
        let mut config = Config::default();
        config.curation.on_failure = CurationOnFailure::Open;
        let (warnings, _errors) = config.validate_with_config_path(None);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("on_failure is not yet implemented")),
            "expected deprecation warning for on_failure=open"
        );
    }

    #[test]
    fn test_curation_env_override_paths() {
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_ALLOWLIST_PATH", "/etc/nora/allow.json");
        std::env::set_var("NORA_CURATION_BLOCKLIST_PATH", "/etc/nora/block.json");
        config.apply_env_overrides();
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
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_BYPASS_TOKEN", "secret-bypass");
        config.apply_env_overrides();
        assert_eq!(
            config.curation.bypass_token,
            Some("secret-bypass".to_string())
        );
        std::env::remove_var("NORA_CURATION_BYPASS_TOKEN");
    }

    #[test]
    fn test_curation_env_override_require_integrity() {
        let mut config = Config::default();
        std::env::set_var("NORA_CURATION_REQUIRE_INTEGRITY", "true");
        config.apply_env_overrides();
        assert!(config.curation.require_integrity);
        std::env::remove_var("NORA_CURATION_REQUIRE_INTEGRITY");
    }

    #[test]
    fn test_validate_curation_enforce_no_allowlist() {
        let mut config = Config::default();
        config.curation.mode = CurationMode::Enforce;
        config.curation.allowlist_path = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("allowlist_path")),
            "enforce without allowlist should be an error"
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
}
