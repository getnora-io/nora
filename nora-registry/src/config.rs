// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

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
    pub raw: RawConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
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
    "http://127.0.0.1:3000".to_string()
}

fn default_bucket() -> String {
    "registry".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenConfig {
    #[serde(default)]
    pub proxies: Vec<MavenProxyEntry>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmConfig {
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
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_auth: Option<String>, // "user:pass" for basic auth
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

/// Go module proxy configuration (GOPROXY protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoConfig {
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

fn default_docker_timeout() -> u64 {
    60
}

fn default_raw_enabled() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    104_857_600 // 100MB
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
            proxies: vec![MavenProxyEntry::Simple(
                "https://repo1.maven.org/maven2".to_string(),
            )],
            proxy_timeout: 30,
        }
    }
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
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
            proxy: Some("https://pypi.org/simple/".to_string()),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            proxy_timeout: 60,
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
/// upload_rps = 500
/// upload_burst = 1000
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

impl Config {
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
    }

    /// Validate configuration and return (warnings, errors).
    ///
    /// Warnings are logged but do not prevent startup.
    /// Errors indicate a fatal misconfiguration and should cause a panic.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
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

        (warnings, errors)
    }

    /// Load configuration with priority: ENV > config.toml > defaults
    pub fn load() -> Self {
        // 1. Start with defaults
        // 2. Override with config.toml if exists
        let mut config: Config = fs::read_to_string("config.toml")
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default();

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

        // Raw config
        if let Ok(val) = env::var("NORA_RAW_ENABLED") {
            self.raw.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RAW_MAX_FILE_SIZE") {
            if let Ok(size) = val.parse() {
                self.raw.max_file_size = size;
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

        // Secrets config
        if let Ok(val) = env::var("NORA_SECRETS_PROVIDER") {
            self.secrets.provider = val;
        }
        if let Ok(val) = env::var("NORA_SECRETS_CLEAR_ENV") {
            self.secrets.clear_env = val.to_lowercase() == "true" || val == "1";
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
                s3_url: String::from("http://127.0.0.1:3000"),
                bucket: String::from("registry"),
                s3_access_key: None,
                s3_secret_key: None,
                s3_region: String::from("us-east-1"),
            },
            maven: MavenConfig::default(),
            npm: NpmConfig::default(),
            pypi: PypiConfig::default(),
            go: GoConfig::default(),
            docker: DockerConfig::default(),
            raw: RawConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            secrets: SecretsConfig::default(),
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
        assert_eq!(d.proxy_timeout, 60);
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
            s3_url = "http://minio:9000"
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
        assert_eq!(config.storage.s3_url, "http://minio:9000");
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
}
