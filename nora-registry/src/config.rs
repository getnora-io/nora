use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

pub use crate::secrets::SecretsConfig;

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
    pub proxies: Vec<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmConfig {
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiConfig {
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default = "default_timeout")]
    pub proxy_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
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

impl Default for MavenConfig {
    fn default() -> Self {
        Self {
            proxies: vec!["https://repo1.maven.org/maven2".to_string()],
            proxy_timeout: 30,
        }
    }
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            proxy: Some("https://registry.npmjs.org".to_string()),
            proxy_timeout: 30,
        }
    }
}

impl Default for PypiConfig {
    fn default() -> Self {
        Self {
            proxy: Some("https://pypi.org/simple/".to_string()),
            proxy_timeout: 30,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
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

fn default_auth_rps() -> u64 { 1 }
fn default_auth_burst() -> u32 { 5 }
fn default_upload_rps() -> u64 { 200 }
fn default_upload_burst() -> u32 { 500 }
fn default_general_rps() -> u64 { 100 }
fn default_general_burst() -> u32 { 200 }

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
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

        // Auth config
        if let Ok(val) = env::var("NORA_AUTH_ENABLED") {
            self.auth.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_AUTH_HTPASSWD_FILE") {
            self.auth.htpasswd_file = val;
        }

        // Maven config
        if let Ok(val) = env::var("NORA_MAVEN_PROXIES") {
            self.maven.proxies = val.split(',').map(|s| s.trim().to_string()).collect();
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

        // PyPI config
        if let Ok(val) = env::var("NORA_PYPI_PROXY") {
            self.pypi.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.pypi.proxy_timeout = timeout;
            }
        }

        // Token storage
        if let Ok(val) = env::var("NORA_AUTH_TOKEN_STORAGE") {
            self.auth.token_storage = val;
        }

        // Rate limit config
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
            },
            storage: StorageConfig {
                mode: StorageMode::Local,
                path: String::from("data/storage"),
                s3_url: String::from("http://127.0.0.1:3000"),
                bucket: String::from("registry"),
            },
            maven: MavenConfig::default(),
            npm: NpmConfig::default(),
            pypi: PypiConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            secrets: SecretsConfig::default(),
        }
    }
}

#[cfg(test)]
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
}
