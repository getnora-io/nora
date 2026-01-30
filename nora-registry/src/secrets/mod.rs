#![allow(dead_code)] // Foundational code for future S3/Vault integration

//! Secrets management for NORA
//!
//! Provides a trait-based architecture for secrets providers:
//! - `env` - Environment variables (default, 12-Factor App)
//! - `aws-secrets` - AWS Secrets Manager (v0.4.0+)
//! - `vault` - HashiCorp Vault (v0.5.0+)
//! - `k8s` - Kubernetes Secrets (v0.4.0+)
//!
//! # Example
//!
//! ```rust,ignore
//! use nora::secrets::{create_secrets_provider, SecretsConfig};
//!
//! let config = SecretsConfig::default(); // Uses ENV provider
//! let provider = create_secrets_provider(&config)?;
//!
//! let api_key = provider.get_secret("API_KEY").await?;
//! println!("Got secret (redacted): {:?}", api_key);
//! ```

mod env;
pub mod protected;

pub use env::EnvProvider;
#[allow(unused_imports)]
pub use protected::{ProtectedString, S3Credentials};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Secrets provider error
#[derive(Debug, Error)]
pub enum SecretsError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),
}

/// Secrets provider trait
///
/// Implement this trait to add new secrets backends.
#[async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Get a secret by key (required)
    async fn get_secret(&self, key: &str) -> Result<ProtectedString, SecretsError>;

    /// Get a secret by key (optional, returns None if not found)
    async fn get_secret_optional(&self, key: &str) -> Option<ProtectedString> {
        self.get_secret(key).await.ok()
    }

    /// Get provider name for logging
    fn provider_name(&self) -> &'static str;
}

/// Secrets configuration
///
/// # Example config.toml
///
/// ```toml
/// [secrets]
/// provider = "env"
/// clear_env = false
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Provider type: "env", "aws-secrets", "vault", "k8s"
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Clear environment variables after reading (for env provider)
    #[serde(default)]
    pub clear_env: bool,
}

fn default_provider() -> String {
    "env".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            clear_env: false,
        }
    }
}

/// Create a secrets provider based on configuration
///
/// Currently supports:
/// - `env` - Environment variables (default)
///
/// Future versions will add:
/// - `aws-secrets` - AWS Secrets Manager
/// - `vault` - HashiCorp Vault
/// - `k8s` - Kubernetes Secrets
pub fn create_secrets_provider(
    config: &SecretsConfig,
) -> Result<Box<dyn SecretsProvider>, SecretsError> {
    match config.provider.as_str() {
        "env" => {
            let mut provider = EnvProvider::new();
            if config.clear_env {
                provider = provider.with_clear_after_read();
            }
            Ok(Box::new(provider))
        }
        // Future providers:
        // "aws-secrets" => { ... }
        // "vault" => { ... }
        // "k8s" => { ... }
        other => Err(SecretsError::UnsupportedProvider(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecretsConfig::default();
        assert_eq!(config.provider, "env");
        assert!(!config.clear_env);
    }

    #[test]
    fn test_create_env_provider() {
        let config = SecretsConfig::default();
        let provider = create_secrets_provider(&config).unwrap();
        assert_eq!(provider.provider_name(), "env");
    }

    #[test]
    fn test_create_unsupported_provider() {
        let config = SecretsConfig {
            provider: "unknown".to_string(),
            clear_env: false,
        };
        let result = create_secrets_provider(&config);
        assert!(matches!(result, Err(SecretsError::UnsupportedProvider(_))));
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            provider = "env"
            clear_env = true
        "#;
        let config: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.provider, "env");
        assert!(config.clear_env);
    }
}
