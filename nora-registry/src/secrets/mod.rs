// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Secrets management for NORA
//!
//! Provides a trait-based architecture for secrets providers:
//! - `env` - Environment variables (default, 12-Factor App)
//!
//! Additional providers (AWS Secrets Manager, HashiCorp Vault, Kubernetes
//! Secrets) may be added in future releases.
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

#[allow(dead_code)] // Variants used by provider impls
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
    #[allow(dead_code)]
    async fn get_secret(&self, key: &str) -> Result<ProtectedString, SecretsError>;

    /// Get a secret by key (optional, returns None if not found)
    #[allow(dead_code)]
    async fn get_secret_optional(&self, key: &str) -> Option<ProtectedString> {
        self.get_secret(key).await.ok()
    }

    /// Get provider name for logging
    #[allow(dead_code)]
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

#[allow(dead_code)] // Scaffolding for future secrets integration (Vault, AWS SM, K8s)
/// Create a secrets provider based on configuration
///
/// Currently supports:
/// - `env` - Environment variables (default)
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
        other => Err(SecretsError::UnsupportedProvider(other.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
