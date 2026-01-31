// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! Environment variables secrets provider
//!
//! Reads secrets from environment variables. This is the default provider
//! following 12-Factor App principles.

use std::env;

use super::{SecretsError, SecretsProvider};
use crate::secrets::protected::ProtectedString;
use async_trait::async_trait;

/// Environment variables secrets provider
///
/// Reads secrets from environment variables.
/// Optionally clears variables after reading for extra security.
#[derive(Debug, Clone)]
pub struct EnvProvider {
    /// Clear environment variables after reading
    clear_after_read: bool,
}

impl EnvProvider {
    /// Create a new environment provider
    pub fn new() -> Self {
        Self {
            clear_after_read: false,
        }
    }

    /// Create a provider that clears env vars after reading
    ///
    /// This prevents secrets from being visible in `/proc/<pid>/environ`
    pub fn with_clear_after_read(mut self) -> Self {
        self.clear_after_read = true;
        self
    }
}

impl Default for EnvProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for EnvProvider {
    async fn get_secret(&self, key: &str) -> Result<ProtectedString, SecretsError> {
        let value = env::var(key).map_err(|_| SecretsError::NotFound(key.to_string()))?;

        if self.clear_after_read {
            env::remove_var(key);
        }

        Ok(ProtectedString::new(value))
    }

    async fn get_secret_optional(&self, key: &str) -> Option<ProtectedString> {
        env::var(key).ok().map(|v| {
            if self.clear_after_read {
                env::remove_var(key);
            }
            ProtectedString::new(v)
        })
    }

    fn provider_name(&self) -> &'static str {
        "env"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_secret_exists() {
        env::set_var("TEST_SECRET_123", "secret-value");
        let provider = EnvProvider::new();
        let secret = provider.get_secret("TEST_SECRET_123").await.unwrap();
        assert_eq!(secret.expose(), "secret-value");
        env::remove_var("TEST_SECRET_123");
    }

    #[tokio::test]
    async fn test_get_secret_not_found() {
        let provider = EnvProvider::new();
        let result = provider.get_secret("NONEXISTENT_VAR_XYZ").await;
        assert!(matches!(result, Err(SecretsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_get_secret_optional_exists() {
        env::set_var("TEST_OPTIONAL_123", "optional-value");
        let provider = EnvProvider::new();
        let secret = provider.get_secret_optional("TEST_OPTIONAL_123").await;
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().expose(), "optional-value");
        env::remove_var("TEST_OPTIONAL_123");
    }

    #[tokio::test]
    async fn test_get_secret_optional_not_found() {
        let provider = EnvProvider::new();
        let secret = provider
            .get_secret_optional("NONEXISTENT_OPTIONAL_XYZ")
            .await;
        assert!(secret.is_none());
    }

    #[tokio::test]
    async fn test_clear_after_read() {
        env::set_var("TEST_CLEAR_123", "to-be-cleared");
        let provider = EnvProvider::new().with_clear_after_read();

        let secret = provider.get_secret("TEST_CLEAR_123").await.unwrap();
        assert_eq!(secret.expose(), "to-be-cleared");

        // Variable should be cleared
        assert!(env::var("TEST_CLEAR_123").is_err());
    }

    #[test]
    fn test_provider_name() {
        let provider = EnvProvider::new();
        assert_eq!(provider.provider_name(), "env");
    }
}
