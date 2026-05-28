// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Protected secret types with memory safety
//!
//! Secrets are automatically zeroed on drop and redacted in Debug output.
//! Used for all credential fields in [`Config`](crate::config::Config) to
//! prevent accidental plaintext logging and ensure memory cleanup.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A protected secret string that is zeroed on drop.
///
/// - Implements Zeroize: memory is overwritten with zeros when dropped
/// - Debug shows `***REDACTED***` instead of actual value
/// - Clone creates a new protected copy (also zeroed on drop)
/// - Deserialize accepts a plain string from config (TOML/JSON/YAML)
/// - Does **not** implement Serialize — credential fields must use
///   `#[serde(skip_serializing)]` to prevent accidental re-serialization
/// - Does **not** implement `Deref<Target=str>` — callers must use
///   [`expose()`](ProtectedString::expose) explicitly
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ProtectedString {
    inner: String,
}

impl ProtectedString {
    /// Create a new protected string.
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Get the secret value.
    ///
    /// **Use sparingly!** The returned `&str` is not protected against
    /// accidental logging. Never pass the result to `debug!`/`info!`/etc.
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Consume and return the inner value wrapped in [`Zeroizing`].
    pub fn into_inner(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.inner))
    }

    /// Check if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Expose the inner `&str` from an `Option<ProtectedString>`.
///
/// Convenience helper for the common pattern in registry handlers:
/// ```rust,ignore
/// // Before: config.npm.proxy_auth.as_deref()
/// // After:  expose_opt(&config.npm.proxy_auth)
/// ```
pub fn expose_opt(opt: &Option<ProtectedString>) -> Option<&str> {
    opt.as_ref().map(|s| s.expose())
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedString")
            .field("value", &"***REDACTED***")
            .finish()
    }
}

impl fmt::Display for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***REDACTED***")
    }
}

impl From<String> for ProtectedString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ProtectedString {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

/// Custom Deserialize: accepts a plain string and wraps it in ProtectedString.
///
/// This preserves backwards compatibility with existing TOML config files
/// where credentials are written as `proxy_auth = "user:pass"`.
impl<'de> serde::Deserialize<'de> for ProtectedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(ProtectedString::new(s))
    }
}

/// S3 credentials with protected secrets
#[allow(dead_code)] // Scaffolding for future secrets integration (Vault, AWS SM, K8s)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct S3Credentials {
    #[zeroize(skip)] // access_key_id is not sensitive
    pub access_key_id: String,
    pub secret_access_key: ProtectedString,
    pub region: Option<String>,
}

#[allow(dead_code)]
impl S3Credentials {
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key: ProtectedString::new(secret_access_key),
            region: None,
        }
    }

    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }
}

impl fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"***REDACTED***")
            .field("region", &self.region)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_string_redacted_debug() {
        let secret = ProtectedString::new("super-secret-value".to_string());
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("super-secret-value"));
    }

    #[test]
    fn test_protected_string_redacted_display() {
        let secret = ProtectedString::new("super-secret-value".to_string());
        let display_output = format!("{}", secret);
        assert_eq!(display_output, "***REDACTED***");
    }

    #[test]
    fn test_protected_string_expose() {
        let secret = ProtectedString::new("my-secret".to_string());
        assert_eq!(secret.expose(), "my-secret");
    }

    #[test]
    fn test_s3_credentials_redacted_debug() {
        let creds = S3Credentials::new(
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        );
        let debug_output = format!("{:?}", creds);
        assert!(debug_output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug_output.contains("wJalrXUtnFEMI"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_protected_string_from_str() {
        let secret: ProtectedString = "test".into();
        assert_eq!(secret.expose(), "test");
    }

    #[test]
    fn test_protected_string_is_empty() {
        let empty = ProtectedString::new(String::new());
        let non_empty = ProtectedString::new("secret".to_string());
        assert!(empty.is_empty());
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_protected_string_deserialize() {
        let json = "\"my-secret-value\"";
        let secret: ProtectedString = serde_json::from_str(json).expect("deserialize");
        assert_eq!(secret.expose(), "my-secret-value");
        // Debug must not leak
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("my-secret-value"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_expose_opt() {
        let some = Some(ProtectedString::from("secret"));
        let none: Option<ProtectedString> = None;
        assert_eq!(expose_opt(&some), Some("secret"));
        assert_eq!(expose_opt(&none), None);
    }
}
