// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! Protected secret types with memory safety
//!
//! Secrets are automatically zeroed on drop and redacted in Debug output.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A protected secret string that is zeroed on drop
///
/// - Implements Zeroize: memory is overwritten with zeros when dropped
/// - Debug shows `***REDACTED***` instead of actual value
/// - Clone creates a new protected copy
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ProtectedString {
    inner: String,
}

impl ProtectedString {
    /// Create a new protected string
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Get the secret value (use sparingly!)
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Consume and return the inner value
    pub fn into_inner(self) -> Zeroizing<String> {
        Zeroizing::new(self.inner.clone())
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
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

/// S3 credentials with protected secrets
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct S3Credentials {
    pub access_key_id: String,
    #[zeroize(skip)] // access_key_id is not sensitive
    pub secret_access_key: ProtectedString,
    pub region: Option<String>,
}

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
}
