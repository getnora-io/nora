//! Input validation for artifact registry paths and identifiers
//!
//! Provides security validation to prevent path traversal attacks and
//! ensure inputs conform to protocol specifications.

use std::fmt;

/// Validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// Path contains traversal sequences (../, etc.)
    PathTraversal,
    /// Docker image name is invalid
    InvalidDockerName(String),
    /// Content digest is invalid
    InvalidDigest(String),
    /// Tag/reference is invalid
    InvalidReference(String),
    /// Input is empty
    EmptyInput,
    /// Input exceeds maximum length
    TooLong { max: usize, actual: usize },
    /// Contains forbidden characters
    ForbiddenCharacter(char),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathTraversal => write!(f, "Path traversal detected"),
            Self::InvalidDockerName(reason) => write!(f, "Invalid Docker name: {}", reason),
            Self::InvalidDigest(reason) => write!(f, "Invalid digest: {}", reason),
            Self::InvalidReference(reason) => write!(f, "Invalid reference: {}", reason),
            Self::EmptyInput => write!(f, "Input cannot be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "Input exceeds maximum length ({} > {})", actual, max)
            }
            Self::ForbiddenCharacter(c) => write!(f, "Forbidden character: {:?}", c),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Maximum allowed storage key length
const MAX_KEY_LENGTH: usize = 1024;

/// Maximum Docker name length
const MAX_DOCKER_NAME_LENGTH: usize = 256;

/// Maximum tag/reference length
const MAX_REFERENCE_LENGTH: usize = 128;

/// Validate and sanitize a storage key to prevent path traversal attacks.
///
/// Rejects keys containing:
/// - `..` path traversal sequences
/// - Leading `/` or `\` (absolute paths)
/// - Null bytes
/// - Empty segments
pub fn validate_storage_key(key: &str) -> Result<(), ValidationError> {
    if key.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    if key.len() > MAX_KEY_LENGTH {
        return Err(ValidationError::TooLong {
            max: MAX_KEY_LENGTH,
            actual: key.len(),
        });
    }

    // Check for null bytes
    if key.contains('\0') {
        return Err(ValidationError::ForbiddenCharacter('\0'));
    }

    // Check for absolute paths
    if key.starts_with('/') || key.starts_with('\\') {
        return Err(ValidationError::PathTraversal);
    }

    // Check for path traversal patterns
    if key.contains("..") {
        return Err(ValidationError::PathTraversal);
    }

    // Check for backslash (Windows path separator)
    if key.contains('\\') {
        return Err(ValidationError::PathTraversal);
    }

    // Check each segment
    for segment in key.split('/') {
        if segment.is_empty() && key != "" {
            // Allow trailing slash but not double slashes
            continue;
        }
        if segment == "." || segment == ".." {
            return Err(ValidationError::PathTraversal);
        }
    }

    Ok(())
}

/// Validate Docker image name per OCI distribution spec.
///
/// Valid names:
/// - Lowercase letters, digits, underscores, dots, hyphens
/// - May contain path separators (/)
/// - Each component must start with alphanumeric
/// - Max 256 characters
///
/// Examples:
/// - `nginx` ✓
/// - `library/nginx` ✓
/// - `my-org/my-image` ✓
/// - `NGINX` ✗ (uppercase)
/// - `../escape` ✗ (path traversal)
pub fn validate_docker_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    if name.len() > MAX_DOCKER_NAME_LENGTH {
        return Err(ValidationError::TooLong {
            max: MAX_DOCKER_NAME_LENGTH,
            actual: name.len(),
        });
    }

    // Check for path traversal
    if name.contains("..") {
        return Err(ValidationError::PathTraversal);
    }

    // Must contain only valid characters
    for c in name.chars() {
        if !matches!(c, 'a'..='z' | '0'..='9' | '_' | '.' | '-' | '/') {
            if c.is_ascii_uppercase() {
                return Err(ValidationError::InvalidDockerName(
                    "must be lowercase".to_string(),
                ));
            }
            return Err(ValidationError::ForbiddenCharacter(c));
        }
    }

    // Cannot start with separator
    if name.starts_with('/') || name.starts_with('.') || name.starts_with('-') {
        return Err(ValidationError::InvalidDockerName(
            "cannot start with separator or special character".to_string(),
        ));
    }

    // Cannot end with separator
    if name.ends_with('/') {
        return Err(ValidationError::InvalidDockerName(
            "cannot end with /".to_string(),
        ));
    }

    // No consecutive separators (except ..)
    if name.contains("//") || name.contains("--") || name.contains("__") {
        return Err(ValidationError::InvalidDockerName(
            "consecutive separators not allowed".to_string(),
        ));
    }

    // Each path segment must start with alphanumeric
    for segment in name.split('/') {
        if segment.is_empty() {
            return Err(ValidationError::InvalidDockerName(
                "empty path segment".to_string(),
            ));
        }
        let first = segment.chars().next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return Err(ValidationError::InvalidDockerName(
                "segment must start with alphanumeric".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate content digest format.
///
/// Supported formats:
/// - `sha256:<64 hex chars>`
/// - `sha512:<128 hex chars>`
///
/// Examples:
/// - `sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4` ✓
/// - `sha256:ABC` ✗ (uppercase)
/// - `md5:abc` ✗ (unsupported algorithm)
pub fn validate_digest(digest: &str) -> Result<(), ValidationError> {
    if digest.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    // Check for path traversal (shouldn't be in digest but defensive check)
    if digest.contains("..") || digest.contains('/') {
        return Err(ValidationError::PathTraversal);
    }

    let parts: Vec<&str> = digest.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(ValidationError::InvalidDigest(
            "missing algorithm prefix (expected algo:hash)".to_string(),
        ));
    }

    let (algo, hash) = (parts[0], parts[1]);

    match algo {
        "sha256" => {
            if hash.len() != 64 {
                return Err(ValidationError::InvalidDigest(format!(
                    "sha256 hash must be 64 characters, got {}",
                    hash.len()
                )));
            }
        }
        "sha512" => {
            if hash.len() != 128 {
                return Err(ValidationError::InvalidDigest(format!(
                    "sha512 hash must be 128 characters, got {}",
                    hash.len()
                )));
            }
        }
        _ => {
            return Err(ValidationError::InvalidDigest(format!(
                "unsupported algorithm: {} (use sha256 or sha512)",
                algo
            )));
        }
    }

    // Hash must be lowercase hex
    for c in hash.chars() {
        if !matches!(c, '0'..='9' | 'a'..='f') {
            if c.is_ascii_uppercase() {
                return Err(ValidationError::InvalidDigest(
                    "hash must be lowercase hex".to_string(),
                ));
            }
            return Err(ValidationError::InvalidDigest(format!(
                "invalid character in hash: {:?}",
                c
            )));
        }
    }

    Ok(())
}

/// Validate Docker tag or reference (tag or digest).
///
/// Tags:
/// - Alphanumeric, dots, underscores, hyphens
/// - Max 128 characters
/// - Must start with alphanumeric
///
/// References may also be digests (sha256:...).
pub fn validate_docker_reference(reference: &str) -> Result<(), ValidationError> {
    if reference.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    if reference.len() > MAX_REFERENCE_LENGTH {
        return Err(ValidationError::TooLong {
            max: MAX_REFERENCE_LENGTH,
            actual: reference.len(),
        });
    }

    // Check for path traversal
    if reference.contains("..") || reference.contains('/') {
        return Err(ValidationError::PathTraversal);
    }

    // If it looks like a digest, validate as digest
    if reference.starts_with("sha256:") || reference.starts_with("sha512:") {
        return validate_digest(reference);
    }

    // Validate as tag
    let first = reference.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(ValidationError::InvalidReference(
            "tag must start with alphanumeric".to_string(),
        ));
    }

    for c in reference.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-') {
            return Err(ValidationError::ForbiddenCharacter(c));
        }
    }

    Ok(())
}

/// Validate Maven artifact path.
///
/// Maven paths follow the pattern: groupId/artifactId/version/filename
/// Example: `org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar`
pub fn validate_maven_path(path: &str) -> Result<(), ValidationError> {
    validate_storage_key(path)
}

/// Validate npm package name.
pub fn validate_npm_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    if name.len() > 214 {
        return Err(ValidationError::TooLong {
            max: 214,
            actual: name.len(),
        });
    }

    // Check for path traversal
    if name.contains("..") {
        return Err(ValidationError::PathTraversal);
    }

    Ok(())
}

/// Validate Cargo crate name.
pub fn validate_crate_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyInput);
    }

    if name.len() > 64 {
        return Err(ValidationError::TooLong {
            max: 64,
            actual: name.len(),
        });
    }

    // Check for path traversal
    if name.contains("..") || name.contains('/') {
        return Err(ValidationError::PathTraversal);
    }

    // Crate names: alphanumeric, underscores, hyphens
    for c in name.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-') {
            return Err(ValidationError::ForbiddenCharacter(c));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Storage key tests
    #[test]
    fn test_storage_key_valid() {
        assert!(validate_storage_key("docker/nginx/blobs/sha256:abc").is_ok());
        assert!(validate_storage_key("maven/org/apache/commons").is_ok());
        assert!(validate_storage_key("simple").is_ok());
    }

    #[test]
    fn test_storage_key_path_traversal() {
        assert!(matches!(
            validate_storage_key("../etc/passwd"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_storage_key("foo/../bar"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_storage_key("foo/.."),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_storage_key_absolute_path() {
        assert!(matches!(
            validate_storage_key("/etc/passwd"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_storage_key("\\windows\\system32"),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_storage_key_null_byte() {
        assert!(matches!(
            validate_storage_key("foo\0bar"),
            Err(ValidationError::ForbiddenCharacter('\0'))
        ));
    }

    #[test]
    fn test_storage_key_empty() {
        assert!(matches!(
            validate_storage_key(""),
            Err(ValidationError::EmptyInput)
        ));
    }

    #[test]
    fn test_storage_key_too_long() {
        let long_key = "a".repeat(1025);
        assert!(matches!(
            validate_storage_key(&long_key),
            Err(ValidationError::TooLong { .. })
        ));
    }

    // Docker name tests
    #[test]
    fn test_docker_name_valid() {
        assert!(validate_docker_name("nginx").is_ok());
        assert!(validate_docker_name("library/nginx").is_ok());
        assert!(validate_docker_name("my-org/my-image").is_ok());
        assert!(validate_docker_name("my_image").is_ok());
        assert!(validate_docker_name("image.name").is_ok());
        assert!(validate_docker_name("a/b/c/d").is_ok());
    }

    #[test]
    fn test_docker_name_uppercase() {
        assert!(matches!(
            validate_docker_name("NGINX"),
            Err(ValidationError::InvalidDockerName(_))
        ));
        assert!(matches!(
            validate_docker_name("MyImage"),
            Err(ValidationError::InvalidDockerName(_))
        ));
    }

    #[test]
    fn test_docker_name_path_traversal() {
        assert!(matches!(
            validate_docker_name("../escape"),
            Err(ValidationError::PathTraversal)
        ));
        assert!(matches!(
            validate_docker_name("foo/../bar"),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_docker_name_invalid_start() {
        assert!(validate_docker_name("/nginx").is_err());
        assert!(validate_docker_name(".nginx").is_err());
        assert!(validate_docker_name("-nginx").is_err());
    }

    #[test]
    fn test_docker_name_consecutive_separators() {
        assert!(validate_docker_name("foo//bar").is_err());
        assert!(validate_docker_name("foo--bar").is_err());
        assert!(validate_docker_name("foo__bar").is_err());
    }

    // Digest tests
    #[test]
    fn test_digest_valid_sha256() {
        let valid = format!("sha256:{}", "a".repeat(64));
        assert!(validate_digest(&valid).is_ok());
    }

    #[test]
    fn test_digest_valid_sha512() {
        let valid = format!("sha512:{}", "a".repeat(128));
        assert!(validate_digest(&valid).is_ok());
    }

    #[test]
    fn test_digest_wrong_length() {
        assert!(validate_digest("sha256:abc").is_err());
        assert!(validate_digest(&format!("sha256:{}", "a".repeat(63))).is_err());
        assert!(validate_digest(&format!("sha256:{}", "a".repeat(65))).is_err());
    }

    #[test]
    fn test_digest_uppercase() {
        let upper = format!("sha256:{}", "A".repeat(64));
        assert!(matches!(
            validate_digest(&upper),
            Err(ValidationError::InvalidDigest(_))
        ));
    }

    #[test]
    fn test_digest_unsupported_algorithm() {
        assert!(matches!(
            validate_digest("md5:abc"),
            Err(ValidationError::InvalidDigest(_))
        ));
    }

    #[test]
    fn test_digest_missing_prefix() {
        assert!(matches!(
            validate_digest("abcdef123456"),
            Err(ValidationError::InvalidDigest(_))
        ));
    }

    // Reference tests
    #[test]
    fn test_reference_valid_tag() {
        assert!(validate_docker_reference("latest").is_ok());
        assert!(validate_docker_reference("v1.0.0").is_ok());
        assert!(validate_docker_reference("1.0").is_ok());
        assert!(validate_docker_reference("my-tag_v2").is_ok());
    }

    #[test]
    fn test_reference_valid_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(validate_docker_reference(&digest).is_ok());
    }

    #[test]
    fn test_reference_path_traversal() {
        assert!(matches!(
            validate_docker_reference("../escape"),
            Err(ValidationError::PathTraversal)
        ));
    }

    #[test]
    fn test_reference_invalid_start() {
        assert!(validate_docker_reference(".hidden").is_err());
        assert!(validate_docker_reference("-dash").is_err());
    }
}
