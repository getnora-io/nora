// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Input validation for artifact registry paths and identifiers
//!
//! Provides security validation to prevent path traversal attacks and
//! ensure inputs conform to protocol specifications.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
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

/// Case-insensitive suffix check for file extensions.
///
/// Avoids allocating a lowercased copy of the whole string.
pub fn ends_with_ci(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

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

    // Reject non-ASCII characters — all registry paths are ASCII-only
    if let Some(ch) = key.chars().find(|c| !c.is_ascii()) {
        return Err(ValidationError::ForbiddenCharacter(ch));
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
        if segment.is_empty() && !key.is_empty() {
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
        // Safety: segment.is_empty() checked above, but use match for defense-in-depth
        let Some(first) = segment.chars().next() else {
            return Err(ValidationError::InvalidDockerName(
                "empty path segment".to_string(),
            ));
        };
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
    // Safety: empty check at function start, but use let-else for defense-in-depth
    let Some(first) = reference.chars().next() else {
        return Err(ValidationError::EmptyInput);
    };
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

/// Middleware that rejects requests with null bytes in the URI path.
///
/// Null bytes in URLs are used in path-traversal attacks. Axum URL-decodes
/// `%00` before passing the path to handlers, which can cause panics or
/// unexpected 500 errors. This middleware intercepts null bytes early and
/// returns a clean 400 Bad Request.
pub async fn reject_null_bytes_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();

    // Check for literal null byte (already URL-decoded by hyper) or
    // percent-encoded null byte in the raw URI.
    if path.contains('\0') || path.contains("%00") || path.contains("%2500") {
        return (
            StatusCode::BAD_REQUEST,
            "Bad Request: null byte in URL path",
        )
            .into_response();
    }

    next.run(request).await
}

/// Match an artifact namespace `value` (a slash-separated coordinate such as
/// `myorg/repo`) against a scope `pattern` using segment-aware glob semantics.
///
/// This is used to enforce OIDC `namespace_scope` and is intentionally **not**
/// the same matcher as the `sub`-claim glob in the OIDC provider: that one is
/// substring/contains-based and is unsafe for `/`-separated paths (e.g. `org*`
/// would match `org-evil`). This matcher is anchored at both ends and treats
/// `/` as a hard segment boundary.
///
/// Semantics (`*` never matches across `/` — a segment boundary is hard):
/// - the whole pattern `"*"` matches anything — the universal, backward-compatible
///   no-op used by the default `namespace_scope = ["*"]`.
/// - a `**` segment matches zero or more segments (`github/**` matches `github`,
///   `github/a`, and `github/a/b`). `**` is only a wildcard as a whole segment.
/// - within a segment, `*` matches any run of non-`/` characters: a bare `*`
///   segment matches exactly one segment (`github/*` matches `github/repo` but
///   not `github/a/b`), and `team-*-dev` matches `team-alpha-dev` but never
///   `team-alpha/dev`.
/// - segments without `*` must match literally.
///
/// Note `github*/x` matches `github-evil/x` — an intra-segment trailing `*`
/// behaves like any glob. Scopes that must not capture sibling namespaces
/// should end the literal part at a `/` boundary (`github/**`, not `github*`).
///
/// # Examples
/// ```ignore
/// assert!(namespace_match("*", "anything/at/all"));
/// assert!(namespace_match("github/*", "github/repo"));
/// assert!(!namespace_match("github/*", "github-evil/x"));
/// assert!(!namespace_match("github/*", "github/a/b"));
/// assert!(namespace_match("github/**", "github/a/b"));
/// assert!(namespace_match("team-*-dev", "team-alpha-dev"));
/// assert!(!namespace_match("team-*-dev", "team-alpha/dev"));
/// ```
pub fn namespace_match(pattern: &str, value: &str) -> bool {
    // Universal no-op: the default scope, and any explicit `*`, matches everything.
    if pattern == "*" {
        return true;
    }
    let pat: Vec<&str> = pattern.split('/').collect();
    let val: Vec<&str> = value.split('/').collect();
    segments_match(&pat, &val)
}

/// Recursive segment matcher backing [`namespace_match`]. Patterns are operator
/// config of a handful of segments, so the worst-case branching on `**` is not a
/// practical concern.
fn segments_match(pat: &[&str], val: &[&str]) -> bool {
    match pat.split_first() {
        // Pattern exhausted: match iff the value is also exhausted (anchored end).
        None => val.is_empty(),
        // `**` consumes zero or more value segments.
        Some((&"**", rest)) => {
            // Zero consumed:
            if segments_match(rest, val) {
                return true;
            }
            // One or more consumed (suffixes val[1..], val[2..], …, []):
            (0..val.len()).any(|i| segments_match(rest, &val[i + 1..]))
        }
        // Any other segment consumes exactly one value segment; `*` inside it
        // matches within that segment only (never across `/`).
        Some((&seg, rest)) => {
            !val.is_empty() && segment_glob(seg, val[0]) && segments_match(rest, &val[1..])
        }
    }
}

/// Char-level glob for one path segment: `*` matches any run of characters
/// (the segment split has already removed every `/`). Iterative single-star
/// backtracking — O(len(pattern) · len(value)) worst case, no recursion, so
/// adversarial fuzz inputs can't blow the stack or go exponential.
fn segment_glob(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    // Byte-wise is UTF-8-safe here: `*` is ASCII and never a continuation byte,
    // and non-wildcard bytes must be equal anyway.
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while vi < v.len() {
        if pi < p.len() && p[pi] == b'*' {
            backtrack = Some((pi, vi));
            pi += 1;
        } else if pi < p.len() && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
        } else if let Some((star_pi, star_vi)) = backtrack {
            // Let the last `*` absorb one more byte and retry after it.
            backtrack = Some((star_pi, star_vi + 1));
            pi = star_pi + 1;
            vi = star_vi + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&b| b == b'*')
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
    fn test_storage_key_non_ascii() {
        assert!(matches!(
            validate_storage_key("maven/com/café/1.0/file.jar"),
            Err(ValidationError::ForbiddenCharacter('é'))
        ));
        assert!(matches!(
            validate_storage_key("raw/ünïcödé.txt"),
            Err(ValidationError::ForbiddenCharacter(_))
        ));
        // ASCII-only paths remain valid
        assert!(validate_storage_key("maven/com/example/1.0/file.jar").is_ok());
        assert!(validate_storage_key("raw/file-name_v2.0.tar.gz").is_ok());
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Valid lowercase Docker name component
    fn docker_component() -> impl Strategy<Value = String> {
        "[a-z0-9][a-z0-9._-]{0,30}".prop_filter("no consecutive separators", |s| {
            !s.contains("..") && !s.contains("//") && !s.contains("--") && !s.contains("__")
        })
    }

    /// Valid sha256 hex string
    fn sha256_hex() -> impl Strategy<Value = String> {
        "[0-9a-f]{64}"
    }

    /// Valid Docker tag (no `..` or `/` which trigger path traversal rejection)
    fn docker_tag() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9][a-zA-Z0-9._-]{0,50}".prop_filter("no path traversal", |s| {
            !s.contains("..") && !s.contains('/')
        })
    }

    // === validate_storage_key ===

    proptest! {
        #[test]
        fn storage_key_never_panics(s in "\\PC{0,2000}") {
            let _ = validate_storage_key(&s);
        }

        #[test]
        fn storage_key_rejects_path_traversal(
            prefix in "[a-z]{0,10}",
            suffix in "[a-z]{0,10}"
        ) {
            let key = format!("{}/../{}", prefix, suffix);
            prop_assert!(validate_storage_key(&key).is_err());
        }

        #[test]
        fn storage_key_rejects_absolute(path in "/[a-z/]{1,50}") {
            prop_assert!(validate_storage_key(&path).is_err());
        }

        #[test]
        fn storage_key_accepts_valid(
            segments in prop::collection::vec("[a-z0-9]{1,20}", 1..5)
        ) {
            let key = segments.join("/");
            prop_assert!(validate_storage_key(&key).is_ok());
        }
    }

    // === validate_docker_name ===

    proptest! {
        #[test]
        fn docker_name_never_panics(s in "\\PC{0,500}") {
            let _ = validate_docker_name(&s);
        }

        #[test]
        fn docker_name_accepts_valid_single(name in docker_component()) {
            prop_assert!(validate_docker_name(&name).is_ok());
        }

        #[test]
        fn docker_name_accepts_valid_path(
            components in prop::collection::vec(docker_component(), 1..4)
        ) {
            let name = components.join("/");
            prop_assert!(validate_docker_name(&name).is_ok());
        }

        #[test]
        fn docker_name_rejects_uppercase(
            lower in "[a-z]{1,10}",
            upper in "[A-Z]{1,10}"
        ) {
            let name = format!("{}{}", lower, upper);
            prop_assert!(validate_docker_name(&name).is_err());
        }
    }

    // === validate_digest ===

    proptest! {
        #[test]
        fn digest_never_panics(s in "\\PC{0,200}") {
            let _ = validate_digest(&s);
        }

        #[test]
        fn digest_sha256_roundtrip(hash in sha256_hex()) {
            let digest = format!("sha256:{}", hash);
            prop_assert!(validate_digest(&digest).is_ok());
        }

        #[test]
        fn digest_sha512_roundtrip(hash in "[0-9a-f]{128}") {
            let digest = format!("sha512:{}", hash);
            prop_assert!(validate_digest(&digest).is_ok());
        }

        #[test]
        fn digest_wrong_algo_rejected(
            algo in "[a-z]{2,8}",
            hash in "[0-9a-f]{64}"
        ) {
            prop_assume!(algo != "sha256" && algo != "sha512");
            let digest = format!("{}:{}", algo, hash);
            prop_assert!(validate_digest(&digest).is_err());
        }
    }

    // === validate_docker_reference ===

    proptest! {
        #[test]
        fn reference_never_panics(s in "\\PC{0,200}") {
            let _ = validate_docker_reference(&s);
        }

        #[test]
        fn reference_accepts_valid_tag(tag in docker_tag()) {
            prop_assert!(validate_docker_reference(&tag).is_ok());
        }

        #[test]
        fn reference_accepts_valid_digest(hash in sha256_hex()) {
            let reference = format!("sha256:{}", hash);
            prop_assert!(validate_docker_reference(&reference).is_ok());
        }

        #[test]
        fn reference_rejects_traversal(
            prefix in "[a-z]{0,5}",
            suffix in "[a-z]{0,5}"
        ) {
            let reference = format!("{}../{}", prefix, suffix);
            prop_assert!(validate_docker_reference(&reference).is_err());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod namespace_match_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn star_pattern_is_universal_noop() {
        // The default `namespace_scope = ["*"]` must match everything.
        assert!(namespace_match("*", "myorg/repo"));
        assert!(namespace_match("*", "a/b/c/d"));
        assert!(namespace_match("*", "single"));
        assert!(namespace_match("*", ""));
    }

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(namespace_match("github/*", "github/repo"));
        // …but not zero and not more than one.
        assert!(!namespace_match("github/*", "github"));
        assert!(!namespace_match("github/*", "github/a/b"));
    }

    #[test]
    fn double_star_matches_zero_or_more_segments() {
        assert!(namespace_match("github/**", "github")); // zero
        assert!(namespace_match("github/**", "github/a")); // one
        assert!(namespace_match("github/**", "github/a/b")); // many
        assert!(!namespace_match("github/**", "other/a")); // wrong prefix
    }

    #[test]
    fn prefix_lookalikes_do_not_match() {
        // The headline requirement of #583: `github/*` must NOT match `github-evil`.
        assert!(!namespace_match("github/*", "github-evil/x"));
        assert!(!namespace_match("github/**", "github-evil/x"));
        assert!(!namespace_match("github/**", "github_evil/x"));
        assert!(!namespace_match("github", "github-evil"));
    }

    #[test]
    fn matching_is_anchored_not_substring() {
        // Unlike the sub-claim glob, this matcher does not do `contains`.
        assert!(!namespace_match("foo", "xfooy"));
        assert!(!namespace_match("org", "org/sub")); // literal != prefix
        assert!(!namespace_match("sub", "org/sub")); // literal != suffix
        assert!(namespace_match("org", "org"));
    }

    #[test]
    fn exact_literal_paths() {
        assert!(namespace_match("myorg/team/repo", "myorg/team/repo"));
        assert!(!namespace_match("myorg/team/repo", "myorg/team/other"));
        assert!(!namespace_match("myorg/team", "myorg/team/repo"));
    }

    #[test]
    fn intra_segment_star_matches_within_segment() {
        assert!(namespace_match("my*org/*", "myXXXorg/repo"));
        assert!(namespace_match("team-*-dev-*", "team-alpha-dev-client"));
        assert!(namespace_match("*-dev", "team-dev")); // leading
        assert!(namespace_match("team-*", "team-")); // zero-width
        assert!(!namespace_match("team-*-dev", "team-alpha-prod"));
        // Multiple stars backtrack correctly.
        assert!(namespace_match("*ab*ab", "abxab"));
        assert!(!namespace_match("*ab*ab", "abab-x"));
    }

    #[test]
    fn intra_segment_star_never_crosses_segment_boundary() {
        // The security property inherited from whole-segment matching: `*`
        // absorbs characters only inside its own segment.
        assert!(!namespace_match("team-*-dev", "team-alpha/dev"));
        assert!(!namespace_match("a*b", "a/b"));
        assert!(!namespace_match("github/x*y", "github/x/y"));
        // Segment count still has to line up.
        assert!(!namespace_match("my*org", "myXXXorg/repo"));
    }

    proptest! {
        // The universal no-op holds for any value.
        #[test]
        fn prop_star_matches_anything(s in "[a-zA-Z0-9/@._-]{0,60}") {
            prop_assert!(namespace_match("*", &s));
        }

        // Anti prefix-confusion: `org/*` never matches `org<sep>rest/...`.
        #[test]
        fn prop_prefix_star_rejects_lookalike(
            org in "[a-z][a-z0-9]{0,9}",
            sep in "[-_.]",
            rest in "[a-z][a-z0-9]{0,7}",
            tail in "[a-z][a-z0-9]{0,7}",
        ) {
            let pattern = format!("{}/*", org);
            let value = format!("{}{}{}/{}", org, sep, rest, tail);
            prop_assert!(!namespace_match(&pattern, &value));
        }

        // Anchoring: a single literal segment never matches a strictly longer
        // segment that merely contains it.
        #[test]
        fn prop_literal_segment_is_anchored(
            pre in "[a-z]{1,4}",
            seg in "[a-z]{2,8}",
            post in "[a-z]{1,4}",
        ) {
            let value = format!("{}{}{}", pre, seg, post);
            prop_assert!(!namespace_match(&seg, &value));
        }

        // `prefix/**` matches every value under `prefix/`.
        #[test]
        fn prop_double_star_matches_all_descendants(
            prefix in "[a-z][a-z0-9]{0,9}",
            descendant in "[a-z][a-z0-9/]{0,30}",
        ) {
            let pattern = format!("{}/**", prefix);
            let value = format!("{}/{}", prefix, descendant);
            prop_assert!(namespace_match(&pattern, &value));
        }

        // An intra-segment `*` absorbs any run of characters inside one segment…
        #[test]
        fn prop_intra_segment_star_matches_within_segment(
            pre in "[a-z]{0,6}",
            mid in "[a-z0-9._-]{0,12}",
            post in "[a-z]{0,6}",
        ) {
            let pattern = format!("{}*{}", pre, post);
            let value = format!("{}{}{}", pre, mid, post);
            prop_assert!(namespace_match(&pattern, &value));
        }

        // …but never across a `/`: the value's extra segment can't be eaten.
        #[test]
        fn prop_intra_segment_star_never_crosses_slash(
            pre in "[a-z]{1,6}",
            left in "[a-z]{0,8}",
            right in "[a-z]{1,8}",
            post in "[a-z]{1,6}",
        ) {
            let pattern = format!("{}*{}", pre, post);
            let value = format!("{}{}/{}{}", pre, left, right, post);
            prop_assert!(!namespace_match(&pattern, &value));
        }

        // Patterns without `*` are exact equality — unchanged by glob support.
        #[test]
        fn prop_starless_pattern_is_exact_match(
            a in "[a-z]{1,8}(/[a-z]{1,8}){0,3}",
            b in "[a-z]{1,8}(/[a-z]{1,8}){0,3}",
        ) {
            prop_assert_eq!(namespace_match(&a, &b), a == b);
        }
    }
}
