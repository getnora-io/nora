// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Curation layer — package access control for proxy registries.
//!
//! This module provides the curation filter chain:
//! - [`ProxyFilter`] trait that individual filters implement
//! - [`BlocklistFilter`] — blocks packages by name/version/registry (issue #186)
//! - [`AllowlistFilter`] — default-deny approved packages (issue #188)
//! - [`NamespaceFilter`] — namespace isolation, always active (issue #185)
//! - [`CurationEngine`] that evaluates a chain of filters
//! - [`BlockedResponse`] for generating 403 responses
//! - [`CurationMetrics`] for raw counters

use crate::config::{CurationConfig, CurationMode};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;

// ============================================================================
// Registry Type (re-export from shared module)
// ============================================================================

pub use crate::registry_type::RegistryType;

// ============================================================================
// Filter Request
// ============================================================================

/// Information about a package request, passed to each filter.
#[derive(Debug, Clone)]
pub struct FilterRequest {
    /// Which registry format this request targets.
    pub registry: RegistryType,
    /// Upstream URL being proxied to (if any).
    pub upstream: Option<String>,
    /// Package/artifact name (e.g., "lodash", "com.google.guava:guava").
    pub name: String,
    /// Version string (e.g., "4.17.21", "33.0.0-jre").
    pub version: Option<String>,
    /// Integrity hash provided by the client (e.g., sha256 checksum).
    pub integrity: Option<String>,
    /// Whether the request carries a valid bypass token.
    pub bypass: bool,
    /// Publish date as Unix timestamp (seconds). None = unknown.
    pub publish_date: Option<i64>,
}

// ============================================================================
// Decision
// ============================================================================

/// Outcome of a single filter evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Explicitly allow this request.
    Allow,
    /// Block this request with a rule name and human-readable reason.
    Block { rule: String, reason: String },
    /// This filter has no opinion — continue to the next filter.
    Skip,
}

// ============================================================================
// ProxyFilter Trait
// ============================================================================

/// A synchronous filter that evaluates a package request.
///
/// Filters must be fast — they operate on in-memory data only, no I/O.
/// Each filter returns [`Decision::Allow`], [`Decision::Block`], or
/// [`Decision::Skip`] to defer to the next filter in the chain.
pub trait ProxyFilter: Send + Sync {
    /// Unique name of this filter (e.g., "blocklist", "allowlist").
    fn name(&self) -> &'static str;

    /// Evaluate a request and return a decision.
    fn evaluate(&self, request: &FilterRequest) -> Decision;
}

// ============================================================================
// Evaluation Result
// ============================================================================

/// Full result of running the filter chain.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The final decision after the chain ran.
    pub decision: Decision,
    /// Name of the filter that produced the decision (None if no filter matched).
    pub decided_by: Option<String>,
    /// Whether this result is audit-only (decision logged but not enforced).
    pub audited: bool,
}

// ============================================================================
// Curation Engine
// ============================================================================

/// The curation engine runs a chain of [`ProxyFilter`]s in order.
pub struct CurationEngine {
    config: CurationConfig,
    filters: Vec<Box<dyn ProxyFilter>>,
    /// Namespace isolation filter — always active, even in Off mode.
    namespace_filter: Option<Box<dyn ProxyFilter>>,
    metrics: CurationMetrics,
}

impl CurationEngine {
    /// Create a new engine with no filters.
    pub fn new(config: CurationConfig) -> Self {
        Self {
            config,
            filters: Vec::new(),
            namespace_filter: None,
            metrics: CurationMetrics::new(),
        }
    }

    /// Add a filter to the end of the chain.
    /// Evaluation order = insertion order.
    pub fn add_filter(&mut self, filter: Box<dyn ProxyFilter>) {
        self.filters.push(filter);
    }

    /// Set the namespace isolation filter (always active, even in Off mode).
    pub fn set_namespace_filter(&mut self, filter: Box<dyn ProxyFilter>) {
        self.namespace_filter = Some(filter);
    }

    /// Current operating mode.
    pub fn mode(&self) -> &CurationMode {
        &self.config.mode
    }

    /// Whether curation is active (not off).
    pub fn is_active(&self) -> bool {
        self.config.mode != CurationMode::Off
    }

    /// Access raw metrics counters.
    pub fn metrics(&self) -> &CurationMetrics {
        &self.metrics
    }

    /// Evaluate a request through the filter chain.
    ///
    /// - **Off**: returns Allow immediately, no filters run, no metrics.
    /// - **Bypass**: returns Allow with a security warning log.
    /// - **Chain**: first Block or Allow wins; Skip continues.
    /// - **Audit**: Block decisions are returned with `audited=true`.
    /// - **Enforce**: Block decisions are final.
    /// - All Skip → Allow.
    pub fn evaluate(&self, request: &FilterRequest) -> EvaluationResult {
        // Namespace isolation: ALWAYS active, even in Off mode.
        // Prevents dependency confusion regardless of curation config.
        if let Some(ref ns_filter) = self.namespace_filter {
            let decision = ns_filter.evaluate(request);
            if let Decision::Block { .. } = &decision {
                self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
                return EvaluationResult {
                    decision,
                    decided_by: Some(ns_filter.name().to_string()),
                    audited: false, // namespace blocks are never audit-only
                };
            }
        }

        // Mode=Off: no-op
        if self.config.mode == CurationMode::Off {
            return EvaluationResult {
                decision: Decision::Allow,
                decided_by: None,
                audited: false,
            };
        }

        // Bypass token
        if request.bypass {
            self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                registry = %request.registry,
                package = %request.name,
                "[SECURITY] Curation bypassed via token"
            );
            return EvaluationResult {
                decision: Decision::Allow,
                decided_by: Some("bypass".to_string()),
                audited: false,
            };
        }

        // Track integrity presence
        if request.integrity.is_none() {
            self.metrics
                .without_integrity
                .fetch_add(1, Ordering::Relaxed);
        }

        // Run filter chain
        for filter in &self.filters {
            let decision = filter.evaluate(request);
            match &decision {
                Decision::Allow => {
                    self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                    return EvaluationResult {
                        decision,
                        decided_by: Some(filter.name().to_string()),
                        audited: false,
                    };
                }
                Decision::Block { .. } => {
                    let audited = self.config.mode == CurationMode::Audit;
                    if audited {
                        self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    return EvaluationResult {
                        decision,
                        decided_by: Some(filter.name().to_string()),
                        audited,
                    };
                }
                Decision::Skip => continue,
            }
        }

        // All filters skipped → Allow
        self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
        EvaluationResult {
            decision: Decision::Allow,
            decided_by: None,
            audited: false,
        }
    }
}

// ============================================================================
// check_download() — handler integration helper (issue #187)
// ============================================================================

/// Check curation policy for a download request.
///
/// Returns `Some(Response)` if blocked (403 in enforce mode), `None` to proceed.
/// In audit mode, logs the decision but returns `None` (request proceeds).
/// In off mode (with no namespace match), returns `None` immediately.
///
/// Bypass: if the request carries `X-Nora-Bypass-Token` matching the configured
/// token, curation is bypassed (namespace filter still applies).
pub fn check_download(
    engine: &CurationEngine,
    bypass_token: Option<&str>,
    headers: &axum::http::HeaderMap,
    registry: RegistryType,
    name: &str,
    version: Option<&str>,
    publish_date: Option<i64>,
) -> Option<Response> {
    let bypass = match bypass_token {
        Some(token) => headers
            .get("x-nora-bypass-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                // Constant-time comparison to prevent timing side-channel
                v.as_bytes().ct_eq(token.as_bytes()).into()
            })
            .unwrap_or(false),
        None => false,
    };

    let request = FilterRequest {
        registry,
        upstream: None,
        name: name.to_string(),
        version: version.map(|v| v.to_string()),
        integrity: None,
        bypass,
        publish_date,
    };

    let result = engine.evaluate(&request);

    match &result.decision {
        Decision::Block { rule, reason } => {
            if result.audited {
                tracing::info!(
                    registry = %registry,
                    package = %name,
                    version = version.unwrap_or("*"),
                    rule = %rule,
                    reason = %reason,
                    "[AUDIT] Download would be blocked"
                );
                None
            } else {
                Some(
                    BlockedResponse {
                        rule: rule.clone(),
                        reason: reason.clone(),
                        registry: registry.to_string(),
                        package: name.to_string(),
                        version: version.map(|v| v.to_string()),
                    }
                    .into_response(),
                )
            }
        }
        Decision::Allow | Decision::Skip => None,
    }
}

/// Extract publish date from file mtime. ONLY for hosted registries —
/// proxy mtime reflects cache time, not actual publish date.
// TODO(v1.0): trust_upstream_dates config for high-security installs
pub async fn extract_mtime_as_publish_date(
    storage: &crate::storage::Storage,
    key: &str,
) -> Option<i64> {
    storage.stat(key).await.map(|m| m.modified as i64)
}

/// Parse an ISO 8601 / RFC 3339 date string to a Unix timestamp (seconds).
///
/// Handles common formats from registry metadata:
/// - `2024-01-15T10:30:00Z` (Go .info `Time` field)
/// - `2024-01-15T10:30:00.123Z` (npm `time` field)
/// - `2024-01-15T10:30:00+00:00` (PyPI `upload_time_iso_8601`)
/// - `2024-01-15T10:30:00.000+0000` (Conan `time` field — non-standard tz offset)
///
/// Returns `None` if the string is not parseable.
pub fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    use chrono::{DateTime, FixedOffset, NaiveDateTime};

    // Try RFC 3339 / ISO 8601 with timezone
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }

    // Try without timezone (assume UTC) — some registries omit the Z
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(ndt.and_utc().timestamp());
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(ndt.and_utc().timestamp());
    }

    // Try non-standard offset format without colon: +0000, +0530
    // (Conan center uses this format)
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(dt.timestamp());
    }
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.timestamp());
    }

    None
}

/// Verify artifact integrity after download (post-download phase, issue #189).
///
/// Computes SHA-256 of `data`, then runs curation evaluation with the hash
/// filled in `FilterRequest.integrity`. This catches integrity mismatches
/// against allowlist entries.
///
/// Returns `Some(Response)` if integrity check fails (403), `None` to proceed.
pub fn verify_integrity(
    engine: &CurationEngine,
    registry: RegistryType,
    name: &str,
    version: Option<&str>,
    data: &[u8],
) -> Option<Response> {
    // Only run if curation is active (not Off)
    if !engine.is_active() {
        return None;
    }

    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    let integrity = format!("sha256:{}", hex::encode(hash));

    let request = FilterRequest {
        registry,
        upstream: None,
        name: name.to_string(),
        version: version.map(|v| v.to_string()),
        integrity: Some(integrity),
        bypass: false, // bypass already checked in pre-download phase
        publish_date: None,
    };

    let result = engine.evaluate(&request);

    match &result.decision {
        Decision::Block { rule, reason } => {
            // Only act on integrity-related blocks
            if !rule.contains("integrity") {
                return None;
            }
            if result.audited {
                tracing::info!(
                    registry = %registry,
                    package = %name,
                    version = version.unwrap_or("*"),
                    rule = %rule,
                    reason = %reason,
                    "[AUDIT] Integrity check would block download"
                );
                None
            } else {
                Some(
                    BlockedResponse {
                        rule: rule.clone(),
                        reason: reason.clone(),
                        registry: registry.to_string(),
                        package: name.to_string(),
                        version: version.map(|v| v.to_string()),
                    }
                    .into_response(),
                )
            }
        }
        Decision::Allow | Decision::Skip => None,
    }
}

// ============================================================================
// Version parsers for filename-based registries (issue #187)
// ============================================================================

/// Parse version from an npm tarball filename.
///
/// For scoped packages `@scope/name`, the tarball is `name-VERSION.tgz`.
/// For regular packages `name`, the tarball is `name-VERSION.tgz`.
pub fn parse_npm_tarball_version(package_name: &str, filename: &str) -> Option<String> {
    let filename = filename.strip_suffix(".tgz")?;
    // For scoped packages like @scope/name, tarball uses just "name" part
    let name_part = if package_name.contains('/') {
        package_name.rsplit('/').next()?
    } else {
        package_name
    };
    let version = filename.strip_prefix(name_part)?.strip_prefix('-')?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// Parse version from a PyPI download filename.
///
/// Handles: `.tar.gz`, `.zip`, `.whl`, `.egg`, `.tgz`
/// For wheels, version is between the first and second `-`.
pub fn parse_pypi_version(normalized_name: &str, filename: &str) -> Option<String> {
    // Strip known extensions
    let base = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tgz"))
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".whl"))
        .or_else(|| filename.strip_suffix(".egg"))?;

    // Normalize: PyPI filenames use underscores, normalized names use hyphens
    let name_underscore = normalized_name.replace('-', "_");
    let base_lower = base.to_lowercase();
    let prefix = format!("{}-", name_underscore.to_lowercase());

    let rest = base_lower.strip_prefix(&prefix)?;
    // For wheels: rest is "VERSION-py3-none-any" — take until next '-' that starts a tag
    // For sdist: rest is just "VERSION"
    // Heuristic: version chars are digits, dots, letters (rc, alpha, beta, post, dev)
    // Split at first '-' followed by non-digit (wheel tags like py3, cp39)
    let version = if filename.ends_with(".whl") {
        rest.split('-').next()?
    } else {
        rest
    };
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

// ============================================================================
// Blocked Response (403 JSON)
// ============================================================================

/// A 403 response body for blocked requests.
/// Used by registry handlers in #185-#189 when curation blocks a request.
pub struct BlockedResponse {
    pub rule: String,
    pub reason: String,
    pub registry: String,
    pub package: String,
    pub version: Option<String>,
}

impl IntoResponse for BlockedResponse {
    fn into_response(self) -> Response {
        let version_str = self.version.as_deref().unwrap_or("*");
        let body = serde_json::json!({
            "error": "blocked_by_policy",
            "error_version": "v1",
            "context": {
                "rule": self.rule,
                "reason": self.reason,
                "registry": self.registry,
                "package": self.package,
                "version": version_str,
            },
            "hint": format!("Run: nora curation explain {}@{}", self.package, version_str),
            "docs": "https://docs.getnora.dev/curation"
        });

        let mut response = (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
        let headers = response.headers_mut();
        // Safe to use expect: these are compile-time constant ASCII strings
        headers.insert(
            "x-nora-decision",
            "blocked".parse().expect("valid header value"),
        );
        headers.insert(
            "x-nora-rule",
            self.rule
                .parse()
                .unwrap_or_else(|_| "unknown".parse().expect("valid header value")),
        );
        headers.insert(
            "x-nora-reason",
            self.reason
                .parse()
                .unwrap_or_else(|_| "unknown".parse().expect("valid header value")),
        );
        response
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Raw atomic counters for curation decisions. No Prometheus wiring yet.
pub struct CurationMetrics {
    pub blocked: AtomicU64,
    pub allowed: AtomicU64,
    pub without_integrity: AtomicU64,
}

impl CurationMetrics {
    fn new() -> Self {
        Self {
            blocked: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            without_integrity: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Blocklist Filter (issue #185)
// ============================================================================

/// On-disk JSON schema for the blocklist file.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistFile {
    /// Schema version (must be 1).
    pub version: u32,
    /// List of block rules.
    pub rules: Vec<BlocklistRule>,
}

/// A single blocklist rule: matches packages by registry, name, and version.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistRule {
    /// Registry type to match: exact (e.g. "npm") or "*" for all.
    pub registry: String,
    /// Package name: exact, prefix glob ("foo*"), suffix glob ("*foo"), or "*".
    pub name: String,
    /// Version: exact or "*" for all versions.
    pub version: String,
    /// Human-readable reason shown in the 403 response.
    pub reason: String,
}

/// Simple glob matching without external dependencies.
///
/// Supports:
/// - `"*"` — matches everything
/// - `"foo.**"` — hierarchical prefix (dot OR colon separator, for Maven groupId:artifactId)
/// - `"foo/**"` — hierarchical prefix (slash separator, for Go modules)
/// - `"foo*"` — prefix match
/// - `"*foo"` — suffix match
/// - exact string comparison otherwise
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // "foo.**" → matches "foo" itself and "foo.anything" or "foo:anything" (Maven colon)
    if let Some(prefix) = pattern.strip_suffix(".**") {
        return value == prefix
            || value.starts_with(&format!("{}.", prefix))
            || value.starts_with(&format!("{}:", prefix));
    }
    // "foo/**" → matches "foo" itself and "foo/anything/deeper"
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return value == prefix || value.starts_with(&format!("{}/", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

/// A filter that blocks packages matching rules loaded from a JSON file.
///
/// Blocklist is checked first in the chain (overlay on allowlist).
/// First matching rule wins → `Decision::Block`.
/// No match → `Decision::Skip` (defer to next filter).
#[derive(Debug)]
pub struct BlocklistFilter {
    rules: Vec<BlocklistRule>,
}

impl BlocklistFilter {
    /// Load and validate a blocklist from a JSON file.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read blocklist file '{}': {}", path, e))?;

        let file: BlocklistFile = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse blocklist JSON '{}': {}", path, e))?;

        if file.version != 1 {
            return Err(format!(
                "unsupported blocklist version {} (expected 1)",
                file.version
            ));
        }

        Ok(Self { rules: file.rules })
    }

    /// Number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl ProxyFilter for BlocklistFilter {
    fn name(&self) -> &'static str {
        "blocklist"
    }

    fn evaluate(&self, request: &FilterRequest) -> Decision {
        let registry_str = request.registry.to_string();
        let version_str = request.version.as_deref().unwrap_or("");

        for rule in &self.rules {
            let registry_match = glob_match(&rule.registry, &registry_str);
            let name_match = glob_match(&rule.name, &request.name);
            let version_match = rule.version == "*" || glob_match(&rule.version, version_str);

            if registry_match && name_match && version_match {
                return Decision::Block {
                    rule: "blocklist".to_string(),
                    reason: rule.reason.clone(),
                };
            }
        }

        Decision::Skip
    }
}

// ============================================================================
// Allowlist Filter (issue #188)
// ============================================================================

/// On-disk JSON schema for the allowlist file.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistFile {
    /// Schema version (must be 1).
    pub version: u32,
    /// List of approved packages.
    pub entries: Vec<AllowlistEntry>,
}

/// A single allowlist entry: an approved (registry, name, version) tuple.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistEntry {
    /// Registry type: "npm", "pypi", "maven", etc.
    pub registry: String,
    /// Exact package name.
    pub name: String,
    /// Exact version string.
    pub version: String,
    /// Integrity hash (e.g., "sha256:abc123"). Optional.
    #[serde(default)]
    pub integrity: Option<String>,
    /// Source of the integrity hash: "upstream", "local", "manual".
    /// Informational only — not used in filter evaluation.
    #[serde(default)]
    #[allow(dead_code)]
    pub integrity_source: Option<String>,
}

/// Default-deny filter: only packages explicitly listed are allowed through.
///
/// Uses HashMap O(1) lookup by (registry, name, version).
/// Blocklist is evaluated first in the chain — blocklisted packages never reach this filter.
#[derive(Debug)]
pub struct AllowlistFilter {
    entries: std::collections::HashMap<(String, String, String), AllowlistEntry>,
    require_integrity: bool,
}

impl AllowlistFilter {
    /// Load and validate an allowlist from a JSON file.
    pub fn from_file(path: &str, require_integrity: bool) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read allowlist file '{}': {}", path, e))?;

        let file: AllowlistFile = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse allowlist JSON '{}': {}", path, e))?;

        if file.version != 1 {
            return Err(format!(
                "unsupported allowlist version {} (expected 1)",
                file.version
            ));
        }

        let mut entries = std::collections::HashMap::new();
        for entry in file.entries {
            let key = (
                entry.registry.clone(),
                entry.name.clone(),
                entry.version.clone(),
            );
            entries.insert(key, entry);
        }

        Ok(Self {
            entries,
            require_integrity,
        })
    }

    /// Number of entries loaded.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl ProxyFilter for AllowlistFilter {
    fn name(&self) -> &'static str {
        "allowlist"
    }

    fn evaluate(&self, request: &FilterRequest) -> Decision {
        // Metadata requests (no version) — skip, let through
        let version = match &request.version {
            Some(v) => v,
            None => return Decision::Skip,
        };

        let key = (
            request.registry.to_string(),
            request.name.clone(),
            version.clone(),
        );

        match self.entries.get(&key) {
            None => Decision::Block {
                rule: "allowlist".to_string(),
                reason: format!(
                    "Package '{}@{}' ({}) not in allowlist",
                    request.name, version, request.registry
                ),
            },
            Some(entry) => {
                // Integrity check only runs when request provides a hash
                // (post-download phase). Pre-download checks pass integrity=None
                // and skip this entirely.
                if let Some(ref actual_hash) = request.integrity {
                    if let Some(ref expected_hash) = entry.integrity {
                        if actual_hash != expected_hash {
                            return Decision::Block {
                                rule: "allowlist:integrity".to_string(),
                                reason: format!(
                                    "Integrity mismatch for '{}@{}': expected {}, got {}",
                                    request.name, version, expected_hash, actual_hash
                                ),
                            };
                        }
                    } else if self.require_integrity {
                        return Decision::Block {
                            rule: "allowlist:integrity".to_string(),
                            reason: format!(
                                "Allowlist entry '{}@{}' missing integrity hash (require_integrity=true)",
                                request.name, version
                            ),
                        };
                    }
                }
                Decision::Allow
            }
        }
    }
}

// ============================================================================
// Namespace Filter (issue #185)
// ============================================================================

/// Blocks packages matching internal namespace patterns.
///
/// This is a security boundary — always active regardless of curation mode.
/// Prevents dependency confusion by ensuring internal packages are never
/// proxied to upstream registries.
pub struct NamespaceFilter {
    patterns: Vec<String>,
}

impl NamespaceFilter {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    /// Number of configured patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl ProxyFilter for NamespaceFilter {
    fn name(&self) -> &'static str {
        "namespace"
    }

    fn evaluate(&self, request: &FilterRequest) -> Decision {
        for pattern in &self.patterns {
            if glob_match(pattern, &request.name) {
                return Decision::Block {
                    rule: "namespace".to_string(),
                    reason: format!(
                        "Package '{}' matches internal namespace '{}'",
                        request.name, pattern
                    ),
                };
            }
        }
        Decision::Skip
    }
}

// ============================================================================
// Tests
// ============================================================================

// ============================================================================
// MinReleaseAgeFilter — block packages younger than N seconds (supply chain)
// ============================================================================

/// Parse a human-readable duration string into seconds.
///
/// Supported formats: `"7d"` (days), `"24h"` (hours), `"1w"` (weeks).
/// Multiple units can be combined: `"1w2d"` = 9 days.
pub fn parse_duration(s: &str) -> Result<i64, String> {
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let mut total: i64 = 0;
    let mut num_buf = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else {
            if num_buf.is_empty() {
                return Err(format!("unexpected unit '{}' without number", ch));
            }
            let n: i64 = num_buf
                .parse()
                .map_err(|_| format!("invalid number '{}'", num_buf))?;
            num_buf.clear();

            match ch {
                'd' => total += n * 86400,
                'h' => total += n * 3600,
                'w' => total += n * 604800,
                _ => return Err(format!("unknown unit '{}' (use d/h/w)", ch)),
            }
        }
    }

    if !num_buf.is_empty() {
        return Err(format!(
            "trailing number '{}' without unit (use d/h/w)",
            num_buf
        ));
    }

    if total == 0 {
        return Err("duration must be greater than zero".to_string());
    }

    Ok(total)
}

/// Filter that blocks packages published less than `min_age_secs` ago.
///
/// If `publish_date` is `None` (unknown), the filter returns `Skip` (no opinion).
/// Supports per-registry overrides: if a registry has its own threshold,
/// it takes precedence over the global `min_age_secs`.
pub struct MinReleaseAgeFilter {
    min_age_secs: i64,
    label: String,
    /// Per-registry override thresholds (seconds).
    overrides: std::collections::HashMap<RegistryType, (i64, String)>,
}

impl MinReleaseAgeFilter {
    pub fn new(min_age_secs: i64, label: &str) -> Self {
        Self {
            min_age_secs,
            label: label.to_string(),
            overrides: std::collections::HashMap::new(),
        }
    }

    /// Add a per-registry override. If `registry` has its own min_release_age,
    /// it will be used instead of the global default.
    pub fn add_override(&mut self, registry: RegistryType, age_secs: i64, label: String) {
        self.overrides.insert(registry, (age_secs, label));
    }

    fn format_duration(secs: i64) -> String {
        if secs >= 604800 {
            let weeks = secs / 604800;
            let days = (secs % 604800) / 86400;
            if days > 0 {
                format!("{}w{}d", weeks, days)
            } else {
                format!("{}w", weeks)
            }
        } else if secs >= 86400 {
            format!("{}d", secs / 86400)
        } else {
            format!("{}h", secs / 3600)
        }
    }
}

impl ProxyFilter for MinReleaseAgeFilter {
    fn name(&self) -> &'static str {
        "min-release-age"
    }

    fn evaluate(&self, request: &FilterRequest) -> Decision {
        let Some(publish_ts) = request.publish_date else {
            return Decision::Skip; // Unknown date — don't block
        };

        // Use per-registry override if available, otherwise global default
        let (threshold, label) = if let Some((secs, lbl)) = self.overrides.get(&request.registry) {
            (*secs, lbl.as_str())
        } else {
            (self.min_age_secs, self.label.as_str())
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let age = now - publish_ts;
        if age < threshold {
            Decision::Block {
                rule: "min-release-age".to_string(),
                reason: format!(
                    "package is {} old (minimum: {})",
                    Self::format_duration(age.max(0)),
                    label,
                ),
            }
        } else {
            Decision::Skip
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{CurationConfig, CurationMode, CurationOnFailure};
    use sha2::Digest;

    /// A test filter that always allows.
    struct AllowAllFilter;
    impl ProxyFilter for AllowAllFilter {
        fn name(&self) -> &'static str {
            "allow-all"
        }
        fn evaluate(&self, _request: &FilterRequest) -> Decision {
            Decision::Allow
        }
    }

    /// A test filter that always blocks.
    struct BlockAllFilter;
    impl ProxyFilter for BlockAllFilter {
        fn name(&self) -> &'static str {
            "block-all"
        }
        fn evaluate(&self, _request: &FilterRequest) -> Decision {
            Decision::Block {
                rule: "block-all".to_string(),
                reason: "everything is blocked".to_string(),
            }
        }
    }

    /// A test filter that always skips.
    struct SkipFilter;
    impl ProxyFilter for SkipFilter {
        fn name(&self) -> &'static str {
            "skip"
        }
        fn evaluate(&self, _request: &FilterRequest) -> Decision {
            Decision::Skip
        }
    }

    /// A filter that blocks only a specific package.
    struct BlockPackageFilter {
        target: String,
    }
    impl ProxyFilter for BlockPackageFilter {
        fn name(&self) -> &'static str {
            "block-package"
        }
        fn evaluate(&self, request: &FilterRequest) -> Decision {
            if request.name == self.target {
                Decision::Block {
                    rule: "block-package".to_string(),
                    reason: format!("{} is blocked", self.target),
                }
            } else {
                Decision::Skip
            }
        }
    }

    fn make_request(name: &str) -> FilterRequest {
        FilterRequest {
            registry: RegistryType::Npm,
            upstream: Some("https://registry.npmjs.org".to_string()),
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            integrity: Some("sha256-abc123".to_string()),
            bypass: false,
            publish_date: None,
        }
    }

    fn make_request_no_integrity(name: &str) -> FilterRequest {
        FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: name.to_string(),
            version: None,
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    fn make_bypass_request(name: &str) -> FilterRequest {
        FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: name.to_string(),
            version: None,
            integrity: None,
            bypass: true,
            publish_date: None,
        }
    }

    fn audit_config() -> CurationConfig {
        CurationConfig {
            mode: CurationMode::Audit,
            ..CurationConfig::default()
        }
    }

    fn enforce_config() -> CurationConfig {
        CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        }
    }

    // ---- Mode=Off tests ----

    #[test]
    fn test_off_mode_returns_allow() {
        let engine = CurationEngine::new(CurationConfig::default());
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.decided_by.is_none());
        assert!(!result.audited);
    }

    #[test]
    fn test_off_mode_no_metrics() {
        let engine = CurationEngine::new(CurationConfig::default());
        engine.evaluate(&make_request("lodash"));
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 0);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_off_mode_ignores_filters() {
        let mut engine = CurationEngine::new(CurationConfig::default());
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
    }

    // ---- Mode=Enforce tests ----

    #[test]
    fn test_enforce_allow_all() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(AllowAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("allow-all".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_enforce_block_all() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_enforce_block_increments_blocked_metric() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        engine.evaluate(&make_request("lodash"));
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_enforce_allow_increments_allowed_metric() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(AllowAllFilter));
        engine.evaluate(&make_request("lodash"));
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 0);
    }

    // ---- Mode=Audit tests ----

    #[test]
    fn test_audit_block_sets_audited_flag() {
        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(result.audited);
    }

    #[test]
    fn test_audit_block_increments_allowed_metric() {
        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(BlockAllFilter));
        engine.evaluate(&make_request("lodash"));
        // In audit mode, blocks count as allowed (not enforced)
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_audit_allow_not_audited() {
        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(AllowAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.audited);
    }

    // ---- Chain ordering tests ----

    #[test]
    fn test_chain_first_block_wins() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        engine.add_filter(Box::new(AllowAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
    }

    #[test]
    fn test_chain_first_allow_wins() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(AllowAllFilter));
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("allow-all".to_string()));
    }

    #[test]
    fn test_chain_skip_then_block() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(SkipFilter));
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
    }

    #[test]
    fn test_chain_all_skip_allows() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(SkipFilter));
        engine.add_filter(Box::new(SkipFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.decided_by.is_none());
    }

    #[test]
    fn test_chain_empty_allows() {
        let engine = CurationEngine::new(enforce_config());
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.decided_by.is_none());
    }

    #[test]
    fn test_selective_block() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockPackageFilter {
            target: "evil-pkg".to_string(),
        }));

        let ok_result = engine.evaluate(&make_request("lodash"));
        assert_eq!(ok_result.decision, Decision::Allow);

        let blocked_result = engine.evaluate(&make_request("evil-pkg"));
        assert!(matches!(blocked_result.decision, Decision::Block { .. }));
    }

    // ---- Bypass tests ----

    #[test]
    fn test_bypass_allows_despite_block_filter() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_bypass_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("bypass".to_string()));
    }

    #[test]
    fn test_bypass_increments_allowed() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        engine.evaluate(&make_bypass_request("lodash"));
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_bypass_ignored_in_off_mode() {
        let engine = CurationEngine::new(CurationConfig::default());
        let result = engine.evaluate(&make_bypass_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        // Off mode — no metrics at all
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 0);
    }

    // ---- Integrity tracking ----

    #[test]
    fn test_no_integrity_tracked() {
        let engine = CurationEngine::new(enforce_config());
        engine.evaluate(&make_request_no_integrity("lodash"));
        assert_eq!(
            engine.metrics().without_integrity.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_with_integrity_not_tracked() {
        let engine = CurationEngine::new(enforce_config());
        engine.evaluate(&make_request("lodash"));
        assert_eq!(
            engine.metrics().without_integrity.load(Ordering::Relaxed),
            0
        );
    }

    // ---- Helper method tests ----

    #[test]
    fn test_is_active() {
        assert!(!CurationEngine::new(CurationConfig::default()).is_active());
        assert!(CurationEngine::new(audit_config()).is_active());
        assert!(CurationEngine::new(enforce_config()).is_active());
    }

    #[test]
    fn test_mode() {
        let engine = CurationEngine::new(audit_config());
        assert_eq!(*engine.mode(), CurationMode::Audit);
    }

    // ---- RegistryType Display ----

    #[test]
    fn test_registry_type_display() {
        assert_eq!(RegistryType::Npm.to_string(), "npm");
        assert_eq!(RegistryType::PyPI.to_string(), "pypi");
        assert_eq!(RegistryType::Maven.to_string(), "maven");
        assert_eq!(RegistryType::Cargo.to_string(), "cargo");
        assert_eq!(RegistryType::Go.to_string(), "go");
        assert_eq!(RegistryType::Docker.to_string(), "docker");
        assert_eq!(RegistryType::Raw.to_string(), "raw");
    }

    // ---- BlockedResponse ----

    #[test]
    fn test_blocked_response_status_code() {
        let resp = BlockedResponse {
            rule: "test-rule".to_string(),
            reason: "test reason".to_string(),
            registry: "npm".to_string(),
            package: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
        };
        let response = resp.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_blocked_response_headers() {
        let resp = BlockedResponse {
            rule: "blocklist".to_string(),
            reason: "known-vulnerable".to_string(),
            registry: "npm".to_string(),
            package: "evil".to_string(),
            version: None,
        };
        let response = resp.into_response();
        assert_eq!(
            response.headers().get("x-nora-decision").unwrap(),
            "blocked"
        );
        assert_eq!(response.headers().get("x-nora-rule").unwrap(), "blocklist");
        assert_eq!(
            response.headers().get("x-nora-reason").unwrap(),
            "known-vulnerable"
        );
    }

    // ---- CurationConfig defaults ----

    #[test]
    fn test_curation_config_defaults() {
        let c = CurationConfig::default();
        assert_eq!(c.mode, CurationMode::Off);
        assert_eq!(c.on_failure, CurationOnFailure::Closed);
        assert!(!c.require_integrity);
    }

    // ---- Multiple evaluations accumulate metrics ----

    #[test]
    fn test_metrics_accumulate() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockPackageFilter {
            target: "evil".to_string(),
        }));

        engine.evaluate(&make_request("lodash"));
        engine.evaluate(&make_request("express"));
        engine.evaluate(&make_request("evil"));
        engine.evaluate(&make_request("evil"));

        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 2);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 2);
    }

    // ================================================================
    // Blocklist tests (issue #185)
    // ================================================================

    // ---- glob_match ----

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("lodash", "lodash"));
        assert!(!glob_match("lodash", "express"));
    }

    #[test]
    fn test_glob_match_prefix() {
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("foo*", "foo"));
        assert!(!glob_match("foo*", "barfoo"));
    }

    #[test]
    fn test_glob_match_suffix() {
        assert!(glob_match("*bar", "foobar"));
        assert!(glob_match("*bar", "bar"));
        assert!(!glob_match("*bar", "barbaz"));
    }

    // ---- BlocklistFilter::from_file ----

    fn write_blocklist(dir: &std::path::Path, content: &str) -> String {
        let path = dir.join("blocklist.json");
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn test_blocklist_load_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(
            dir.path(),
            r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil", "version": "*", "reason": "bad"}]}"#,
        );
        let filter = BlocklistFilter::from_file(&path).unwrap();
        assert_eq!(filter.rule_count(), 1);
    }

    #[test]
    fn test_blocklist_load_empty_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(dir.path(), r#"{"version": 1, "rules": []}"#);
        let filter = BlocklistFilter::from_file(&path).unwrap();
        assert_eq!(filter.rule_count(), 0);
    }

    #[test]
    fn test_blocklist_load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(dir.path(), "not json");
        let err = BlocklistFilter::from_file(&path).unwrap_err();
        assert!(err.contains("failed to parse"));
    }

    #[test]
    fn test_blocklist_load_missing_file() {
        let err = BlocklistFilter::from_file("/nonexistent/blocklist.json").unwrap_err();
        assert!(err.contains("failed to read"));
    }

    #[test]
    fn test_blocklist_load_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(dir.path(), r#"{"version": 99, "rules": []}"#);
        let err = BlocklistFilter::from_file(&path).unwrap_err();
        assert!(err.contains("unsupported blocklist version 99"));
    }

    // ---- BlocklistFilter::evaluate ----

    fn make_blocklist(rules: Vec<BlocklistRule>) -> BlocklistFilter {
        BlocklistFilter { rules }
    }

    fn make_request_with_registry(
        registry: RegistryType,
        name: &str,
        version: Option<&str>,
    ) -> FilterRequest {
        FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    #[test]
    fn test_blocklist_exact_match() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "event-stream".to_string(),
            version: "*".to_string(),
            reason: "supply chain attack".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::Npm, "event-stream", Some("1.0.0"));
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));
    }

    #[test]
    fn test_blocklist_no_match_different_name() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "event-stream".to_string(),
            version: "*".to_string(),
            reason: "supply chain attack".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.0.0"));
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_registry_mismatch() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "evil".to_string(),
            version: "*".to_string(),
            reason: "bad".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::PyPI, "evil", Some("1.0.0"));
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_registry_wildcard() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "*".to_string(),
            name: "evil-package".to_string(),
            version: "*".to_string(),
            reason: "malware".to_string(),
        }]);
        // Should match any registry
        let npm_req = make_request_with_registry(RegistryType::Npm, "evil-package", Some("1.0.0"));
        assert!(matches!(filter.evaluate(&npm_req), Decision::Block { .. }));

        let pypi_req =
            make_request_with_registry(RegistryType::PyPI, "evil-package", Some("1.0.0"));
        assert!(matches!(filter.evaluate(&pypi_req), Decision::Block { .. }));
    }

    #[test]
    fn test_blocklist_name_prefix_glob() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "evil-*".to_string(),
            version: "*".to_string(),
            reason: "evil prefix".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::Npm, "evil-package", Some("1.0.0"));
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let safe_req = make_request_with_registry(RegistryType::Npm, "good-package", Some("1.0.0"));
        assert_eq!(filter.evaluate(&safe_req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_name_suffix_glob() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "*".to_string(),
            name: "*-malware".to_string(),
            version: "*".to_string(),
            reason: "malware suffix".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::Cargo, "pkg-malware", Some("0.1.0"));
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let safe_req =
            make_request_with_registry(RegistryType::Cargo, "malware-detector", Some("0.1.0"));
        assert_eq!(filter.evaluate(&safe_req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_exact_version() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            reason: "prototype pollution".to_string(),
        }]);
        // Matching version
        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.20"));
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        // Different version — not blocked
        let req2 = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_blocklist_version_none_matches_wildcard() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "evil".to_string(),
            version: "*".to_string(),
            reason: "bad".to_string(),
        }]);
        // No version in request, rule is "*" → should match
        let req = make_request_with_registry(RegistryType::Npm, "evil", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));
    }

    #[test]
    fn test_blocklist_version_none_no_match_exact() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "evil".to_string(),
            version: "1.0.0".to_string(),
            reason: "bad".to_string(),
        }]);
        // No version in request, rule requires exact "1.0.0" → no match
        let req = make_request_with_registry(RegistryType::Npm, "evil", None);
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_multiple_rules_first_match() {
        let filter = make_blocklist(vec![
            BlocklistRule {
                registry: "npm".to_string(),
                name: "evil".to_string(),
                version: "*".to_string(),
                reason: "first rule".to_string(),
            },
            BlocklistRule {
                registry: "*".to_string(),
                name: "evil".to_string(),
                version: "*".to_string(),
                reason: "second rule".to_string(),
            },
        ]);
        let req = make_request_with_registry(RegistryType::Npm, "evil", Some("1.0.0"));
        match filter.evaluate(&req) {
            Decision::Block { reason, .. } => assert_eq!(reason, "first rule"),
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_blocklist_empty_rules_skips() {
        let filter = make_blocklist(vec![]);
        let req = make_request_with_registry(RegistryType::Npm, "anything", Some("1.0.0"));
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_blocklist_filter_name() {
        let filter = make_blocklist(vec![]);
        assert_eq!(filter.name(), "blocklist");
    }

    #[test]
    fn test_blocklist_reason_in_decision() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "*".to_string(),
            name: "bad".to_string(),
            version: "*".to_string(),
            reason: "CVE-2024-12345".to_string(),
        }]);
        let req = make_request_with_registry(RegistryType::Maven, "bad", Some("1.0"));
        match filter.evaluate(&req) {
            Decision::Block { rule, reason } => {
                assert_eq!(rule, "blocklist");
                assert_eq!(reason, "CVE-2024-12345");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // ---- Integration: BlocklistFilter in CurationEngine ----

    #[test]
    fn test_engine_with_blocklist_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(
            dir.path(),
            r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil", "version": "*", "reason": "blocked"}]}"#,
        );
        let filter = BlocklistFilter::from_file(&path).unwrap();

        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(filter));

        let result = engine.evaluate(&make_request("evil"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("blocklist".to_string()));
    }

    #[test]
    fn test_engine_with_blocklist_skips_non_matching() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blocklist(
            dir.path(),
            r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil", "version": "*", "reason": "blocked"}]}"#,
        );
        let filter = BlocklistFilter::from_file(&path).unwrap();

        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(filter));

        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_engine_blocklist_audit_mode() {
        let filter = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "evil".to_string(),
            version: "*".to_string(),
            reason: "bad".to_string(),
        }]);

        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(filter));

        let result = engine.evaluate(&make_request("evil"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(result.audited);
    }

    // ================================================================
    // glob_match ** tests (issue #185)
    // ================================================================

    #[test]
    fn test_glob_match_double_star_dot_matches_nested() {
        assert!(glob_match("com.company.**", "com.company.utils"));
        assert!(glob_match("com.company.**", "com.company.utils.strings"));
        assert!(glob_match("com.company.**", "com.company"));
    }

    #[test]
    fn test_glob_match_double_star_dot_no_match() {
        assert!(!glob_match("com.company.**", "com.other"));
        assert!(!glob_match("com.company.**", "company.utils"));
    }

    #[test]
    fn test_glob_match_double_star_colon_matches_maven() {
        // Maven groupId:artifactId — colon separator
        assert!(glob_match("com.evil.**", "com.evil:lib"));
        assert!(glob_match("com.evil.**", "com.evil:lib-core"));
        assert!(glob_match("com.evil.sub.**", "com.evil.sub:utils"));
    }

    #[test]
    fn test_glob_match_double_star_colon_no_false_positive() {
        assert!(!glob_match("com.evil.**", "com.evilcorp:lib"));
        assert!(!glob_match("com.evil.**", "org.evil:lib"));
    }

    #[test]
    fn test_glob_match_double_star_slash_matches_nested() {
        assert!(glob_match("internal/**", "internal/pkg"));
        assert!(glob_match("internal/**", "internal/pkg/sub"));
        assert!(glob_match("internal/**", "internal"));
    }

    #[test]
    fn test_glob_match_double_star_slash_no_match() {
        assert!(!glob_match("internal/**", "external/pkg"));
        assert!(!glob_match("internal/**", "internals/pkg"));
    }

    // ================================================================
    // NamespaceFilter tests (issue #185)
    // ================================================================

    fn make_ns_filter(patterns: &[&str]) -> NamespaceFilter {
        NamespaceFilter::new(patterns.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_ns_filter_npm_scope() {
        let filter = make_ns_filter(&["@company/*"]);
        let req = make_request_with_registry(RegistryType::Npm, "@company/utils", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Npm, "@other/utils", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_maven_groupid() {
        let filter = make_ns_filter(&["com.company.**"]);
        let req = make_request_with_registry(RegistryType::Maven, "com.company.auth", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Maven, "org.apache.commons", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_cargo_prefix() {
        let filter = make_ns_filter(&["company-*"]);
        let req = make_request_with_registry(RegistryType::Cargo, "company-cli", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Cargo, "other-cli", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_docker_prefix() {
        let filter = make_ns_filter(&["internal/*"]);
        let req = make_request_with_registry(RegistryType::Docker, "internal/myapp", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Docker, "public/myapp", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_go_module() {
        let filter = make_ns_filter(&["go.company.com/**"]);
        let req = make_request_with_registry(RegistryType::Go, "go.company.com/pkg", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Go, "github.com/other", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_exact_match() {
        let filter = make_ns_filter(&["secret-tool"]);
        let req = make_request_with_registry(RegistryType::Npm, "secret-tool", None);
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));

        let req2 = make_request_with_registry(RegistryType::Npm, "secret-tool-extra", None);
        assert_eq!(filter.evaluate(&req2), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_empty_patterns_always_skip() {
        let filter = make_ns_filter(&[]);
        let req = make_request_with_registry(RegistryType::Npm, "anything", None);
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_ns_filter_multiple_patterns_first_match_wins() {
        let filter = make_ns_filter(&["@company/*", "internal-*"]);
        let req = make_request_with_registry(RegistryType::Npm, "@company/utils", None);
        match filter.evaluate(&req) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("@company/*"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_ns_filter_name() {
        let filter = make_ns_filter(&[]);
        assert_eq!(filter.name(), "namespace");
    }

    #[test]
    fn test_ns_filter_pattern_count() {
        let filter = make_ns_filter(&["a", "b", "c"]);
        assert_eq!(filter.pattern_count(), 3);
    }

    // ================================================================
    // Engine + NamespaceFilter integration (issue #185)
    // ================================================================

    #[test]
    fn test_engine_namespace_blocks_in_off_mode() {
        let mut engine = CurationEngine::new(CurationConfig::default()); // mode=Off
        engine.set_namespace_filter(Box::new(make_ns_filter(&["@internal/*"])));

        let req = make_request_with_registry(RegistryType::Npm, "@internal/secret", None);
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("namespace".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_engine_namespace_blocks_in_off_mode_no_filters() {
        let mut engine = CurationEngine::new(CurationConfig::default());
        // No regular filters, only namespace
        engine.set_namespace_filter(Box::new(make_ns_filter(&["company-*"])));

        let req = make_request_with_registry(RegistryType::Cargo, "company-core", None);
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_engine_namespace_blocks_before_bypass() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.set_namespace_filter(Box::new(make_ns_filter(&["@internal/*"])));
        engine.add_filter(Box::new(AllowAllFilter));

        // Even with bypass=true, namespace blocks
        let mut req = make_request_with_registry(RegistryType::Npm, "@internal/secret", None);
        req.bypass = true;
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("namespace".to_string()));
    }

    #[test]
    fn test_engine_namespace_skip_continues_to_chain() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.set_namespace_filter(Box::new(make_ns_filter(&["@internal/*"])));
        engine.add_filter(Box::new(BlockPackageFilter {
            target: "evil-pkg".to_string(),
        }));

        // Not matching namespace → continues to blocklist
        let req = make_request_with_registry(RegistryType::Npm, "evil-pkg", Some("1.0.0"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-package".to_string()));
    }

    #[test]
    fn test_engine_namespace_block_increments_blocked_metric() {
        let mut engine = CurationEngine::new(CurationConfig::default()); // mode=Off
        engine.set_namespace_filter(Box::new(make_ns_filter(&["@internal/*"])));

        let req = make_request_with_registry(RegistryType::Npm, "@internal/foo", None);
        engine.evaluate(&req);
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_engine_namespace_not_audited_even_in_audit_mode() {
        let mut engine = CurationEngine::new(audit_config());
        engine.set_namespace_filter(Box::new(make_ns_filter(&["@internal/*"])));

        let req = make_request_with_registry(RegistryType::Npm, "@internal/foo", None);
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(!result.audited); // namespace blocks are NEVER audit-only
    }

    // ================================================================
    // AllowlistFilter tests (issue #188)
    // ================================================================

    fn write_allowlist(dir: &std::path::Path, content: &str) -> String {
        let path = dir.join("allowlist.json");
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }

    fn make_allowlist_entries(
        entries: Vec<AllowlistEntry>,
        require_integrity: bool,
    ) -> AllowlistFilter {
        let mut map = std::collections::HashMap::new();
        for entry in entries {
            let key = (
                entry.registry.clone(),
                entry.name.clone(),
                entry.version.clone(),
            );
            map.insert(key, entry);
        }
        AllowlistFilter {
            entries: map,
            require_integrity,
        }
    }

    // ---- from_file tests ----

    #[test]
    fn test_allowlist_load_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_allowlist(
            dir.path(),
            r#"{"version": 1, "entries": [
                {"registry": "npm", "name": "lodash", "version": "4.17.21"},
                {"registry": "pypi", "name": "requests", "version": "2.31.0", "integrity": "sha256:abc"}
            ]}"#,
        );
        let filter = AllowlistFilter::from_file(&path, false).unwrap();
        assert_eq!(filter.entry_count(), 2);
    }

    #[test]
    fn test_allowlist_load_empty_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_allowlist(dir.path(), r#"{"version": 1, "entries": []}"#);
        let filter = AllowlistFilter::from_file(&path, false).unwrap();
        assert_eq!(filter.entry_count(), 0);
    }

    #[test]
    fn test_allowlist_load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_allowlist(dir.path(), "not json at all");
        let err = AllowlistFilter::from_file(&path, false).unwrap_err();
        assert!(err.contains("failed to parse"));
    }

    #[test]
    fn test_allowlist_load_missing_file() {
        let err = AllowlistFilter::from_file("/nonexistent/allowlist.json", false).unwrap_err();
        assert!(err.contains("failed to read"));
    }

    #[test]
    fn test_allowlist_load_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_allowlist(dir.path(), r#"{"version": 99, "entries": []}"#);
        let err = AllowlistFilter::from_file(&path, false).unwrap_err();
        assert!(err.contains("unsupported allowlist version 99"));
    }

    // ---- evaluate: allow/block tests ----

    #[test]
    fn test_allowlist_exact_match_allows() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );
        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        assert_eq!(filter.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn test_allowlist_not_found_blocks() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );
        let req = make_request_with_registry(RegistryType::Npm, "express", Some("4.18.0"));
        match filter.evaluate(&req) {
            Decision::Block { rule, reason } => {
                assert_eq!(rule, "allowlist");
                assert!(reason.contains("not in allowlist"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_allowlist_metadata_request_skips() {
        let filter = make_allowlist_entries(vec![], false);
        // version=None → metadata request → Skip
        let req = make_request_with_registry(RegistryType::Npm, "lodash", None);
        assert_eq!(filter.evaluate(&req), Decision::Skip);
    }

    #[test]
    fn test_allowlist_registry_mismatch_blocks() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );
        // Same name+version but different registry → not found
        let req = make_request_with_registry(RegistryType::PyPI, "lodash", Some("4.17.21"));
        assert!(matches!(filter.evaluate(&req), Decision::Block { .. }));
    }

    #[test]
    fn test_allowlist_same_name_different_registry_scoped() {
        let filter = make_allowlist_entries(
            vec![
                AllowlistEntry {
                    registry: "npm".to_string(),
                    name: "utils".to_string(),
                    version: "1.0.0".to_string(),
                    integrity: None,
                    integrity_source: None,
                },
                AllowlistEntry {
                    registry: "pypi".to_string(),
                    name: "utils".to_string(),
                    version: "2.0.0".to_string(),
                    integrity: None,
                    integrity_source: None,
                },
            ],
            false,
        );
        // npm utils@1.0.0 → Allow
        let req1 = make_request_with_registry(RegistryType::Npm, "utils", Some("1.0.0"));
        assert_eq!(filter.evaluate(&req1), Decision::Allow);

        // pypi utils@2.0.0 → Allow
        let req2 = make_request_with_registry(RegistryType::PyPI, "utils", Some("2.0.0"));
        assert_eq!(filter.evaluate(&req2), Decision::Allow);

        // pypi utils@1.0.0 → Block (wrong version for pypi)
        let req3 = make_request_with_registry(RegistryType::PyPI, "utils", Some("1.0.0"));
        assert!(matches!(filter.evaluate(&req3), Decision::Block { .. }));
    }

    // ---- evaluate: integrity tests ----

    #[test]
    fn test_allowlist_integrity_match_allows() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: Some("sha256-abc123".to_string()),
                integrity_source: Some("upstream".to_string()),
            }],
            false,
        );
        let mut req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        req.integrity = Some("sha256-abc123".to_string());
        assert_eq!(filter.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn test_allowlist_integrity_mismatch_blocks() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: Some("sha256-abc123".to_string()),
                integrity_source: None,
            }],
            false,
        );
        let mut req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        req.integrity = Some("sha256-TAMPERED".to_string());
        match filter.evaluate(&req) {
            Decision::Block { rule, reason } => {
                assert_eq!(rule, "allowlist:integrity");
                assert!(reason.contains("Integrity mismatch"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_allowlist_entry_has_integrity_request_doesnt_allows() {
        // Client limitation: client may not provide integrity → still allow
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: Some("sha256-abc123".to_string()),
                integrity_source: None,
            }],
            false,
        );
        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        // req.integrity is None by default from make_request_with_registry
        assert_eq!(filter.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn test_allowlist_require_integrity_missing_blocks() {
        // require_integrity=true + entry without integrity + post-download (integrity provided) → block
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None, // no integrity hash on entry
                integrity_source: None,
            }],
            true, // require_integrity=true
        );
        // Post-download request: integrity is provided (computed from downloaded data)
        let req = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            integrity: Some("sha256:abc123".to_string()),
            bypass: false,
            publish_date: None,
        };
        match filter.evaluate(&req) {
            Decision::Block { rule, reason } => {
                assert_eq!(rule, "allowlist:integrity");
                assert!(reason.contains("missing integrity hash"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_allowlist_require_integrity_false_missing_allows() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false, // require_integrity=false
        );
        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        assert_eq!(filter.evaluate(&req), Decision::Allow);
    }

    // ---- Engine integration tests ----

    #[test]
    fn test_engine_blocklist_before_allowlist_blocks() {
        // Package on both blocklist and allowlist → blocklist wins (evaluated first)
        let blocklist = make_blocklist(vec![BlocklistRule {
            registry: "npm".to_string(),
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            reason: "CVE-2021-xxxxx".to_string(),
        }]);
        let allowlist = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );

        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(blocklist));
        engine.add_filter(Box::new(allowlist));

        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.20"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("blocklist".to_string()));
    }

    #[test]
    fn test_engine_allowlist_enforce_unknown_blocks() {
        let allowlist = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );

        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(allowlist));

        // Unknown package → blocked
        let req = make_request_with_registry(RegistryType::Npm, "unknown-pkg", Some("1.0.0"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("allowlist".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_engine_allowlist_audit_unknown_audited() {
        let allowlist = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );

        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(allowlist));

        let req = make_request_with_registry(RegistryType::Npm, "unknown-pkg", Some("1.0.0"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert!(result.audited);
    }

    #[test]
    fn test_engine_empty_allowlist_blocks_everything() {
        let allowlist = make_allowlist_entries(vec![], false);

        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(allowlist));

        let req = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        let result = engine.evaluate(&req);
        assert!(matches!(result.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_allowlist_filter_name() {
        let filter = make_allowlist_entries(vec![], false);
        assert_eq!(filter.name(), "allowlist");
    }

    // ================================================================
    // check_download() tests (issue #187)
    // ================================================================

    fn make_headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn test_check_download_off_mode_returns_none() {
        let engine = CurationEngine::new(CurationConfig::default());
        let headers = axum::http::HeaderMap::new();
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_check_download_enforce_block_returns_403() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let headers = axum::http::HeaderMap::new();
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_some());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_check_download_audit_block_returns_none() {
        let mut engine = CurationEngine::new(audit_config());
        engine.add_filter(Box::new(BlockAllFilter));
        let headers = axum::http::HeaderMap::new();
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_check_download_bypass_token_matches() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let headers = make_headers(&[("x-nora-bypass-token", "secret123")]);
        let result = super::check_download(
            &engine,
            Some("secret123"),
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_check_download_bypass_token_mismatch() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let headers = make_headers(&[("x-nora-bypass-token", "wrong")]);
        let result = super::check_download(
            &engine,
            Some("secret123"),
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_check_download_no_bypass_configured() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(BlockAllFilter));
        let headers = make_headers(&[("x-nora-bypass-token", "anything")]);
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_check_download_no_version_metadata() {
        let engine = CurationEngine::new(enforce_config());
        // No filters → all Skip → Allow
        let headers = axum::http::HeaderMap::new();
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Npm,
            "lodash",
            None,
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_check_download_enforce_no_filters_allows() {
        let engine = CurationEngine::new(enforce_config());
        let headers = axum::http::HeaderMap::new();
        let result = super::check_download(
            &engine,
            None,
            &headers,
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
            None,
        );
        assert!(result.is_none());
    }

    // ================================================================
    // Version parser tests (issue #187)
    // ================================================================

    #[test]
    fn test_parse_npm_tarball_version_regular() {
        assert_eq!(
            super::parse_npm_tarball_version("lodash", "lodash-4.17.21.tgz"),
            Some("4.17.21".to_string())
        );
    }

    #[test]
    fn test_parse_npm_tarball_version_scoped() {
        assert_eq!(
            super::parse_npm_tarball_version("@babel/core", "core-7.26.0.tgz"),
            Some("7.26.0".to_string())
        );
    }

    #[test]
    fn test_parse_npm_tarball_version_no_tgz() {
        assert_eq!(
            super::parse_npm_tarball_version("lodash", "lodash-4.17.21"),
            None
        );
    }

    #[test]
    fn test_parse_npm_tarball_version_wrong_name() {
        assert_eq!(
            super::parse_npm_tarball_version("lodash", "express-4.18.0.tgz"),
            None
        );
    }

    #[test]
    fn test_parse_pypi_version_sdist() {
        assert_eq!(
            super::parse_pypi_version("flask", "Flask-2.0.0.tar.gz"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_parse_pypi_version_wheel() {
        assert_eq!(
            super::parse_pypi_version("flask", "flask-2.0.0-py3-none-any.whl"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_parse_pypi_version_hyphen_name() {
        assert_eq!(
            super::parse_pypi_version("my-package", "my_package-1.2.3.tar.gz"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn test_parse_pypi_version_no_ext() {
        assert_eq!(super::parse_pypi_version("flask", "flask-2.0.0"), None);
    }

    #[test]
    fn test_parse_pypi_version_zip() {
        assert_eq!(
            super::parse_pypi_version("requests", "requests-2.31.0.zip"),
            Some("2.31.0".to_string())
        );
    }

    // ── verify_integrity tests (issue #189) ─────────────────────────────

    #[test]
    fn test_verify_integrity_mode_off_returns_none() {
        let engine = super::CurationEngine::new(CurationConfig::default());
        let result = super::verify_integrity(
            &engine,
            super::RegistryType::Cargo,
            "my-crate",
            Some("1.0.0"),
            b"some data",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_integrity_matching_hash() {
        let hash = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(b"crate-data"))
        );
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "cargo",
                "name": "my-crate",
                "version": "1.0.0",
                "integrity": hash,
                "integrity_source": "manual"
            }]
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, serde_json::to_string(&allowlist_json).unwrap()).unwrap();

        let mut config = CurationConfig::default();
        config.mode = super::super::config::CurationMode::Enforce;
        let mut engine = super::CurationEngine::new(config);
        let filter = super::AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        engine.add_filter(Box::new(filter));

        let result = super::verify_integrity(
            &engine,
            super::RegistryType::Cargo,
            "my-crate",
            Some("1.0.0"),
            b"crate-data",
        );
        assert!(result.is_none(), "matching hash should pass");
    }

    #[test]
    fn test_verify_integrity_mismatched_hash() {
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "cargo",
                "name": "my-crate",
                "version": "1.0.0",
                "integrity": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "integrity_source": "manual"
            }]
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, serde_json::to_string(&allowlist_json).unwrap()).unwrap();

        let mut config = CurationConfig::default();
        config.mode = super::super::config::CurationMode::Enforce;
        let mut engine = super::CurationEngine::new(config);
        let filter = super::AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        engine.add_filter(Box::new(filter));

        let result = super::verify_integrity(
            &engine,
            super::RegistryType::Cargo,
            "my-crate",
            Some("1.0.0"),
            b"tampered-data",
        );
        assert!(result.is_some(), "mismatched hash should block");
    }

    #[test]
    fn test_verify_integrity_no_hash_in_entry_passes() {
        // Allowlist entry without integrity — verify_integrity should pass
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "cargo",
                "name": "my-crate",
                "version": "1.0.0"
            }]
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, serde_json::to_string(&allowlist_json).unwrap()).unwrap();

        let mut config = CurationConfig::default();
        config.mode = super::super::config::CurationMode::Enforce;
        let mut engine = super::CurationEngine::new(config);
        let filter = super::AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        engine.add_filter(Box::new(filter));

        let result = super::verify_integrity(
            &engine,
            super::RegistryType::Cargo,
            "my-crate",
            Some("1.0.0"),
            b"any-data",
        );
        assert!(result.is_none(), "no integrity in entry → pass");
    }

    #[test]
    fn test_allowlist_pre_download_no_integrity_passes() {
        // Pre-download check (integrity=None) should NOT block on require_integrity
        let hash = "sha256:abc123";
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "cargo",
                "name": "my-crate",
                "version": "1.0.0",
                "integrity": hash,
                "integrity_source": "manual"
            }]
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, serde_json::to_string(&allowlist_json).unwrap()).unwrap();

        // require_integrity=true, but pre-download has no integrity → should STILL allow
        let filter = super::AllowlistFilter::from_file(path.to_str().unwrap(), true).unwrap();
        let request = super::FilterRequest {
            registry: super::RegistryType::Cargo,
            upstream: None,
            name: "my-crate".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None, // pre-download: no integrity
            bypass: false,
            publish_date: None,
        };
        let decision = filter.evaluate(&request);
        assert!(
            matches!(decision, super::Decision::Allow),
            "pre-download with integrity=None must not block: got {:?}",
            decision
        );
    }

    #[test]
    fn test_allowlist_post_download_require_integrity_blocks_missing() {
        // Post-download check with require_integrity but entry has no hash → block
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "cargo",
                "name": "my-crate",
                "version": "1.0.0"
            }]
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, serde_json::to_string(&allowlist_json).unwrap()).unwrap();

        let filter = super::AllowlistFilter::from_file(path.to_str().unwrap(), true).unwrap();
        let request = super::FilterRequest {
            registry: super::RegistryType::Cargo,
            upstream: None,
            name: "my-crate".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: Some("sha256:abc123".to_string()), // post-download: has integrity
            bypass: false,
            publish_date: None,
        };
        let decision = filter.evaluate(&request);
        assert!(
            matches!(decision, super::Decision::Block { .. }),
            "require_integrity + entry without hash + post-download → block: got {:?}",
            decision
        );
    }
}

// ============================================================================
// MinReleaseAge tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod min_release_age_tests {
    use super::*;

    // ── parse_duration tests ────────────────────────────────────────────

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("30d").unwrap(), 2592000);
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("24h").unwrap(), 86400);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn test_parse_duration_weeks() {
        assert_eq!(parse_duration("1w").unwrap(), 604800);
        assert_eq!(parse_duration("2w").unwrap(), 1209600);
    }

    #[test]
    fn test_parse_duration_combined() {
        assert_eq!(parse_duration("1w2d").unwrap(), 604800 + 172800);
        assert_eq!(parse_duration("1d12h").unwrap(), 86400 + 43200);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("7").is_err()); // no unit
        assert!(parse_duration("7x").is_err()); // unknown unit
        assert!(parse_duration("d").is_err()); // no number
    }

    // ── MinReleaseAgeFilter tests ───────────────────────────────────────

    #[test]
    fn test_min_release_age_young_package_blocked() {
        let filter = MinReleaseAgeFilter::new(604800, "7d"); // 7 days
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let request = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "fresh-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 86400), // 1 day ago
        };
        assert!(matches!(filter.evaluate(&request), Decision::Block { .. }));
    }

    #[test]
    fn test_min_release_age_old_package_passes() {
        let filter = MinReleaseAgeFilter::new(604800, "7d"); // 7 days
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let request = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "stable-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 864000), // 10 days ago
        };
        assert!(matches!(filter.evaluate(&request), Decision::Skip));
    }

    #[test]
    fn test_min_release_age_unknown_date_skips() {
        let filter = MinReleaseAgeFilter::new(604800, "7d");
        let request = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "unknown-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        };
        assert!(matches!(filter.evaluate(&request), Decision::Skip));
    }

    #[test]
    fn test_min_release_age_exactly_at_boundary() {
        let filter = MinReleaseAgeFilter::new(86400, "1d"); // 1 day
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Exactly at boundary — age == min_age, should pass (not less than)
        let request = FilterRequest {
            registry: RegistryType::Cargo,
            upstream: None,
            name: "boundary-pkg".to_string(),
            version: Some("2.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 86400),
        };
        assert!(matches!(filter.evaluate(&request), Decision::Skip));
    }

    #[test]
    fn test_min_release_age_chain_integration() {
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Enforce,
            ..CurationConfig::default()
        });
        engine.add_filter(Box::new(MinReleaseAgeFilter::new(604800, "7d")));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Young package — blocked
        let req_young = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "young-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 3600), // 1 hour ago
        };
        let result = engine.evaluate(&req_young);
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by.as_deref(), Some("min-release-age"));

        // Old package — passes (Skip -> default Allow in enforce)
        let req_old = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "old-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 864000), // 10 days
        };
        let result = engine.evaluate(&req_old);
        assert!(!matches!(result.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_min_release_age_format_duration() {
        assert_eq!(MinReleaseAgeFilter::format_duration(3600), "1h");
        assert_eq!(MinReleaseAgeFilter::format_duration(86400), "1d");
        assert_eq!(MinReleaseAgeFilter::format_duration(604800), "1w");
        assert_eq!(MinReleaseAgeFilter::format_duration(691200), "1w1d");
    }

    #[tokio::test]
    async fn test_extract_mtime_as_publish_date_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        storage.put("raw/test.txt", b"hello").await.unwrap();

        let result = extract_mtime_as_publish_date(&storage, "raw/test.txt").await;
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_extract_mtime_as_publish_date_missing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = extract_mtime_as_publish_date(&storage, "raw/nonexistent.txt").await;
        assert!(result.is_none());
    }
}
