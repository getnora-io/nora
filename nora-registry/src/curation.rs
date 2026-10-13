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
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;

// ============================================================================
// Registry Type (re-export from shared module)
// ============================================================================

pub use crate::registry_type::RegistryType;
pub use nora_registry::pypi_files::{parse_pypi_version, pep503_normalize};

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
    /// The version the request fetches, if it names one.
    pub version: RequestVersion,
    /// Integrity hash provided by the client (e.g., sha256 checksum).
    pub integrity: Option<String>,
    /// Whether the request carries a valid bypass token.
    pub bypass: bool,
    /// Publish date as Unix timestamp (seconds). None = unknown.
    pub publish_date: Option<i64>,
}

/// What a request says about the version it fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestVersion {
    /// The request names no version: a package-level request (metadata, an index),
    /// a file of a format without versions (raw), or an import whose source gives none.
    Unspecified,
    /// The version read from the request (e.g., "4.17.21", "33.0.0-jre").
    Known(String),
    /// An artifact download whose version could not be read from the request: its
    /// file name is in a form the handler does not parse. The allowlist cannot match
    /// it and refuses it; rules that need no version still apply.
    Unrecognised,
}

impl RequestVersion {
    /// The version of an artifact download, `Unrecognised` when none could be read.
    pub fn of_artifact(version: Option<&str>) -> Self {
        version.map_or(Self::Unrecognised, |v| Self::Known(v.to_string()))
    }

    /// The version a request names, `Unspecified` when it names none.
    pub fn named(version: Option<&str>) -> Self {
        version.map_or(Self::Unspecified, |v| Self::Known(v.to_string()))
    }

    /// The version, when one was read from the request.
    pub fn known(&self) -> Option<&str> {
        match self {
            Self::Known(v) => Some(v),
            Self::Unspecified | Self::Unrecognised => None,
        }
    }
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

    /// Whether curation reads a download's name: it is on (audit logs what it would refuse),
    /// or a namespace filter is set (it runs even with curation off). A format that learns an
    /// alias's canonical name from its upstream, for curation to read, asks only when this
    /// holds.
    pub fn reads_names(&self) -> bool {
        self.is_active() || self.namespace_filter.is_some()
    }

    /// Whether a download can be refused by its name: curation enforces, or a namespace filter
    /// is set (its blocks are never audit-only). Where this does not hold, a name curation
    /// cannot learn costs the download nothing.
    pub fn can_refuse_names(&self) -> bool {
        self.config.mode == CurationMode::Enforce || self.namespace_filter.is_some()
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
        let result = self.evaluate_inner(request);
        // Expose the effective curation decision in Prometheus — previously only
        // internal counters existed, so allow/block was invisible in telemetry.
        let decision = match &result.decision {
            Decision::Allow => "allow",
            Decision::Block { .. } if result.audited => "audit",
            Decision::Block { .. } => "block",
            Decision::Skip => "skip",
        };
        crate::metrics::CURATION_DECISIONS_TOTAL
            .with_label_values(&[decision])
            .inc();
        result
    }

    fn evaluate_inner(&self, request: &FilterRequest) -> EvaluationResult {
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
    version: RequestVersion,
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
        version: version.clone(),
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
                    version = version.known().unwrap_or("*"),
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
                        registry,
                        package: name.to_string(),
                        version: version.known().map(|v| v.to_string()),
                    }
                    .into_response(),
                )
            }
        }
        Decision::Allow | Decision::Skip => None,
    }
}

/// Check namespace isolation only — no full curation pipeline.
///
/// Returns `Some(Response)` if the package name matches an internal namespace
/// pattern. This prevents dependency confusion by ensuring internal packages
/// are never fetched from upstream registries.
///
/// Unlike [`check_download`], this does NOT run the blocklist, allowlist, or
/// min-release-age filters — it only evaluates the namespace filter.
pub fn check_namespace_isolation(
    engine: &CurationEngine,
    registry: RegistryType,
    name: &str,
) -> Option<Response> {
    let request = FilterRequest {
        registry,
        upstream: None,
        name: name.to_string(),
        version: RequestVersion::Unspecified,
        integrity: None,
        bypass: false,
        publish_date: None,
    };

    if let Some(ref ns_filter) = engine.namespace_filter {
        let decision = ns_filter.evaluate(&request);
        if let Decision::Block { rule, reason } = &decision {
            engine.metrics.blocked.fetch_add(1, Ordering::Relaxed);
            crate::metrics::record_namespace_isolation_refused(registry.as_str());
            return Some(
                BlockedResponse {
                    rule: rule.clone(),
                    reason: reason.clone(),
                    registry,
                    package: name.to_string(),
                    version: None,
                }
                .into_response(),
            );
        }
    }
    None
}

/// Predicate: does `name` match a configured internal-namespace pattern?
///
/// Side-effect-free companion to [`check_namespace_isolation`] — it does NOT
/// increment the `blocked` metric or build a [`Response`]. Use it to DECIDE
/// whether to skip an upstream fetch (dependency-confusion defense) while still
/// serving a locally-published/cached copy; reserve [`check_namespace_isolation`]
/// for the branch that actually returns the 403 block, so the metric counts only
/// client-facing blocks (matching the download path). Returns `false` when no
/// namespace filter is configured.
pub fn is_internal_namespace(engine: &CurationEngine, registry: RegistryType, name: &str) -> bool {
    let Some(ref ns_filter) = engine.namespace_filter else {
        return false;
    };
    let request = FilterRequest {
        registry,
        upstream: None,
        name: name.to_string(),
        version: RequestVersion::Unspecified,
        integrity: None,
        bypass: false,
        publish_date: None,
    };
    matches!(ns_filter.evaluate(&request), Decision::Block { .. })
}

/// True when an internal-namespace filter is configured at all. Batch endpoints
/// (e.g. npm audit `audits/quick`, whose package names are inside a gzipped
/// lockfile and cannot be per-name filtered without inflating) use this to decide
/// whether they must refuse rather than risk leaking internal names upstream (#597).
pub fn namespace_filter_active(engine: &CurationEngine) -> bool {
    engine.namespace_filter.is_some()
}

/// Extract publish date from file mtime. Used for hosted registries, and — when
/// `server.trust_upstream_dates = false` — for proxy registries too (#513): the
/// NORA-cache mtime is NORA-controlled, so it cannot be spoofed by an upstream
/// registry the way an upstream-supplied `published`/`time`/etc. date can. NB in
/// proxy mode this measures cache-age, not real publish date.
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
        version: RequestVersion::named(version),
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
                        registry,
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

/// Verify artifact integrity using a pre-computed hash string (#580).
///
/// Same logic as [`verify_integrity`] but accepts the hash directly instead
/// of computing it from raw data. Used by streaming download paths where
/// SHA-256 was computed incrementally during the download.
///
/// `hash` must be in `sha256:<64hex>` format (e.g., from Docker content-
/// addressable digest).
pub fn verify_integrity_by_hash(
    engine: &CurationEngine,
    registry: RegistryType,
    name: &str,
    version: Option<&str>,
    hash: &str,
) -> Option<Response> {
    debug_assert!(
        hash.starts_with("sha256:") && hash.len() == 71,
        "verify_integrity_by_hash: expected sha256:<64hex>, got: {hash}"
    );

    if !engine.is_active() {
        return None;
    }

    let request = FilterRequest {
        registry,
        upstream: None,
        name: name.to_string(),
        version: RequestVersion::named(version),
        integrity: Some(hash.to_string()),
        bypass: false,
        publish_date: None,
    };

    let result = engine.evaluate(&request);

    match &result.decision {
        Decision::Block { rule, reason } => {
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
                    "[AUDIT] Integrity check would block download (hash-based)"
                );
                None
            } else {
                Some(
                    BlockedResponse {
                        rule: rule.clone(),
                        reason: reason.clone(),
                        registry,
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
/// For scoped packages `@scope/name`, the tarball is `name-VERSION.tgz` on npmjs and
/// `@scope/name-VERSION.tgz` on GitLab's npm registry; both are accepted.
/// For regular packages `name`, the tarball is `name-VERSION.tgz`.
/// Font Awesome's registry puts the file under a version directory,
/// `VERSION/name-VERSION.tgz`; it is accepted when the directory names the version
/// the file does.
///
/// `None` makes the allowlist treat the request as metadata and let it through, so a
/// form this parser misses is a curation bypass, not a cosmetic miss.
pub fn parse_npm_tarball_version(package_name: &str, filename: &str) -> Option<String> {
    if let Some(version) = parse_npm_tarball_file(package_name, filename) {
        return Some(version);
    }
    let (dir, file) = filename.split_once('/')?;
    parse_npm_tarball_file(package_name, file).filter(|version| version == dir)
}

fn parse_npm_tarball_file(package_name: &str, filename: &str) -> Option<String> {
    let filename = filename.strip_suffix(".tgz")?;
    // For scoped packages like @scope/name, the npmjs tarball uses just the "name" part
    let name_part = if package_name.contains('/') {
        package_name.rsplit('/').next()?
    } else {
        package_name
    };
    let version = filename
        .strip_prefix(package_name)
        .or_else(|| filename.strip_prefix(name_part))?
        .strip_prefix('-')?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// A PEP 440 version as `packaging.version.Version` reads one (the spec's `VERSION_PATTERN`:
/// case-insensitive, an optional leading `v`, surrounding whitespace allowed). Numbers are kept
/// as digit strings without their leading zeros, so no length overflows.
#[derive(Debug)]
struct Pep440 {
    epoch: String,
    release: Vec<String>,
    pre: Option<(&'static str, String)>,
    post: Option<String>,
    dev: Option<String>,
    local: Vec<String>,
}

/// A decimal number without its leading zeros (`007` is `7`, `000` is `0`).
fn pep440_number(digits: &str) -> String {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn pep440_digits(s: &str) -> usize {
    s.bytes().take_while(u8::is_ascii_digit).count()
}

/// One optional `-`, `_` or `.` separator at the start of `s`.
fn pep440_separator(s: &str) -> usize {
    usize::from(s.starts_with(['-', '_', '.']))
}

/// After a label: an optional separator and an optional number (0 when absent). The separator
/// is taken even with no number after it, as the regex's greedy `[-_.]?` takes it.
fn pep440_label_number(after_label: &str) -> (String, &str) {
    let after = &after_label[pep440_separator(after_label)..];
    let n = pep440_digits(after);
    if n > 0 {
        (pep440_number(&after[..n]), &after[n..])
    } else {
        ("0".to_string(), after)
    }
}

/// Parse a version as `packaging.version.Version` does; `None` when it is no PEP 440 version.
fn pep440_parse(version: &str) -> Option<Pep440> {
    let lower = version.trim().to_ascii_lowercase();
    let mut rest = lower.strip_prefix('v').unwrap_or(&lower);

    // Epoch: `N!`.
    let mut epoch = "0".to_string();
    let n = pep440_digits(rest);
    if n > 0 && rest[n..].starts_with('!') {
        epoch = pep440_number(&rest[..n]);
        rest = &rest[n + 1..];
    }
    // Release: `N(.N)*`.
    let mut release = Vec::new();
    loop {
        let n = pep440_digits(rest);
        if n == 0 {
            return None;
        }
        release.push(pep440_number(&rest[..n]));
        rest = &rest[n..];
        match rest.strip_prefix('.').filter(|r| pep440_digits(r) > 0) {
            Some(r) => rest = r,
            None => break,
        }
    }
    // Pre-release: `[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?N?`, longest label first.
    let mut pre = None;
    let s = &rest[pep440_separator(rest)..];
    const PRE: [(&str, &str); 8] = [
        ("alpha", "a"),
        ("beta", "b"),
        ("preview", "rc"),
        ("pre", "rc"),
        ("rc", "rc"),
        ("a", "a"),
        ("b", "b"),
        ("c", "rc"),
    ];
    if let Some((label, normal)) = PRE.iter().find(|(label, _)| s.starts_with(label)) {
        let (n, after) = pep440_label_number(&s[label.len()..]);
        pre = Some((*normal, n));
        rest = after;
    }
    // Post-release: `-N`, or `[-_.]?(post|rev|r)[-_.]?N?`.
    let mut post = None;
    if let Some(r) = rest.strip_prefix('-').filter(|r| pep440_digits(r) > 0) {
        let n = pep440_digits(r);
        post = Some(pep440_number(&r[..n]));
        rest = &r[n..];
    } else {
        let s = &rest[pep440_separator(rest)..];
        if let Some(label) = ["post", "rev", "r"]
            .iter()
            .find(|label| s.starts_with(**label))
        {
            let (n, after) = pep440_label_number(&s[label.len()..]);
            post = Some(n);
            rest = after;
        }
    }
    // Development release: `[-_.]?dev[-_.]?N?`.
    let mut dev = None;
    let s = &rest[pep440_separator(rest)..];
    if let Some(after_label) = s.strip_prefix("dev") {
        let (n, after) = pep440_label_number(after_label);
        dev = Some(n);
        rest = after;
    }
    // Local version: `+[a-z0-9]+([-_.][a-z0-9]+)*`, numeric segments as numbers.
    let mut local = Vec::new();
    if let Some(segments) = rest.strip_prefix('+') {
        for segment in segments.split(['-', '_', '.']) {
            if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return None;
            }
            local.push(if segment.bytes().all(|b| b.is_ascii_digit()) {
                pep440_number(segment)
            } else {
                segment.to_string()
            });
        }
        rest = "";
    }
    rest.is_empty().then_some(Pep440 {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

/// A parsed version written back as `packaging` writes it; `trim` drops the release's trailing
/// zeros as `canonicalize_version` does.
fn pep440_render(version: &Pep440, trim: bool) -> String {
    let mut release: &[String] = &version.release;
    while trim && release.len() > 1 && release[release.len() - 1] == "0" {
        release = &release[..release.len() - 1];
    }
    let mut out = String::new();
    if version.epoch != "0" {
        out.push_str(&version.epoch);
        out.push('!');
    }
    out.push_str(&release.join("."));
    if let Some((label, n)) = &version.pre {
        out.push_str(label);
        out.push_str(n);
    }
    if let Some(n) = &version.post {
        out.push_str(".post");
        out.push_str(n);
    }
    if let Some(n) = &version.dev {
        out.push_str(".dev");
        out.push_str(n);
    }
    if !version.local.is_empty() {
        out.push('+');
        out.push_str(&version.local.join("."));
    }
    out
}

/// `str(packaging.version.Version(v))`: a PEP 440 version in its normal form (`1.0-1` is
/// `1.0.post1`, `2.0.0.RC1` is `2.0.0rc1`); `None` when it is no PEP 440 version.
pub fn pep440_normalized(version: &str) -> Option<String> {
    pep440_parse(version).map(|v| pep440_render(&v, false))
}

/// `packaging.utils.canonicalize_version(v)`: the normal form without the release's trailing
/// zeros — one key for the versions PEP 440 counts as equal (`1.0`, `1.0.0` and `v1` are `1`);
/// `None` when it is no PEP 440 version.
pub fn pep440_key(version: &str) -> Option<String> {
    pep440_parse(version).map(|v| pep440_render(&v, true))
}

/// A curation file's registry name in NORA's own spelling: `*` as written, a registry type in
/// any case or by an alias `RegistryType::from_str_opt` takes (`PyPI`, `maven2`, `rubygems`) as
/// that type's name; `None` for a name NORA does not know.
fn curation_registry_name(name: &str) -> Option<String> {
    if name == "*" {
        return Some(name.to_string());
    }
    RegistryType::from_str_opt(name).map(|registry| registry.to_string())
}

/// The registry names a curation file may use, for a load error.
fn known_registry_names() -> String {
    RegistryType::all()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The curation pattern syntax, defined once for names, versions and registries: `*` holds for
/// everything; `foo.**` for `foo` and the names under it, which continue with `child` or `:`
/// (Maven's group/artifact separator); `foo/**` for `foo` and `foo/…`; `foo*` for the names
/// beginning with `foo`; `*foo` for those ending with it; anything else for itself. `form` puts
/// the pattern's body in the form the value is in, and never touches the syntax.
fn pattern_holds(pattern: &str, value: &str, form: impl Fn(&str) -> String, child: char) -> bool {
    if pattern == "*" {
        return true;
    }
    let under = |root: &str, separators: &[char]| {
        value == root
            || value
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with(separators))
    };
    if let Some(root) = pattern.strip_suffix(".**") {
        return under(&form(root), &[child, ':']);
    }
    if let Some(root) = pattern.strip_suffix("/**") {
        return under(&form(root), &['/']);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(&form(prefix));
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(&form(suffix));
    }
    form(pattern) == value
}

/// Whether a rule's or a namespace's name pattern holds for a name in the registry's form: the
/// pattern's body is put in that form ([`curation_name`]) in every syntax. PyPI writes every `.`
/// of a name as `-`, so the names under `corp.**` are `corp-…` there.
fn curation_glob_match(registry: RegistryType, pattern: &str, name: &str) -> bool {
    let child = if registry == RegistryType::PyPI {
        '-'
    } else {
        '.'
    };
    pattern_holds(pattern, name, |body| curation_name(registry, body), child)
}

/// One `.`-separated identifier of a NuGet pre-release or metadata part: letters, digits, `-`.
fn nuget_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A NuGet version's normal form, lowercase, as NuGet clients put it in flat-container URLs
/// (`NuGetVersion.ToNormalizedString().ToLowerInvariant()`): one to four numbers (`1.0` and
/// `1.0.0.0` are `1.0.0`, a fourth only when not 0, leading zeros dropped), the pre-release as
/// written, build metadata dropped. `None` when NuGet.Versioning would not parse it.
pub fn nuget_version_key(version: &str) -> Option<String> {
    let version = version.trim();
    let (version, metadata) = match version.split_once('+') {
        Some((version, metadata)) => (version, Some(metadata)),
        None => (version, None),
    };
    if metadata.is_some_and(|m| !m.split('.').all(nuget_identifier)) {
        return None;
    }
    let (release, pre) = match version.split_once('-') {
        Some((release, pre)) => (release, Some(pre)),
        None => (version, None),
    };
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut numbers = [0i32; 4];
    for (number, part) in numbers.iter_mut().zip(&parts) {
        // Each number is read as `int.Parse` reads it: white space around it is allowed.
        let part = part.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c));
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    let mut out = format!("{}.{}.{}", numbers[0], numbers[1], numbers[2]);
    if numbers[3] > 0 {
        out.push_str(&format!(".{}", numbers[3]));
    }
    if let Some(pre) = pre {
        for id in pre.split('.') {
            let numeric = id.bytes().all(|b| b.is_ascii_digit());
            if !nuget_identifier(id) || (numeric && id.len() > 1 && id.starts_with('0')) {
                return None;
            }
        }
        out.push('-');
        out.push_str(pre);
    }
    Some(out.to_lowercase())
}

/// A semver number as node-semver takes it: `0` or digits without a leading zero, at most
/// `Number.MAX_SAFE_INTEGER`.
fn semver_number(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.parse::<u64>().is_ok_and(|n| n <= 9_007_199_254_740_991)
}

/// One `.`-separated semver identifier: letters, digits and `-`.
fn semver_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// An npm version as npm publishes it (`semver.clean`, npm's semver 7.7): white space trimmed,
/// leading `=` and `v` dropped, then a strict semver version written back without build
/// metadata — `v1.3.0`, `=1.3.0` and `1.3.0+build.1` are `1.3.0`. `None` when npm would not take it.
pub fn npm_version_key(version: &str) -> Option<String> {
    let version = version.trim().trim_start_matches(['=', 'v']);
    if version.len() > 256 {
        return None;
    }
    let (version, build) = match version.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (version, None),
    };
    if build.is_some_and(|b| !b.split('.').all(semver_identifier)) {
        return None;
    }
    let (release, pre) = match version.split_once('-') {
        Some((release, pre)) => (release, Some(pre)),
        None => (version, None),
    };
    let numbers: Vec<&str> = release.split('.').collect();
    if numbers.len() != 3 || !numbers.iter().all(|n| semver_number(n)) {
        return None;
    }
    // A numeric pre-release identifier follows the number rule; any other is letters, digits, `-`.
    if pre.is_some_and(|p| {
        !p.split('.').all(|id| {
            semver_identifier(id) && (id.bytes().any(|b| !b.is_ascii_digit()) || semver_number(id))
        })
    }) {
        return None;
    }
    Some(match pre {
        Some(pre) => format!("{release}-{pre}"),
        None => release.to_string(),
    })
}

/// A Go semver number: `0` or digits without a leading zero.
fn go_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

/// A Go module version as the go command reads it (`module.CanonicalVersion`, golang.org/x/mod):
/// `v` and up to three numbers (`v1` and `v1.2` are `v1.0.0` and `v1.2.0`; a short form takes
/// no pre-release or build), the pre-release as written, build metadata dropped except
/// `+incompatible`. `None` when it is no Go version (`1.2.3` without `v` is not).
pub fn go_version_key(version: &str) -> Option<String> {
    let rest = version.strip_prefix('v')?;
    let (rest, build) = match rest.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (rest, None),
    };
    if build.is_some_and(|b| !b.split('.').all(semver_identifier)) {
        return None;
    }
    let (release, pre) = match rest.split_once('-') {
        Some((release, pre)) => (release, Some(pre)),
        None => (rest, None),
    };
    let numbers: Vec<&str> = release.split('.').collect();
    if numbers.len() > 3 || !numbers.iter().all(|n| go_number(n)) {
        return None;
    }
    if numbers.len() < 3 && (pre.is_some() || build.is_some()) {
        return None;
    }
    if pre.is_some_and(|p| {
        !p.split('.').all(|id| {
            semver_identifier(id) && (id.bytes().any(|b| !b.is_ascii_digit()) || go_number(id))
        })
    }) {
        return None;
    }
    let mut out = format!(
        "v{}.{}.{}",
        numbers[0],
        numbers.get(1).unwrap_or(&"0"),
        numbers.get(2).unwrap_or(&"0")
    );
    if let Some(pre) = pre {
        out.push('-');
        out.push_str(pre);
    }
    if build == Some("incompatible") {
        out.push_str("+incompatible");
    }
    Some(out)
}

/// A pub version as pub_semver reads it (`version.dart`): `major.minor.patch`, then an optional
/// `-pre-release` and `+build`, each `.`-separated identifiers of letters, digits and `-`. Its key
/// writes every number without leading zeros, as pub.dev keeps a version (`01.0.0` is `1.0.0`,
/// `1.0.0-dev.01` is `1.0.0-dev.1`; an all-digit identifier too large for an integer stays text),
/// and keeps the build and the case of text, which pub compares too (`1.0.0+1` is not
/// `1.0.0+2`). `None` for a string pub_semver does not parse.
pub fn pub_version_key(version: &str) -> Option<String> {
    let (rest, build) = match version.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (version, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    if numbers.len() != 3 {
        return None;
    }
    let mut key = numbers
        .iter()
        .map(|n| {
            (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .then(|| n.parse::<i64>().ok().map(|n| n.to_string()))
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?
        .join(".");
    let identifiers = |part: &str| -> Option<String> {
        part.split('.')
            .map(|id| {
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return None;
                }
                if id.bytes().all(|b| b.is_ascii_digit()) {
                    if let Ok(n) = id.parse::<i64>() {
                        return Some(n.to_string());
                    }
                }
                Some(id.to_string())
            })
            .collect::<Option<Vec<_>>>()
            .map(|ids| ids.join("."))
    };
    if let Some(pre) = pre {
        key.push('-');
        key.push_str(&identifiers(pre)?);
    }
    if let Some(build) = build {
        key.push('+');
        key.push_str(&identifiers(build)?);
    }
    Some(key)
}

/// A version as curation compares it. PyPI's as PEP 440 counts versions equal (pip compares
/// parsed versions, so `1.0-1`, `1.0.post1` and `1.0.0.post1` are one version); NuGet's in
/// NuGet's lowercase normal form (`13.0`, `13.0.0.0` and `13.0.0+build` are `13.0.0`); npm's as
/// npm publishes them (`v1.3.0` is `1.3.0`); Go's as the go command reads them (`v1.2` is
/// `v1.2.0`); pub's as pub.dev keeps them (`01.0.0` is `1.0.0`); every other registry's as
/// written. A string the format would not parse compares as written (NuGet's in lowercase:
/// NuGet compares versions without case).
pub fn curation_version(registry: RegistryType, version: &str) -> String {
    match registry {
        RegistryType::PyPI => pep440_key(version).unwrap_or_else(|| version.to_string()),
        RegistryType::Nuget => nuget_version_key(version).unwrap_or_else(|| version.to_lowercase()),
        RegistryType::Npm => npm_version_key(version).unwrap_or_else(|| version.to_string()),
        RegistryType::Go => go_version_key(version).unwrap_or_else(|| version.to_string()),
        RegistryType::PubDart => pub_version_key(version).unwrap_or_else(|| version.to_string()),
        // A Hub commit is hex, served in lower case.
        RegistryType::HuggingFace => version.to_lowercase(),
        _ => version.to_string(),
    }
}

/// Whether a rule's version names a request's version: compared in curation's form
/// ([`curation_version`]); a pattern with `*` matches the spelling or the format's normal form
/// (PyPI: `1.0.*` holds for `1.0-1`, which is `1.0.post1`; NuGet: compared in lowercase).
fn rule_version_matches(registry: RegistryType, rule: &str, version: &str) -> bool {
    if rule.contains('*') {
        let normal = match registry {
            RegistryType::PyPI => pep440_normalized(version),
            RegistryType::Nuget => nuget_version_key(version),
            RegistryType::Npm => npm_version_key(version),
            RegistryType::Go => go_version_key(version),
            RegistryType::PubDart => pub_version_key(version),
            _ => None,
        };
        // NuGet compares versions without case: the pattern and the spelling both fold.
        let fold = |v: &str| match registry {
            RegistryType::Nuget => v.to_lowercase(),
            _ => v.to_string(),
        };
        let pattern = fold(rule);
        return glob_match(&pattern, &fold(version))
            || normal.is_some_and(|normal| glob_match(&pattern, &normal));
    }
    curation_version(registry, rule) == curation_version(registry, version)
}

/// A package name in the form its registry looks it up: PyPI per PEP 503, NuGet and Terraform
/// in lowercase (NuGet ids resolve without case; Terraform lowercases provider names and
/// registry.terraform.io answers provider and module paths in any case), Hugging Face repo ids
/// in lowercase (the Hub answers `Org/Model` with a redirect to `org/model`), cargo as crates.io's
/// `canon_crate_name` (lowercase, `-` as `_`: `Evil-Crate` and `evil_crate` are one crate),
/// every other registry as written. Requests,
/// rules, allowlist entries and internal namespaces are compared in this form, so a rule written
/// in any spelling the registry resolves to the package (`Newtonsoft.Json`, `Flask_RESTful`,
/// `serde-json`) holds for the request.
pub fn curation_name(registry: RegistryType, name: &str) -> String {
    match registry {
        RegistryType::PyPI => pep503_normalize(name),
        RegistryType::Nuget | RegistryType::Terraform | RegistryType::HuggingFace => {
            name.to_lowercase()
        }
        RegistryType::Cargo => name.to_lowercase().replace('-', "_"),
        _ => name.to_string(),
    }
}

// ============================================================================
// Blocked Response (403 JSON)
// ============================================================================

/// A 403 response body for blocked requests.
/// Used by registry handlers in #185-#189 when curation blocks a request.
pub struct BlockedResponse {
    pub rule: String,
    pub reason: String,
    /// The registry the refused package belongs to. The enum, not a string, so
    /// every refusal path hands the same value and the body and hint format it
    /// in ONE place — a path cannot emit a mount point (`/npm/`) where the hint
    /// needs the name (`npm`) (#1099).
    pub registry: RegistryType,
    pub package: String,
    pub version: Option<String>,
}

/// What a refused download carries out of its handler, as a response extension, so the
/// audit layer can record the refusal without each of the many refusal sites taking the
/// audit log and the caller.
#[derive(Clone, Debug)]
pub struct CurationRefusal {
    pub rule: String,
    pub reason: String,
    pub registry: String,
    pub package: String,
    pub version: Option<String>,
}

/// The curation page a refusal links to.
const CURATION_DOCS_URL: &str = "https://getnora.dev/configuration/curation/";

/// The command a refusal's hint names: `nora curation explain registry:name@version`,
/// without `@version` when the request named none, and the spec as one shell word, so
/// the hint pasted into a shell runs as it is (#1099).
pub(crate) fn explain_command(registry: &str, package: &str, version: Option<&str>) -> String {
    let spec = match version {
        Some(version) => format!("{registry}:{package}@{version}"),
        None => format!("{registry}:{package}"),
    };
    format!("nora curation explain {}", shell_word(&spec))
}

/// `word` as one shell word: as it is when no character means anything to a shell,
/// else in single quotes, a `'` inside closed, escaped and reopened.
fn shell_word(word: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c);
    if !word.is_empty() && word.chars().all(plain) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod shell_word_quoting {
    use super::shell_word;

    /// A 403 hint is meant to be pasted into a shell and run; a package name with
    /// a shell metacharacter must be single-quoted, or the hint is an injection
    /// vector (#1099). Only
    /// `[A-Za-z0-9@%+=:,./_-]` may stay bare.
    #[test]
    fn shell_word_quotes_every_shell_metacharacter() {
        for dangerous in [
            "a;b", "a$b", "a`b", "a!b", "a b", "a'b", "a|b", "a&b", "a(b", "a)b", "a>b", "a<b",
            "a\nb", "a\\b", "a*b", "a?b", "a[b", "a]b", "a{b", "a}b", "a#b", "a~b", "a\"b",
        ] {
            let q = shell_word(dangerous);
            assert!(
                q.starts_with('\''),
                "shell_word({dangerous:?}) = {q:?} left a metacharacter bare — a shell would interpret it"
            );
        }
    }

    /// The bare path must stay bare — a mutant that quotes everything would pass
    /// the test above but break the readable hint for ordinary specs.
    #[test]
    fn shell_word_leaves_a_safe_spec_bare() {
        for safe in [
            "npm:is-number@7.0.0",
            "npm:@scope/pkg@1.0.0",
            "docker:library/nginx@sha256:abc",
            "raw:dir/a.b_c-1.txt",
            "cargo:serde",
        ] {
            assert_eq!(shell_word(safe), safe, "a safe spec must not be quoted");
        }
    }
}

impl IntoResponse for BlockedResponse {
    fn into_response(self) -> Response {
        let refusal = CurationRefusal {
            rule: self.rule.clone(),
            reason: self.reason.clone(),
            registry: self.registry.as_str().to_string(),
            package: self.package.clone(),
            version: self.version.clone(),
        };
        let version_str = self.version.as_deref().unwrap_or("*");
        let body = serde_json::json!({
            "error": "blocked_by_policy",
            "error_version": "v1",
            "context": {
                "rule": self.rule,
                "reason": self.reason,
                "registry": self.registry.as_str(),
                "package": self.package,
                "version": version_str,
            },
            "hint": format!(
                "Run: {}",
                explain_command(self.registry.as_str(), &self.package, self.version.as_deref())
            ),
            "docs": CURATION_DOCS_URL
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
        response.extensions_mut().insert(refusal);
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
    pattern_holds(pattern, value, str::to_string, '.')
}

/// A filter that blocks packages matching rules loaded from a JSON file.
///
/// Blocklist is checked first in the chain (overlay on allowlist).
/// First matching rule wins → `Decision::Block`.
/// No match → `Decision::Skip` (defer to next filter).
#[derive(Debug)]
pub struct BlocklistFilter {
    /// Every rule, in file order. Both collections below index into this, so
    /// first-match-wins is decided by original position, not by which structure
    /// happened to answer.
    rules: Vec<BlocklistRule>,
    /// Rules with a literal `name`, bucketed for an O(1) probe. A generated
    /// blocklist is almost entirely these.
    by_name: HashMap<String, Vec<usize>>,
    /// Rules whose `name` is a pattern. Scanned in order; at generated scale
    /// this stays in the tens while `by_name` holds the rest.
    globs: Vec<usize>,
}

impl BlocklistFilter {
    /// Build the lookup index. The allowlist next door has always been an O(1)
    /// map; the blocklist walked every rule and ran three `glob_match` calls on
    /// each, which is free at a hand-written scale and is not once the file is
    /// machine-generated.
    pub fn new(rules: Vec<BlocklistRule>) -> Self {
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut globs = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            // `glob_match` treats every pattern form through `*` — `*`, `foo*`,
            // `*foo`, `foo.**`, `foo/**` — so a name without one is literal.
            if rule.name.contains('*') {
                globs.push(index);
            } else {
                // Indexed under the name's form in each registry the rule covers
                // ([`curation_name`]); `evaluate` looks up the request's name in its form.
                let mut forms: Vec<String> = RegistryType::all()
                    .iter()
                    .filter(|registry| glob_match(&rule.registry, &registry.to_string()))
                    .map(|&registry| curation_name(registry, &rule.name))
                    .collect();
                forms.sort();
                forms.dedup();
                for form in forms {
                    by_name.entry(form).or_default().push(index);
                }
            }
        }
        Self {
            rules,
            by_name,
            globs,
        }
    }

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

        // A rule names its registry in NORA's spelling; one NORA does not know would match
        // nothing, so it is refused rather than loaded.
        let mut rules = file.rules;
        for (index, rule) in rules.iter_mut().enumerate() {
            rule.registry = curation_registry_name(&rule.registry).ok_or_else(|| {
                format!(
                    "blocklist '{}' rule {}: unknown registry '{}' (expected * or one of: {})",
                    path,
                    index + 1,
                    rule.registry,
                    known_registry_names()
                )
            })?;
        }
        Ok(Self::new(rules))
    }

    /// Number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Does this rule cover the request, given a name that already matched?
    fn covers(
        &self,
        index: usize,
        registry: RegistryType,
        registry_str: &str,
        version: &str,
    ) -> bool {
        let rule = &self.rules[index];
        glob_match(&rule.registry, registry_str)
            && (rule.version == "*" || rule_version_matches(registry, &rule.version, version))
    }
}

impl ProxyFilter for BlocklistFilter {
    fn name(&self) -> &'static str {
        "blocklist"
    }

    fn evaluate(&self, request: &FilterRequest) -> Decision {
        let registry_str = request.registry.to_string();
        let version_str = request.version.known().unwrap_or("");

        // First match in file order wins, and that choice is visible: it decides
        // which rule's `reason` the client reads in the 403. So the two
        // collections are merged by original index rather than probed one after
        // the other.
        let mut winner: Option<usize> = None;

        let request_name = curation_name(request.registry, &request.name);
        if let Some(bucket) = self.by_name.get(request_name.as_str()) {
            winner = bucket.iter().copied().find(|&index| {
                curation_name(request.registry, &self.rules[index].name) == request_name
                    && self.covers(index, request.registry, &registry_str, version_str)
            });
        }

        for &index in &self.globs {
            // `globs` is ascending: once an earlier exact rule has won, no later
            // pattern can displace it.
            if winner.is_some_and(|w| index > w) {
                break;
            }
            if curation_glob_match(request.registry, &self.rules[index].name, &request_name)
                && self.covers(index, request.registry, &registry_str, version_str)
            {
                winner = Some(index);
                break;
            }
        }

        match winner {
            Some(index) => Decision::Block {
                rule: "blocklist".to_string(),
                reason: self.rules[index].reason.clone(),
            },
            None => Decision::Skip,
        }
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
        for (index, mut entry) in file.entries.into_iter().enumerate() {
            // As for blocklist rules: NORA's spelling, an unknown registry refused.
            entry.registry = curation_registry_name(&entry.registry)
                .filter(|registry| registry != "*")
                .ok_or_else(|| {
                    format!(
                        "allowlist '{}' entry {}: unknown registry '{}' (expected one of: {})",
                        path,
                        index + 1,
                        entry.registry,
                        known_registry_names()
                    )
                })?;
            entries.insert(Self::entry_key(&entry), entry);
        }

        Ok(Self {
            entries,
            require_integrity,
        })
    }

    /// The key an entry is found under: its name and version in the form curation compares
    /// them for the entry's registry ([`curation_name`], [`curation_version`]).
    fn entry_key(entry: &AllowlistEntry) -> (String, String, String) {
        match RegistryType::from_str_opt(&entry.registry) {
            Some(registry) => (
                entry.registry.clone(),
                curation_name(registry, &entry.name),
                curation_version(registry, &entry.version),
            ),
            None => (
                entry.registry.clone(),
                entry.name.clone(),
                entry.version.clone(),
            ),
        }
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
        let version = match &request.version {
            RequestVersion::Known(v) => v,
            // A package-level request names no version: nothing to match here.
            RequestVersion::Unspecified => return Decision::Skip,
            // An artifact whose version is unknown cannot be matched against an entry,
            // and passing it as metadata would serve versions nobody listed.
            RequestVersion::Unrecognised => {
                return Decision::Block {
                    rule: "allowlist".to_string(),
                    reason: format!(
                        "Package '{}' ({}): version not recognised in the request, so it \
                         cannot be matched against the allowlist",
                        request.name, request.registry
                    ),
                }
            }
        };

        let key = (
            request.registry.to_string(),
            curation_name(request.registry, &request.name),
            curation_version(request.registry, version),
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
        let request_name = curation_name(request.registry, &request.name);
        for pattern in &self.patterns {
            if curation_glob_match(request.registry, pattern, &request_name) {
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

            let unit: i64 = match ch {
                'd' => 86400,
                'h' => 3600,
                'w' => 604800,
                _ => return Err(format!("unknown unit '{}' (use d/h/w)", ch)),
            };
            // A sum that does not fit is refused: wrapped, it became a negative or
            // small threshold (#1099).
            total = n
                .checked_mul(unit)
                .and_then(|secs| total.checked_add(secs))
                .ok_or_else(|| format!("duration '{}' is too large", s))?;
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

/// Filter that blocks packages published less than a minimum age ago.
///
/// The minimum is per registry: a registry's own `[curation.<registry>]
/// min_release_age` if it has one, else the global `min_release_age`. A registry
/// with neither is not filtered by age — and a per-registry value needs no global
/// one to apply (#1098). If `publish_date` is `None` (unknown), the filter defers
/// (`Skip`) to the digest quarantine (#741).
pub struct MinReleaseAgeFilter {
    /// The global threshold (seconds, label): the default for registries
    /// without their own.
    default: Option<(i64, String)>,
    /// Per-registry thresholds (seconds, label).
    overrides: std::collections::HashMap<RegistryType, (i64, String)>,
}

impl MinReleaseAgeFilter {
    /// A filter with a global threshold only (unit tests; the server builds it
    /// with [`Self::from_config`]).
    #[cfg(test)]
    pub fn new(min_age_secs: i64, label: &str) -> Self {
        Self {
            default: Some((min_age_secs, label.to_string())),
            overrides: std::collections::HashMap::new(),
        }
    }

    /// The filter `cfg` asks for: the global `min_release_age` as the default and
    /// each `[curation.<registry>] min_release_age` as that registry's own
    /// threshold; `None` when no value is set anywhere. The one builder for
    /// startup, SIGHUP reload, `curation explain` and the test state.
    ///
    /// A value that does not parse is left out and returned by its key and value,
    /// for the caller to refuse (enforce) or log.
    pub fn from_config(cfg: &crate::config::CurationConfig) -> (Option<Self>, Vec<String>) {
        let mut problems = Vec::new();
        let mut parse = |key: String, value: &str| match parse_duration(value) {
            Ok(secs) => Some((secs, value.to_string())),
            Err(e) => {
                problems.push(format!("{key}=\"{value}\": {e}"));
                None
            }
        };
        let default = cfg
            .min_release_age
            .as_deref()
            .and_then(|value| parse("curation.min_release_age".to_string(), value));
        let mut overrides = std::collections::HashMap::new();
        for &rt in RegistryType::all() {
            let Some(value) = cfg
                .registry_override(rt)
                .and_then(|o| o.min_release_age.as_deref())
            else {
                continue;
            };
            if let Some(threshold) = parse(format!("curation.{rt}.min_release_age"), value) {
                overrides.insert(rt, threshold);
            }
        }
        let filter =
            (default.is_some() || !overrides.is_empty()).then_some(Self { default, overrides });
        (filter, problems)
    }

    /// The thresholds for a log line: `"7d (npm: 3d)"`, or `"npm: 3d"` without a
    /// global value.
    pub fn summary(&self) -> String {
        let overrides: Vec<String> = RegistryType::all()
            .iter()
            .filter_map(|rt| {
                self.overrides
                    .get(rt)
                    .map(|(_, label)| format!("{rt}: {label}"))
            })
            .collect();
        match (&self.default, overrides.is_empty()) {
            (Some((_, label)), true) => label.clone(),
            (Some((_, label)), false) => format!("{label} ({})", overrides.join(", ")),
            (None, _) => overrides.join(", "),
        }
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
        // Resolve the threshold for this registry first: a per-registry override
        // takes precedence over the global default.
        let Some((threshold, label)) = self
            .overrides
            .get(&request.registry)
            .or(self.default.as_ref())
        else {
            // Neither a value of its own nor a global one: not filtered by age.
            return Decision::Skip;
        };
        let threshold = *threshold;

        let Some(publish_ts) = request.publish_date else {
            // Defer to digest-quarantine — the unspoofable first-seen holder
            // (curation-quarantine-uniform). An unknown upstream publish date is
            // not min-release-age's to hold: this filter judges the REAL release
            // age and can only do so with a trusted date. The "hold new/unknown"
            // duty belongs to digest-quarantine, which keys on the content digest
            // and NORA's own clock (no upstream date needed). Config validation
            // guarantees an age control (trust_upstream_dates OR an active
            // quarantine) is configured whenever min_release_age is set on a proxy
            // registry (curation-minage-real-age-defer, #741), so this Skip is not
            // a fail-open hole.
            return Decision::Skip;
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

    #[test]
    fn names_are_read_when_curation_is_on_and_refused_when_it_enforces() {
        let with_namespace = |config: &CurationConfig| {
            let mut engine = CurationEngine::new(config.clone());
            engine.set_namespace_filter(Box::new(NamespaceFilter::new(vec!["acme/*".into()])));
            engine
        };
        let mut config = CurationConfig::default();
        let off = CurationEngine::new(config.clone());
        assert!(!off.reads_names() && !off.can_refuse_names());
        let ns = with_namespace(&config);
        assert!(ns.reads_names() && ns.can_refuse_names());
        config.mode = CurationMode::Audit;
        let audit = CurationEngine::new(config.clone());
        assert!(audit.reads_names() && !audit.can_refuse_names());
        let ns = with_namespace(&config);
        assert!(ns.reads_names() && ns.can_refuse_names());
        config.mode = CurationMode::Enforce;
        let enforce = CurationEngine::new(config);
        assert!(enforce.reads_names() && enforce.can_refuse_names());
    }

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
            version: RequestVersion::Known("1.0.0".to_string()),
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
            version: RequestVersion::Unspecified,
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
            version: RequestVersion::Unspecified,
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
            registry: RegistryType::Npm,
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
            registry: RegistryType::Npm,
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

    /// The JSON body of a refusal, as a client reads it.
    async fn refusal_body(refusal: BlockedResponse) -> serde_json::Value {
        let body = axum::body::to_bytes(refusal.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn refusal(registry: RegistryType, package: &str, version: Option<&str>) -> BlockedResponse {
        BlockedResponse {
            rule: "blocklist".to_string(),
            reason: "r".to_string(),
            registry,
            package: package.to_string(),
            version: version.map(str::to_string),
        }
    }

    /// #1099: the hint names the registry, in the form `nora curation explain`
    /// takes, as one shell word — quoted only when a character would not survive
    /// a shell — and without a version when the request named none.
    #[test]
    fn a_refusal_hint_is_an_explain_command_a_shell_runs_as_it_is() {
        for (registry, package, version, command) in [
            (
                "npm",
                "is-number",
                Some("7.0.0"),
                "nora curation explain npm:is-number@7.0.0",
            ),
            (
                "npm",
                "@scope/pkg",
                Some("1.0.0"),
                "nora curation explain npm:@scope/pkg@1.0.0",
            ),
            (
                "docker",
                "library/nginx",
                Some("sha256:0123abcd"),
                "nora curation explain docker:library/nginx@sha256:0123abcd",
            ),
            ("pub", "Pong", None, "nora curation explain pub:Pong"),
            (
                "raw",
                "dir/my file.txt",
                None,
                "nora curation explain 'raw:dir/my file.txt'",
            ),
            ("raw", "it's", None, r"nora curation explain 'raw:it'\''s'"),
            ("raw", "a*", None, "nora curation explain 'raw:a*'"),
        ] {
            assert_eq!(
                explain_command(registry, package, version),
                command,
                "{registry}:{package}"
            );
        }
    }

    /// #1099: the docs link opens the curation page.
    #[tokio::test]
    async fn a_refusal_links_the_curation_page() {
        let body = refusal_body(refusal(RegistryType::Npm, "is-number", Some("7.0.0"))).await;
        assert_eq!(body["docs"], "https://getnora.dev/configuration/curation/");
    }

    /// The JSON body of a refusal that a real refusal path has already turned into
    /// a `Response` (those return a `Response`, not a `BlockedResponse`).
    async fn body_of_response(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// #1099: the hint on the NAMESPACE refusal path names the registry
    /// (`npm`), not its mount point (`/npm/`) — a `/npm/:…` spec does not resolve,
    /// so the hint would not run. Exercises the real `check_namespace_isolation`,
    /// not a hand-built response, since that is where the registry is set.
    #[tokio::test]
    async fn a_namespace_refusal_hint_names_the_registry_not_the_mount_point() {
        let mut engine = CurationEngine::new(CurationConfig::default());
        engine.set_namespace_filter(Box::new(NamespaceFilter::new(vec!["@corp/*".to_string()])));
        let response = check_namespace_isolation(&engine, RegistryType::Npm, "@corp/secret")
            .expect("a package in an internal namespace is refused");
        let body = body_of_response(response).await;
        assert_eq!(body["context"]["registry"], "npm");
        assert_eq!(body["hint"], "Run: nora curation explain npm:@corp/secret");
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
        BlocklistFilter::new(rules)
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
            version: RequestVersion::named(version),
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    fn br(registry: &str, name: &str, version: &str, reason: &str) -> BlocklistRule {
        BlocklistRule {
            registry: registry.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            reason: reason.to_string(),
        }
    }

    /// The naive scan this filter replaced, comparing names in the registry's form: the
    /// indexed implementation must agree with it on every input, including which rule wins.
    fn naive_decision(rules: &[BlocklistRule], request: &FilterRequest) -> Option<String> {
        let registry_str = request.registry.to_string();
        let version_str = request.version.known().unwrap_or("");
        let name = curation_name(request.registry, &request.name);
        rules
            .iter()
            .find(|rule| {
                glob_match(&rule.registry, &registry_str)
                    && curation_glob_match(request.registry, &rule.name, &name)
                    && (rule.version == "*"
                        || rule_version_matches(request.registry, &rule.version, version_str))
            })
            .map(|rule| rule.reason.clone())
    }

    /// The index finds a literal rule under its name's form in every registry the rule covers:
    /// rules and requests in mixed case and separators, in every registry, agree with the scan.
    #[test]
    fn the_index_agrees_with_the_scan_in_every_registry_form() {
        let rules = vec![
            br("*", "Left-Pad", "*", "any-registry-literal"),
            br(
                "nuget",
                "runtime.linux-x64.Microsoft.NETCore.App",
                "*",
                "nuget-dot-dash",
            ),
            br("pypi", "Flask_RESTful", "*", "pypi-underscore"),
            br("cargo", "Serde-JSON", "*", "cargo-dash"),
            br("terraform", "Acme/foo-bar_baz", "*", "terraform-case"),
            br("*", "Corp.**", "*", "any-registry-hierarchy"),
            br("*", "Evil_*", "1.0.0", "any-registry-prefix"),
        ];
        let filter = make_blocklist(rules.clone());
        let names = [
            "left-pad",
            "Left_Pad",
            "LEFT.PAD",
            "runtime.linux-x64.microsoft.netcore.app",
            "flask-restful",
            "Flask.RESTful",
            "serde_json",
            "serde-json",
            "acme/foo-bar_baz",
            "ACME/FOO-BAR_BAZ",
            "corp",
            "corp-tools",
            "corp.tools",
            "corporate",
            "evil-thing",
            "evil_thing",
        ];
        let versions = [None, Some("1.0.0"), Some("2.0.0")];
        let mut checked = 0;
        for &registry in RegistryType::all() {
            for name in names {
                for version in versions {
                    let req = make_request_with_registry(registry, name, version);
                    assert_eq!(
                        reason_of(&filter.evaluate(&req)),
                        naive_decision(&rules, &req),
                        "{registry:?} {name}@{version:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(
            checked,
            RegistryType::all().len() * names.len() * versions.len()
        );
    }

    fn reason_of(decision: &Decision) -> Option<String> {
        match decision {
            Decision::Block { reason, .. } => Some(reason.clone()),
            _ => None,
        }
    }

    /// #953: the index must not change any decision, and must not change *which*
    /// rule decides — the winning rule's `reason` is what a client reads in the
    /// 403, so a reordering would be visible in production and invisible to a
    /// test that only asserts Block vs Skip.
    #[test]
    fn test_blocklist_index_agrees_with_naive_scan() {
        // Deliberately overlapping: literal and pattern rules that match the
        // same names, interleaved so file order and structure order disagree.
        let rules = vec![
            br("npm", "left-pad", "*", "first-literal"),
            br("*", "left-*", "*", "second-glob"),
            br("npm", "lodash", "4.17.20", "third-literal-pinned"),
            br("npm", "lo*", "*", "fourth-glob"),
            br("*", "*", "9.9.9", "fifth-catch-all-version"),
            br("pypi", "left-pad", "*", "sixth-other-registry"),
            br("npm", "@scope/pkg", "*", "seventh-scoped"),
            br("npm", "*-stream", "*", "eighth-suffix-glob"),
        ];
        let filter = make_blocklist(rules.clone());

        let names = [
            "left-pad",
            "lodash",
            "loose",
            "event-stream",
            "@scope/pkg",
            "unrelated",
            "left-hand",
        ];
        let versions = [None, Some("1.0.0"), Some("4.17.20"), Some("9.9.9")];
        let registries = [RegistryType::Npm, RegistryType::PyPI, RegistryType::Cargo];

        let mut checked = 0;
        for registry in registries {
            for name in names {
                for version in versions {
                    let req = make_request_with_registry(registry, name, version);
                    let expected = naive_decision(&rules, &req);
                    let actual = reason_of(&filter.evaluate(&req));
                    assert_eq!(
                        actual, expected,
                        "indexed lookup disagreed with the naive scan for {:?} {}@{:?}",
                        registry, name, version
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 84, "the matrix must actually run");
    }

    /// An earlier pattern rule outranks a later literal one, and swapping the
    /// file order swaps the winner. This is the ordering property in isolation.
    #[test]
    fn test_blocklist_earlier_rule_wins_regardless_of_shape() {
        let glob_first = make_blocklist(vec![
            br("npm", "ev*", "*", "glob-wins"),
            br("npm", "event-stream", "*", "literal-loses"),
        ]);
        let literal_first = make_blocklist(vec![
            br("npm", "event-stream", "*", "literal-wins"),
            br("npm", "ev*", "*", "glob-loses"),
        ]);
        let req = make_request_with_registry(RegistryType::Npm, "event-stream", Some("1.0.0"));

        assert_eq!(
            reason_of(&glob_first.evaluate(&req)),
            Some("glob-wins".to_string())
        );
        assert_eq!(
            reason_of(&literal_first.evaluate(&req)),
            Some("literal-wins".to_string())
        );
    }

    /// A literal name lands in the map, but registry and version still narrow it.
    #[test]
    fn test_blocklist_indexed_rule_still_checks_registry_and_version() {
        let filter = make_blocklist(vec![br("npm", "lodash", "4.17.20", "pinned")]);

        let wrong_registry =
            make_request_with_registry(RegistryType::PyPI, "lodash", Some("4.17.20"));
        assert!(matches!(filter.evaluate(&wrong_registry), Decision::Skip));

        let wrong_version =
            make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.21"));
        assert!(matches!(filter.evaluate(&wrong_version), Decision::Skip));

        let hit = make_request_with_registry(RegistryType::Npm, "lodash", Some("4.17.20"));
        assert_eq!(
            reason_of(&filter.evaluate(&hit)),
            Some("pinned".to_string())
        );
    }

    /// Duplicate literal names share a bucket; the first one still wins.
    #[test]
    fn test_blocklist_duplicate_names_keep_file_order() {
        let filter = make_blocklist(vec![
            br("npm", "dup", "1.0.0", "narrow-first"),
            br("npm", "dup", "*", "broad-second"),
        ]);
        assert_eq!(
            reason_of(&filter.evaluate(&make_request_with_registry(
                RegistryType::Npm,
                "dup",
                Some("1.0.0")
            ))),
            Some("narrow-first".to_string())
        );
        assert_eq!(
            reason_of(&filter.evaluate(&make_request_with_registry(
                RegistryType::Npm,
                "dup",
                Some("2.0.0")
            ))),
            Some("broad-second".to_string())
        );
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
            map.insert(AllowlistFilter::entry_key(&entry), entry);
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

    /// A package-level request names no version and passes; an artifact whose
    /// version could not be read is refused, with a reason that says so.
    #[test]
    fn allowlist_refuses_an_artifact_with_an_unrecognised_version() {
        let filter = make_allowlist_entries(vec![], false);
        let mut req = make_request_with_registry(RegistryType::Npm, "lodash", None);
        assert_eq!(req.version, RequestVersion::Unspecified);
        assert_eq!(filter.evaluate(&req), Decision::Skip);
        req.version = RequestVersion::Unrecognised;
        match filter.evaluate(&req) {
            Decision::Block { rule, reason } => {
                assert_eq!(rule, "allowlist");
                assert!(reason.contains("version not recognised"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    /// Package-level requests name no version, so the allowlist lets them through:
    /// an index or listing is not a download, and a raw file has no version to list.
    /// Marking them `Unrecognised` would refuse every install under an allowlist.
    #[tokio::test]
    async fn package_level_requests_pass_the_allowlist() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let dir = tempfile::tempdir().unwrap();
        let allowlist = write_allowlist(
            dir.path(),
            r#"{"version": 1, "entries": [{"registry": "npm", "name": "x", "version": "1"}]}"#,
        );
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
            let dead = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = dead.clone();
            cfg.nuget.proxy_timeout = 1;
            cfg.gems.enabled = true;
            cfg.gems.proxy = dead.clone();
            cfg.gems.proxy_timeout = 1;
            cfg.pub_dart.enabled = true;
            cfg.pub_dart.proxy = dead;
            cfg.pub_dart.proxy_timeout = 1;
            cfg.raw.enabled = true;
        });
        ctx.state
            .storage
            .put("raw/docs/readme.txt", b"hello")
            .await
            .unwrap();
        for path in [
            "/nuget/v3/registration/pkg/index.json",
            "/gems/info/pkg",
            "/pub/api/packages/pkg",
            "/raw/docs/readme.txt",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    #[test]
    fn request_version_constructors() {
        assert_eq!(
            RequestVersion::of_artifact(None),
            RequestVersion::Unrecognised
        );
        assert_eq!(RequestVersion::named(None), RequestVersion::Unspecified);
        assert_eq!(
            RequestVersion::of_artifact(Some("1.0")),
            RequestVersion::Known("1.0".to_string())
        );
        assert_eq!(RequestVersion::named(Some("1.0")).known(), Some("1.0"));
        assert_eq!(RequestVersion::Unrecognised.known(), None);
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
            version: RequestVersion::Known("4.17.21".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Known("1.0.0".to_string()),
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
            RequestVersion::Unspecified,
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
            RequestVersion::Known("1.0.0".to_string()),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_check_namespace_isolation_matches_blocks() {
        let mut engine = CurationEngine::new(CurationConfig::default());
        let ns_filter = super::NamespaceFilter::new(vec!["@internal/*".to_string()]);
        engine.set_namespace_filter(Box::new(ns_filter));
        let result = super::check_namespace_isolation(&engine, RegistryType::Npm, "@internal/pkg");
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_check_namespace_isolation_no_match_returns_none() {
        let mut engine = CurationEngine::new(CurationConfig::default());
        let ns_filter = super::NamespaceFilter::new(vec!["@internal/*".to_string()]);
        engine.set_namespace_filter(Box::new(ns_filter));
        let result = super::check_namespace_isolation(&engine, RegistryType::Npm, "public-pkg");
        assert!(result.is_none());
    }

    #[test]
    fn test_check_namespace_isolation_no_filter_returns_none() {
        let engine = CurationEngine::new(CurationConfig::default());
        let result = super::check_namespace_isolation(&engine, RegistryType::Npm, "@internal/pkg");
        assert!(result.is_none());
    }

    #[test]
    fn test_check_namespace_isolation_active_even_in_off_mode() {
        // Namespace isolation is always active, even when curation is Off
        let mut engine = CurationEngine::new(CurationConfig {
            mode: CurationMode::Off,
            ..CurationConfig::default()
        });
        let ns_filter = super::NamespaceFilter::new(vec!["@internal/*".to_string()]);
        engine.set_namespace_filter(Box::new(ns_filter));
        let result = super::check_namespace_isolation(&engine, RegistryType::Npm, "@internal/pkg");
        assert!(result.is_some());
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

    /// GitLab's npm registry names a scoped tarball after the full package name:
    /// `<base>/@vendor/a/-/@vendor/a-1.0.0.tgz` (the npmjs form is `a-1.0.0.tgz`).
    #[test]
    fn test_parse_npm_tarball_version_scoped_full_name_filename() {
        assert_eq!(
            super::parse_npm_tarball_version("@vendor/a", "@vendor/a-1.0.0.tgz"),
            Some("1.0.0".to_string())
        );
        // The other scope's tarball is not this package's version.
        assert_eq!(
            super::parse_npm_tarball_version("@vendor/a", "@other/a-1.0.0.tgz"),
            None
        );
    }

    /// Fail-closed chain: a version the parser cannot read makes the allowlist
    /// skip the request as if it were metadata. For a GitLab-form scoped tarball
    /// that let an unlisted package through; it must be blocked.
    #[test]
    fn allowlist_blocks_an_unlisted_gitlab_form_scoped_tarball() {
        let filter = make_allowlist_entries(
            vec![AllowlistEntry {
                registry: "npm".to_string(),
                name: "@vendor/a".to_string(),
                version: "1.0.0".to_string(),
                integrity: None,
                integrity_source: None,
            }],
            false,
        );
        let request = |filename: &str| FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "@vendor/a".to_string(),
            version: RequestVersion::of_artifact(
                super::parse_npm_tarball_version("@vendor/a", filename).as_deref(),
            ),
            integrity: None,
            bypass: false,
            publish_date: None,
        };
        assert!(
            matches!(
                filter.evaluate(&request("@vendor/a-6.6.6.tgz")),
                Decision::Block { .. }
            ),
            "unlisted version must be blocked"
        );
        assert!(
            !matches!(
                filter.evaluate(&request("@vendor/a-1.0.0.tgz")),
                Decision::Block { .. }
            ),
            "control: the listed version passes"
        );
    }

    /// Font Awesome's form: `<name>/-/<version>/<name>-<version>.tgz`, so the handler
    /// passes `<version>/<name>-<version>.tgz`. The directory must name the same
    /// version as the file; otherwise the form is not recognised.
    #[test]
    fn test_parse_npm_tarball_version_under_a_version_directory() {
        let parse = super::parse_npm_tarball_version;
        assert_eq!(
            parse(
                "@fortawesome/fontawesome-pro",
                "6.1.1/fontawesome-pro-6.1.1.tgz"
            ),
            Some("6.1.1".to_string())
        );
        assert_eq!(
            parse("lodash", "4.17.21/lodash-4.17.21.tgz"),
            Some("4.17.21".to_string())
        );
        assert_eq!(
            parse("@fortawesome/pro-test", "9.9.9/pro-test-1.0.0.tgz"),
            None
        );
        assert_eq!(parse("lodash", "/lodash-4.17.21.tgz"), None);
        assert_eq!(parse("lodash", "x/4.17.21/lodash-4.17.21.tgz"), None);
        assert_eq!(parse("lodash", "4.17.21/express-4.17.21.tgz"), None);
    }

    /// The fuzz copy in `lib.rs` parses the same forms as the one curation uses.
    #[test]
    fn the_fuzzed_npm_parser_matches_the_one_curation_uses() {
        for (name, file) in [
            ("lodash", "lodash-4.17.21.tgz"),
            ("@babel/core", "core-7.26.0.tgz"),
            ("@vendor/a", "@vendor/a-1.0.0.tgz"),
            ("@vendor/a", "@other/a-1.0.0.tgz"),
            ("@fortawesome/pro-test", "1.0.0/pro-test-1.0.0.tgz"),
            ("@fortawesome/pro-test", "9.9.9/pro-test-1.0.0.tgz"),
            ("lodash", "x/4.17.21/lodash-4.17.21.tgz"),
            ("lodash", "lodash-.tgz"),
        ] {
            assert_eq!(
                super::parse_npm_tarball_version(name, file),
                nora_registry::version_fuzz::parse_npm_tarball_version(name, file),
                "{name} {file}"
            );
        }
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
            version: RequestVersion::Known("1.0.0".to_string()),
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

    // ── verify_integrity_by_hash tests (#580) ──────────────────────────

    #[test]
    fn test_verify_integrity_by_hash_mode_off_returns_none() {
        let engine = super::CurationEngine::new(CurationConfig::default());
        let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"data")));
        let result = super::verify_integrity_by_hash(
            &engine,
            super::RegistryType::Docker,
            "library/nginx",
            Some("latest"),
            &hash,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_integrity_by_hash_matching() {
        let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"blob-data")));
        let allowlist_json = serde_json::json!({
            "version": 1,
            "entries": [{
                "registry": "docker",
                "name": "library/nginx",
                "version": "latest",
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

        let result = super::verify_integrity_by_hash(
            &engine,
            super::RegistryType::Docker,
            "library/nginx",
            Some("latest"),
            &hash,
        );
        assert!(result.is_none(), "matching hash should pass");
    }

    #[test]
    fn test_verify_integrity_by_hash_consistent_with_verify_integrity() {
        // verify_integrity_by_hash with the same hash that verify_integrity
        // would compute must produce the same result.
        let data = b"consistency-check";
        let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));
        let engine = super::CurationEngine::new(CurationConfig::default());

        let result_data =
            super::verify_integrity(&engine, super::RegistryType::Docker, "test", None, data);
        let result_hash = super::verify_integrity_by_hash(
            &engine,
            super::RegistryType::Docker,
            "test",
            None,
            &hash,
        );
        assert_eq!(result_data.is_none(), result_hash.is_none());
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
            version: RequestVersion::Known("1.0.0".to_string()),
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

    /// #1099: a duration too large for the counter is refused, not wrapped into a
    /// negative or small threshold.
    #[test]
    fn test_parse_duration_overflow_is_an_error() {
        for value in [
            "99999999999999999w",
            "9223372036854775807d",
            "15250284452471w15250284452471w",
            "99999999999999999999h",
        ] {
            assert!(parse_duration(value).is_err(), "{value}");
        }
        assert_eq!(
            parse_duration("15250284452w").unwrap(),
            15250284452 * 604800
        );
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
            version: RequestVersion::Known("1.0.0".to_string()),
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
            version: RequestVersion::Known("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: Some(now - 864000), // 10 days ago
        };
        assert!(matches!(filter.evaluate(&request), Decision::Skip));
    }

    #[test]
    fn test_min_release_age_unknown_date_defers_to_quarantine() {
        // An unknown upstream publish date is not min-release-age's to hold: it
        // judges the REAL release age and needs a trusted date, so it defers
        // (Skip). Holding new/unknown artifacts is digest-quarantine's job
        // (curation-quarantine-uniform). Config validation guarantees an age
        // control is active when min_release_age is set on a proxy
        // (curation-minage-real-age-defer, #741), so this Skip is not fail-open.
        let filter = MinReleaseAgeFilter::new(604800, "7d");
        let request = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "unknown-pkg".to_string(),
            version: RequestVersion::Known("1.0.0".to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        };
        assert!(matches!(filter.evaluate(&request), Decision::Skip));
    }

    #[test]
    fn test_min_release_age_unknown_date_skips_when_disabled() {
        // With the quarantine disabled for this registry (threshold 0) an unknown
        // date has nothing to enforce against, so it defers — operators can opt a
        // registry out of the age quarantine.
        let filter = MinReleaseAgeFilter::new(0, "0");
        let request = FilterRequest {
            registry: RegistryType::Npm,
            upstream: None,
            name: "unknown-pkg".to_string(),
            version: RequestVersion::Known("1.0.0".to_string()),
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
            version: RequestVersion::Known("2.0.0".to_string()),
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
            version: RequestVersion::Known("1.0.0".to_string()),
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
            version: RequestVersion::Known("1.0.0".to_string()),
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

/// Property tests of the PyPI file-name version parser: the version curation decides on is the
/// one the file name carries, whatever spelling of the project name the file uses.
#[cfg(test)]
mod pypi_file_version_properties {
    use super::parse_pypi_version;
    use proptest::prelude::*;

    /// PEP 503 normalization: lowercase, every run of `-`, `_`, `.` is one `-`.
    fn pep503(name: &str) -> String {
        let mut out = String::new();
        let mut run = false;
        for c in name.chars() {
            if matches!(c, '-' | '_' | '.') {
                if !run {
                    out.push('-');
                }
                run = true;
            } else {
                out.extend(c.to_lowercase());
                run = false;
            }
        }
        out
    }

    fn project() -> impl Strategy<Value = String> {
        "[A-Za-z][A-Za-z0-9]{0,8}([-_.][A-Za-z0-9]{1,8}){0,3}"
    }

    fn version() -> impl Strategy<Value = String> {
        "(0|[1-9][0-9]{0,3})(\\.(0|[1-9][0-9]{0,3})){0,3}((a|b|rc)[0-9]{1,2}|\\.post[0-9]{1,2}|\\.dev[0-9]{1,2})?"
    }

    proptest! {
        // An sdist named with the project name as published (hyphens, dots, any case), or
        // escaped with underscores (PEP 625), reads back its version.
        #[test]
        fn an_sdist_reads_back_its_version_in_any_spelling_of_the_name(name in project(), v in version()) {
            let normalized = pep503(&name);
            for ext in [".tar.gz", ".zip"] {
                let as_published = format!("{name}-{v}{ext}");
                prop_assert_eq!(parse_pypi_version(&normalized, &as_published), Some(v.clone()), "{}", as_published);
                let escaped = format!("{}-{v}{ext}", normalized.replace('-', "_"));
                prop_assert_eq!(parse_pypi_version(&normalized, &escaped), Some(v.clone()), "{}", escaped);
            }
        }

        // A wheel (name escaped with underscores, PEP 427) reads back its version.
        #[test]
        fn a_wheel_reads_back_its_version(name in project(), v in version()) {
            let normalized = pep503(&name);
            let wheel = format!("{}-{v}-py3-none-any.whl", normalized.replace('-', "_"));
            prop_assert_eq!(parse_pypi_version(&normalized, &wheel), Some(v), "{}", wheel);
        }

        // A file of another project reads as no version of this one — unless the other name is
        // this one followed by `-` and more: then the file reads as pip reads it (`Z-A-0.tar.gz`
        // under `z` is version `A-0`, which pip skips as no PEP 440 version; the corpus test
        // holds that case). Which files are a project's own, the project's index decides.
        #[test]
        fn another_projects_file_is_no_version_of_this_one(name in project(), other in project(), v in version()) {
            prop_assume!(pep503(&name) != pep503(&other));
            prop_assume!(!pep503(&other).starts_with(&format!("{}-", pep503(&name))));
            let file = format!("{other}-{v}.tar.gz");
            prop_assert_eq!(parse_pypi_version(&pep503(&name), &file), None, "{} as {}", file, name);
        }
    }
}

/// A curation rule names a package as its registry spells it — `Newtonsoft.Json`, `Flask`,
/// `Inflector` — and holds for the name a request carries after the handler's normalization
/// (NuGet and cargo lowercase, PyPI per PEP 503).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod rule_names_in_published_spelling {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn blocklist(rules: &[(&str, &str)]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocklist.json");
        let rules: Vec<String> = rules
            .iter()
            .map(|(registry, name)| {
                format!(r#"{{"registry": "{registry}", "name": "{name}", "version": "*", "reason": "malware"}}"#)
            })
            .collect();
        std::fs::write(
            &path,
            format!(r#"{{"version": 1, "rules": [{}]}}"#, rules.join(",")),
        )
        .unwrap();
        (dir, path.to_string_lossy().into_owned())
    }

    fn request(registry: super::RegistryType, name: &str, version: &str) -> super::FilterRequest {
        super::FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version: super::RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    // The form follows the request's registry: a case-insensitive registry folds the rule's
    // case, a case-sensitive one does not (npm `JSONStream` is not `jsonstream`).
    #[test]
    fn a_rule_folds_only_where_its_registry_folds_names() {
        use super::{BlocklistFilter, BlocklistRule, Decision, ProxyFilter, RegistryType};
        let rule = |registry: &str, name: &str| BlocklistRule {
            registry: registry.to_string(),
            name: name.to_string(),
            version: "*".to_string(),
            reason: "r".to_string(),
        };
        let filter = BlocklistFilter::new(vec![
            rule("npm", "JSONStream"),
            rule("*", "Flask_RESTful"),
            rule("nuget", "Corp.*"),
            rule("cargo", "evil-crate"),
        ]);
        let blocked = |registry, name: &str| {
            matches!(
                filter.evaluate(&request(registry, name, "1.0")),
                Decision::Block { .. }
            )
        };
        assert!(blocked(RegistryType::Npm, "JSONStream"));
        assert!(!blocked(RegistryType::Npm, "jsonstream"));
        assert!(blocked(RegistryType::PyPI, "flask-restful"));
        assert!(!blocked(RegistryType::Npm, "flask-restful"));
        assert!(blocked(RegistryType::Nuget, "corp.tools"));
        assert!(!blocked(RegistryType::Nuget, "other.tools"));
        // Whatever spelling a handler passes, the filter decides on the registry's form.
        assert!(blocked(RegistryType::Cargo, "Evil_Crate"));
        assert!(blocked(RegistryType::Cargo, "EVIL-CRATE"));
        assert!(!blocked(RegistryType::Npm, "evil_crate"));
    }

    // An allowlist entry in the published spelling allows the normalized request.
    #[test]
    fn an_allowlist_entry_in_the_published_spelling_allows_the_normalized_request() {
        use super::{AllowlistFilter, Decision, ProxyFilter, RegistryType};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(
            &path,
            r#"{"version": 1, "entries": [
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "13.0.1"},
                {"registry": "pypi", "name": "Flask_RESTful", "version": "0.3.9"},
                {"registry": "npm", "name": "JSONStream", "version": "1.3.5"}
            ]}"#,
        )
        .unwrap();
        let filter = AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        let decide = |registry, name: &str, version: &str| {
            filter.evaluate(&request(registry, name, version))
        };
        assert_eq!(
            decide(RegistryType::Nuget, "newtonsoft.json", "13.0.1"),
            Decision::Allow
        );
        assert_eq!(
            decide(RegistryType::PyPI, "flask-restful", "0.3.9"),
            Decision::Allow
        );
        assert_eq!(
            decide(RegistryType::Npm, "JSONStream", "1.3.5"),
            Decision::Allow
        );
        assert!(matches!(
            decide(RegistryType::Npm, "jsonstream", "1.3.5"),
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn a_rule_in_the_published_spelling_blocks_the_normalized_request() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PKG".to_vec()))
            .mount(&upstream)
            .await;
        let (_dir, path) = blocklist(&[
            ("nuget", "Newtonsoft.Json"),
            ("pypi", "Flask_RESTful"),
            ("cargo", "Inflector"),
        ]);
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri.clone());
            cfg.pypi.proxy = Some(uri.clone());
            cfg.cargo.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(path);
        });
        for uri in [
            "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            "/simple/flask-restful/Flask-RESTful-0.3.9.tar.gz",
            "/cargo/api/v1/crates/Inflector/0.11.4/download",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        }
    }

    #[tokio::test]
    async fn an_internal_namespace_in_the_published_spelling_isolates_the_normalized_request() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUAT".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri.clone());
            cfg.pypi.proxy = Some(uri);
            cfg.curation.internal_namespaces =
                vec!["Corp.Internal".to_string(), "Corp_Tools".to_string()];
        });
        for uri in [
            "/nuget/v3/flatcontainer/corp.internal/1.0.0/corp.internal.1.0.0.nupkg",
            "/simple/corp-tools/",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert!(!resp.status().is_success(), "{uri}: {}", resp.status());
        }
        assert!(
            upstream.received_requests().await.unwrap().is_empty(),
            "an internal name went upstream"
        );
    }
}

/// PEP 440 normal forms as `packaging` computes them (`testdata/pypi`, measured with the
/// packaging pip ships): `str(Version(v))` and `canonicalize_version(v)`, or no version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pep440_per_packaging {
    use super::{parse_pypi_version, pep440_key, pep440_normalized, pep503_normalize};

    fn rows(file: &str, columns: usize) -> Vec<Vec<String>> {
        let path = format!("{}/testdata/pypi/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| {
                let fields: Vec<String> = row.split('\t').map(String::from).collect();
                assert_eq!(fields.len(), columns, "{row}");
                fields
            })
            .collect()
    }

    #[test]
    fn every_version_normalizes_as_packaging_does() {
        let rows = rows("pep440-versions.tsv", 3);
        assert_eq!(rows.len(), 1309);
        for row in rows {
            let (version, normalized, key) = (&row[0], &row[1], &row[2]);
            let want = |s: &String| (s != "INVALID").then(|| s.clone());
            assert_eq!(pep440_normalized(version), want(normalized), "{version:?}");
            assert_eq!(pep440_key(version), want(key), "{version:?}");
        }
    }

    // Go module versions as golang.org/x/mod reads them (testdata/go/versions).
    #[test]
    fn every_go_version_is_canonical_as_the_go_command_makes_it() {
        use super::go_version_key;
        let path = format!(
            "{}/testdata/go/versions/canonical.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        let corpus = std::fs::read_to_string(path).unwrap();
        let rows: Vec<(&str, &str)> = corpus
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split_once('\t').unwrap())
            .collect();
        assert_eq!(rows.len(), 1621);
        for (version, canonical) in rows {
            let want = (canonical != "INVALID").then(|| canonical.to_string());
            assert_eq!(go_version_key(version), want, "{version:?}");
        }
    }

    // npm's normal forms as npm 10.9's semver.clean computes them (testdata/npm/versions).
    #[test]
    fn every_npm_version_cleans_as_npm_does() {
        use super::npm_version_key;
        let path = format!(
            "{}/testdata/npm/versions/clean.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        let corpus = std::fs::read_to_string(path).unwrap();
        let rows: Vec<(&str, &str)> = corpus
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split_once('\t').unwrap())
            .collect();
        assert_eq!(rows.len(), 4373);
        for (version, clean) in rows {
            let want = (clean != "INVALID").then(|| clean.to_string());
            assert_eq!(npm_version_key(version), want, "{version:?}");
        }
    }

    // NuGet's normal forms as NuGet.Versioning 6.14 computes them (testdata/nuget/versions).
    #[test]
    fn every_nuget_version_normalizes_as_nuget_does() {
        use super::nuget_version_key;
        let path = format!(
            "{}/testdata/nuget/versions/normal-forms.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        let corpus = std::fs::read_to_string(path).unwrap();
        let rows: Vec<Vec<&str>> = corpus
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split('\t').collect())
            .collect();
        assert_eq!(rows.len(), 3626);
        for row in rows {
            let (version, lowercase) = (row[0], row[2]);
            let want = (lowercase != "INVALID").then(|| lowercase.to_string());
            assert_eq!(nuget_version_key(version), want, "{version:?}");
        }
    }

    // A registry without a normal form compares versions as written: Maven's `1.0` and `1.0.0`
    // are two artifacts; and npm's normal form keeps `1.0.0-rc1` apart from `1.0.0rc1`.
    #[test]
    fn other_registries_compare_versions_as_written() {
        use super::{curation_version, AllowlistFilter, BlocklistFilter, BlocklistRule, Decision};
        use super::{FilterRequest, ProxyFilter, RegistryType, RequestVersion};
        assert_eq!(curation_version(RegistryType::Maven, "1.0"), "1.0");
        assert_eq!(
            curation_version(RegistryType::Npm, "1.0.0-rc1"),
            "1.0.0-rc1"
        );
        assert_eq!(curation_version(RegistryType::PyPI, "1.0.0-rc1"), "1rc1");
        let request = |registry, name: &str, version: &str| FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version: RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        };
        let blocklist = BlocklistFilter::new(vec![BlocklistRule {
            registry: "maven".to_string(),
            name: "com.example:lib".to_string(),
            version: "1.0".to_string(),
            reason: "r".to_string(),
        }]);
        assert_eq!(
            blocklist.evaluate(&request(RegistryType::Maven, "com.example:lib", "1.0.0")),
            Decision::Skip
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(
            &path,
            r#"{"version": 1, "entries": [{"registry": "maven", "name": "com.example:lib", "version": "1.0"}]}"#,
        )
        .unwrap();
        let allowlist = AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        assert!(matches!(
            allowlist.evaluate(&request(RegistryType::Maven, "com.example:lib", "1.0.0")),
            Decision::Block { .. }
        ));
    }

    // A version pattern matches the spelling or the normal form: `1.0.*` holds for `1.0-1`,
    // which is `1.0.post1`.
    #[test]
    fn a_version_pattern_matches_the_normal_form() {
        use super::{BlocklistFilter, BlocklistRule, Decision, FilterRequest, ProxyFilter};
        use super::{RegistryType, RequestVersion};
        let blocklist = BlocklistFilter::new(vec![BlocklistRule {
            registry: "pypi".to_string(),
            name: "foo".to_string(),
            version: "1.0.*".to_string(),
            reason: "r".to_string(),
        }]);
        let decide = |version: &str| {
            blocklist.evaluate(&FilterRequest {
                registry: RegistryType::PyPI,
                upstream: None,
                name: "foo".to_string(),
                version: RequestVersion::Known(version.to_string()),
                integrity: None,
                bypass: false,
                publish_date: None,
            })
        };
        assert!(matches!(decide("1.0-1"), Decision::Block { .. }));
        assert!(matches!(decide("1.0.3"), Decision::Block { .. }));
        assert_eq!(decide("1.1"), Decision::Skip);
    }

    // A NuGet version pattern is matched without case: clients ask for `2.0.0-beta1`.
    #[test]
    fn a_nuget_version_pattern_matches_without_case() {
        use super::{BlocklistFilter, BlocklistRule, Decision, FilterRequest, ProxyFilter};
        use super::{RegistryType, RequestVersion};
        let blocklist = BlocklistFilter::new(vec![BlocklistRule {
            registry: "nuget".to_string(),
            name: "evil.lib".to_string(),
            version: "2.0.0-Beta*".to_string(),
            reason: "r".to_string(),
        }]);
        let decide = |version: &str| {
            blocklist.evaluate(&FilterRequest {
                registry: RegistryType::Nuget,
                upstream: None,
                name: "evil.lib".to_string(),
                version: RequestVersion::Known(version.to_string()),
                integrity: None,
                bypass: false,
                publish_date: None,
            })
        };
        assert!(matches!(decide("2.0.0-beta1"), Decision::Block { .. }));
        assert_eq!(decide("2.0.0"), Decision::Skip);
    }

    // Every file name in the corpus, as the client that takes it reads it (pip's own
    // LinkEvaluator; setuptools for an egg; pip in lowercase for an extension in another case):
    // NORA reads the same version, compared as PEP 440 versions, for every file it serves, and
    // none for another project's file, an empty version, or a file it does not serve.
    #[test]
    fn every_file_reads_the_version_its_client_reads() {
        let key = |v: &str| pep440_key(v).unwrap_or_else(|| v.to_string());
        let rows = rows("file-versions.tsv", 5);
        assert_eq!(rows.len(), 7264);
        let (mut read, mut unread, mut unserved) = (0, 0, 0);
        for row in rows {
            let (project, file, how, version) = (&row[0], &row[1], &row[2], &row[3]);
            let nora = parse_pypi_version(&pep503_normalize(project), file);
            if nora_registry::pypi_files::served_extension(file).is_none() {
                assert_eq!(nora, None, "{project} {file}: not served");
                unserved += 1;
            } else if version.is_empty() {
                assert_eq!(nora, None, "{project} {file}: {how}");
                unread += 1;
            } else {
                assert_eq!(
                    nora.as_deref().map(key),
                    Some(key(version)),
                    "{project} {file}: {how}"
                );
                read += 1;
            }
        }
        assert_eq!((read, unread, unserved), (3432, 184, 3648));
    }

    /// The fuzz targets drive the server's reader: `parse_pypi_version` and `pep503_normalize`
    /// are defined once, in `pypi_files.rs`, and the library and curation re-export them.
    #[test]
    fn the_pypi_file_reader_is_defined_once() {
        for (file, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("curation.rs", include_str!("curation.rs")),
            ("registry/pypi.rs", include_str!("registry/pypi.rs")),
        ] {
            for definition in [
                concat!("fn parse_pypi", "_version("),
                concat!("fn pep503", "_normalize("),
            ] {
                assert!(!source.contains(definition), "{file} defines {definition}");
            }
        }
        assert!(include_str!("lib.rs").contains("pub use crate::pypi_files::parse_pypi_version;"));
    }
}

/// A rule or an entry names its registry as NORA's registry types do, in any case or by an
/// alias `RegistryType::from_str_opt` takes (`PyPI`, `maven2`); a name it does not know is
/// refused when the file loads, not left to match nothing.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_file_registry_names {
    use super::{
        AllowlistFilter, BlocklistFilter, Decision, FilterRequest, ProxyFilter, RegistryType,
        RequestVersion,
    };

    fn request(registry: RegistryType, name: &str, version: &str) -> FilterRequest {
        FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version: RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    fn file(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_rule_names_its_registry_in_any_case_or_by_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "PyPI", "name": "evil", "version": "*", "reason": "r"},
                {"registry": "maven2", "name": "com.evil:lib", "version": "*", "reason": "r"}
            ]}"#,
        );
        let filter = BlocklistFilter::from_file(&path).unwrap();
        let blocked = |registry, name: &str| {
            matches!(
                filter.evaluate(&request(registry, name, "1.0")),
                Decision::Block { .. }
            )
        };
        assert!(blocked(RegistryType::PyPI, "evil"));
        assert!(blocked(RegistryType::Maven, "com.evil:lib"));
    }

    #[test]
    fn an_entry_names_its_registry_in_any_case_or_by_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "PyPI", "name": "flask", "version": "3.0.0"}]}"#,
        );
        let filter = AllowlistFilter::from_file(&path, false).unwrap();
        assert_eq!(
            filter.evaluate(&request(RegistryType::PyPI, "flask", "3.0.0")),
            Decision::Allow
        );
    }

    #[test]
    fn a_registry_nora_does_not_know_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = file(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "pypy", "name": "evil", "version": "*", "reason": "r"}]}"#,
        );
        assert!(BlocklistFilter::from_file(&blocklist).is_err());
        let allowlist = file(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "rubygem", "name": "rails", "version": "7.0.0"}]}"#,
        );
        assert!(AllowlistFilter::from_file(&allowlist, false).is_err());
        // An allowlist entry is exact: `*` would name no registry a request carries.
        let any_entry = file(
            &dir,
            "any-entry.json",
            r#"{"version": 1, "entries": [{"registry": "*", "name": "rails", "version": "7.0.0"}]}"#,
        );
        assert!(AllowlistFilter::from_file(&any_entry, false).is_err());
        let any = file(
            &dir,
            "any.json",
            r#"{"version": 1, "rules": [{"registry": "*", "name": "evil", "version": "*", "reason": "r"}]}"#,
        );
        assert!(BlocklistFilter::from_file(&any).is_ok());
    }
}

/// Registry forms beyond the first example: every `-` of a crate name folds; a NuGet version
/// NuGet cannot parse still compares without case; a NuGet version pattern matches the normal
/// form; a version pattern matches the spelling as written.
#[cfg(test)]
mod curation_forms_beyond_the_first_example {
    use super::{
        AllowlistFilter, BlocklistFilter, BlocklistRule, Decision, FilterRequest, NamespaceFilter,
        ProxyFilter, RegistryType, RequestVersion,
    };

    fn request(registry: RegistryType, name: &str, version: &str) -> FilterRequest {
        FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version: RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    fn rule(registry: &str, name: &str, version: &str) -> BlocklistFilter {
        BlocklistFilter::new(vec![BlocklistRule {
            registry: registry.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            reason: "r".to_string(),
        }])
    }

    fn allowlist(body: &str) -> (tempfile::TempDir, AllowlistFilter) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, body).unwrap();
        let filter = AllowlistFilter::from_file(path.to_str().unwrap(), false).unwrap();
        (dir, filter)
    }

    fn blocked(d: Decision) -> bool {
        matches!(d, Decision::Block { .. })
    }

    // canon_crate_name folds every `-`, not the first one.
    #[test]
    fn cargo_name_folds_every_hyphen() {
        let r = rule("cargo", "evil-crate-x", "*");
        assert!(blocked(r.evaluate(&request(
            RegistryType::Cargo,
            "evil_crate_x",
            "1.0.0"
        ))));
        assert!(blocked(r.evaluate(&request(
            RegistryType::Cargo,
            "Evil_Crate-X",
            "1.0.0"
        ))));
        let (_d, a) = allowlist(
            r#"{"version": 1, "entries": [{"registry": "cargo", "name": "my-crate-x", "version": "1.0.0"}]}"#,
        );
        assert_eq!(
            a.evaluate(&request(RegistryType::Cargo, "my_crate_x", "1.0.0")),
            Decision::Allow
        );
        let ns = NamespaceFilter::new(vec!["corp-int-*".to_string()]);
        assert!(blocked(ns.evaluate(&request(
            RegistryType::Cargo,
            "corp_int_x",
            "1.0.0"
        ))));
    }

    // a NuGet version NuGet does not parse compares as written, without case.
    #[test]
    fn nuget_unparsed_version_compares_without_case() {
        let r = rule("nuget", "evil.lib", "1.0.0-Beta_1");
        assert!(blocked(r.evaluate(&request(
            RegistryType::Nuget,
            "evil.lib",
            "1.0.0-beta_1"
        ))));
        let (_d, a) = allowlist(
            r#"{"version": 1, "entries": [{"registry": "nuget", "name": "good.lib", "version": "1.0.0-RC_1"}]}"#,
        );
        assert_eq!(
            a.evaluate(&request(RegistryType::Nuget, "good.lib", "1.0.0-rc_1")),
            Decision::Allow
        );
    }

    // a NuGet version pattern matches the normal form, not only the spelling.
    #[test]
    fn nuget_version_pattern_matches_the_normal_form() {
        let r = rule("nuget", "evil.lib", "13.0.*");
        assert!(blocked(r.evaluate(&request(
            RegistryType::Nuget,
            "evil.lib",
            "13.0"
        ))));
        assert!(blocked(r.evaluate(&request(
            RegistryType::Nuget,
            "evil.lib",
            "13.0.0.0"
        ))));
        let r = rule("nuget", "evil.lib", "2.0.0-beta*");
        assert!(blocked(r.evaluate(&request(
            RegistryType::Nuget,
            "evil.lib",
            "2.0.0-BETA1"
        ))));
    }

    // a version pattern matches the spelling: Maven has no normal form at all, and a
    // PyPI pattern written in the published spelling holds for that spelling.
    #[test]
    fn version_pattern_matches_the_spelling() {
        let r = rule("maven", "com.evil:lib", "1.*");
        assert!(blocked(r.evaluate(&request(
            RegistryType::Maven,
            "com.evil:lib",
            "1.2"
        ))));
        let r = rule("pypi", "evil", "1.0-*");
        assert!(blocked(r.evaluate(&request(
            RegistryType::PyPI,
            "evil",
            "1.0-1"
        ))));
    }
}

/// A version pattern with `*` matches the spelling and the normal form in npm and Go as well.
#[cfg(test)]
mod version_patterns_match_the_normal_form {
    use super::{BlocklistFilter, BlocklistRule, Decision, FilterRequest, ProxyFilter};
    use super::{RegistryType, RequestVersion};

    fn decide(registry: RegistryType, rule_version: &str, version: &str) -> Decision {
        let r = BlocklistFilter::new(vec![BlocklistRule {
            registry: registry.to_string(),
            name: "evil".to_string(),
            version: rule_version.to_string(),
            reason: "r".to_string(),
        }]);
        r.evaluate(&FilterRequest {
            registry,
            upstream: None,
            name: "evil".to_string(),
            version: RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        })
    }

    #[test]
    fn npm_version_pattern_matches_the_normal_form() {
        // The exact rule holds for `v1.3.0` (npm's `1.3.0`) ...
        assert!(matches!(
            decide(RegistryType::Npm, "1.3.0", "v1.3.0"),
            Decision::Block { .. }
        ));
        // ... so the pattern over the same version must too.
        assert!(matches!(
            decide(RegistryType::Npm, "1.3.*", "v1.3.0"),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn go_version_pattern_matches_the_normal_form() {
        assert!(matches!(
            decide(RegistryType::Go, "v1.2.0", "v1.2"),
            Decision::Block { .. }
        ));
        assert!(matches!(
            decide(RegistryType::Go, "v1.2.*", "v1.2"),
            Decision::Block { .. }
        ));
    }
}

/// A PyPI internal namespace written as a hierarchical pattern (`corp.**`) isolates the project
/// itself and every project under it, whose normalized names use `-`.
#[cfg(test)]
mod hierarchical_pypi_namespace {
    use super::{
        Decision, FilterRequest, NamespaceFilter, ProxyFilter, RegistryType, RequestVersion,
    };

    fn decide(pattern: &str, name: &str) -> Decision {
        NamespaceFilter::new(vec![pattern.to_string()]).evaluate(&FilterRequest {
            registry: RegistryType::PyPI,
            upstream: None,
            name: name.to_string(),
            version: RequestVersion::Unspecified,
            integrity: None,
            bypass: false,
            publish_date: None,
        })
    }

    #[test]
    fn a_hierarchical_pypi_namespace_isolates_its_projects() {
        assert!(matches!(
            decide("corp.*", "corp.tools"),
            Decision::Block { .. }
        ));
        assert!(
            matches!(decide("corp.**", "corp"), Decision::Block { .. }),
            "corp.** vs corp"
        );
        assert!(
            matches!(decide("corp.**", "corp.tools"), Decision::Block { .. }),
            "corp.** vs corp.tools"
        );
    }
}

/// A file of another project, or one with an empty version, reads no version of this project.
#[cfg(test)]
mod pypi_files_of_other_projects {
    use super::parse_pypi_version;

    // pip compares a wheel's name field with the project's canonical name.
    #[test]
    fn another_projects_wheel_has_no_version() {
        assert_eq!(
            parse_pypi_version("flask", "django-1.0-py3-none-any.whl"),
            None
        );
    }

    // pip returns no version for an empty one.
    #[test]
    fn an_empty_version_is_no_version() {
        assert_eq!(parse_pypi_version("flask", "flask-.tar.gz"), None);
        assert_eq!(parse_pypi_version("flask", "flask--py3-none-any.whl"), None);
    }

    // A project whose name merely begins with this one's is another project.
    #[test]
    fn a_longer_name_is_another_project() {
        assert_eq!(parse_pypi_version("flask", "flaskx-1.0.tar.gz"), None);
        assert_eq!(parse_pypi_version("flask", "flask2-1.0.zip"), None);
    }
}

/// Pattern bodies in every syntax take the registry's form, hierarchies hold whole segments
/// only, a literal rule is found in any registry's form, and a registry is named exactly.
#[cfg(test)]
mod curation_patterns_whole_segments_and_forms {
    use super::{
        AllowlistFilter, BlocklistFilter, BlocklistRule, Decision, FilterRequest, NamespaceFilter,
        ProxyFilter, RegistryType, RequestVersion,
    };

    fn request(registry: RegistryType, name: &str, version: RequestVersion) -> FilterRequest {
        FilterRequest {
            registry,
            upstream: None,
            name: name.to_string(),
            version,
            integrity: None,
            bypass: false,
            publish_date: None,
        }
    }

    fn internal(registry: RegistryType, pattern: &str, name: &str) -> bool {
        matches!(
            NamespaceFilter::new(vec![pattern.to_string()]).evaluate(&request(
                registry,
                name,
                RequestVersion::Unspecified
            )),
            Decision::Block { .. }
        )
    }

    fn blocked(registry: &str, rule_name: &str, req: RegistryType, name: &str) -> bool {
        let filter = BlocklistFilter::new(vec![BlocklistRule {
            registry: registry.to_string(),
            name: rule_name.to_string(),
            version: "*".to_string(),
            reason: "r".to_string(),
        }]);
        matches!(
            filter.evaluate(&request(
                req,
                name,
                RequestVersion::Known("1.0.0".to_string())
            )),
            Decision::Block { .. }
        )
    }

    // The body of a `foo/**` pattern takes the registry's form like every other pattern.
    #[test]
    fn a_slash_hierarchy_root_is_in_the_registry_form() {
        assert!(internal(
            RegistryType::Nuget,
            "Acme.Internal/**",
            "Acme.Internal"
        ));
        assert!(internal(RegistryType::PyPI, "Corp_Tools/**", "corp-tools"));
        assert!(internal(RegistryType::Terraform, "Acme/**", "acme/infra"));
    }

    // `foo/**` is `foo` and `foo/...`, not every name starting with `foo`.
    #[test]
    fn a_slash_hierarchy_holds_whole_segments_only() {
        assert!(internal(RegistryType::Go, "acme/**", "acme/x"));
        assert!(!internal(RegistryType::Go, "acme/**", "acme-public/x"));
        assert!(!internal(
            RegistryType::Terraform,
            "acme/**",
            "acmecorp/vpc/aws"
        ));
        assert!(!blocked("go", "acme/**", RegistryType::Go, "acmecorp/lib"));
    }

    // `foo.**` is `foo` and `foo.`/`foo:`/(PyPI) `foo-` names, not every name starting with `foo`.
    #[test]
    fn a_dot_hierarchy_holds_whole_segments_only() {
        assert!(internal(RegistryType::PyPI, "corp.**", "corp-tools"));
        assert!(!internal(RegistryType::PyPI, "corp.**", "corporate"));
        assert!(!internal(RegistryType::Nuget, "Acme.**", "AcmeTools"));
        assert!(!internal(
            RegistryType::Maven,
            "com.corp.**",
            "com.corporate:lib"
        ));
        assert!(!blocked("pypi", "corp.**", RegistryType::PyPI, "corporate"));
    }

    // A NuGet (lowercase-form) rule whose name holds both `.` and `-` is found by the index.
    #[test]
    fn a_lowercase_form_rule_with_dot_and_dash_is_indexed() {
        assert!(blocked(
            "nuget",
            "runtime.linux-x64.Microsoft.NETCore.App",
            RegistryType::Nuget,
            "runtime.linux-x64.microsoft.netcore.app"
        ));
        assert!(blocked(
            "terraform",
            "Acme/foo-bar_baz",
            RegistryType::Terraform,
            "acme/foo-bar_baz"
        ));
    }

    // A registry pattern other than `*` names no registry NORA knows and fails the load.
    #[test]
    fn a_registry_pattern_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let block = dir.path().join("blocklist.json");
        std::fs::write(
            &block,
            r#"{"version": 1, "rules": [{"registry": "py*", "name": "evil", "version": "*", "reason": "r"}]}"#,
        )
        .unwrap();
        assert!(BlocklistFilter::from_file(block.to_str().unwrap()).is_err());
        let allow = dir.path().join("allowlist.json");
        std::fs::write(
            &allow,
            r#"{"version": 1, "entries": [{"registry": "n*", "name": "lodash", "version": "4.17.21"}]}"#,
        )
        .unwrap();
        assert!(AllowlistFilter::from_file(allow.to_str().unwrap(), false).is_err());
    }
}

/// A NuGet version NuGet cannot parse compares without case, exactly and through a pattern.
#[cfg(test)]
mod nuget_unparsed_version_without_case {
    use super::{
        BlocklistFilter, BlocklistRule, Decision, FilterRequest, ProxyFilter, RegistryType,
        RequestVersion,
    };

    fn decide(rule_version: &str, version: &str) -> Decision {
        BlocklistFilter::new(vec![BlocklistRule {
            registry: "nuget".to_string(),
            name: "acme".to_string(),
            version: rule_version.to_string(),
            reason: "r".to_string(),
        }])
        .evaluate(&FilterRequest {
            registry: RegistryType::Nuget,
            upstream: None,
            name: "acme".to_string(),
            version: RequestVersion::Known(version.to_string()),
            integrity: None,
            bypass: false,
            publish_date: None,
        })
    }

    // A NuGet version NuGet cannot parse compares without case — exactly (HEAD holds this)
    // and through a `*` pattern (HEAD compares the pattern, lowercased, with the spelling as written).
    #[test]
    fn nuget_unparsed_version_pattern_matches_without_case() {
        assert!(matches!(
            decide("1.0.0-beta_1", "1.0.0-Beta_1"),
            Decision::Block { .. }
        ));
        assert!(matches!(
            decide("1.0.0-beta_*", "1.0.0-Beta_1"),
            Decision::Block { .. }
        ));
    }
}

/// The pattern syntax as a table: every form, each boundary on both sides, for plain values and
/// for names in several registries' forms; and, for any body, a pattern holds exactly where the
/// same pattern with its body already in the registry's form holds.
#[cfg(test)]
mod curation_pattern_spec {
    use super::{curation_glob_match, curation_name, glob_match, RegistryType};
    use proptest::prelude::*;

    #[test]
    fn the_pattern_syntax_holds_where_it_says() {
        let plain = [
            ("*", "anything", true),
            ("*", "", true),
            ("lodash", "lodash", true),
            ("lodash", "lodash2", false),
            ("foo*", "foo", true),
            ("foo*", "foobar", true),
            ("foo*", "barfoo", false),
            ("*bar", "foobar", true),
            ("*bar", "barbaz", false),
            ("com.corp.**", "com.corp", true),
            ("com.corp.**", "com.corp.utils", true),
            ("com.corp.**", "com.corp:lib", true),
            ("com.corp.**", "com.corporate:lib", false),
            ("com.corp.**", "com.corporate", false),
            ("com.corp.**", "org.com.corp", false),
            ("internal/**", "internal", true),
            ("internal/**", "internal/pkg/deep", true),
            ("internal/**", "internalpkg", false),
            ("internal/**", "internal-public/x", false),
        ];
        for (pattern, value, holds) in plain {
            assert_eq!(glob_match(pattern, value), holds, "{pattern} {value}");
        }
        let named = [
            (RegistryType::PyPI, "corp.**", "corp", true),
            (RegistryType::PyPI, "corp.**", "corp-tools", true),
            (RegistryType::PyPI, "Corp.**", "corp-tools", true),
            (RegistryType::PyPI, "corp.**", "corporate", false),
            (RegistryType::PyPI, "Corp_Tools/**", "corp-tools", true),
            (RegistryType::PyPI, "Corp_*", "corp-tools", true),
            (RegistryType::PyPI, "*_Tools", "corp-tools", true),
            (RegistryType::Nuget, "Acme.**", "acme.tools", true),
            (RegistryType::Nuget, "Acme.**", "acmetools", false),
            (
                RegistryType::Nuget,
                "Acme.Internal/**",
                "acme.internal",
                true,
            ),
            (
                RegistryType::Nuget,
                "runtime.linux-x64.Microsoft.NETCore.App",
                "runtime.linux-x64.microsoft.netcore.app",
                true,
            ),
            (RegistryType::Cargo, "Corp-*", "corp_tools", true),
            (RegistryType::Cargo, "corp-tools", "corp_tools", true),
            (RegistryType::Terraform, "Acme/**", "acme/infra", true),
            (
                RegistryType::Terraform,
                "acme/**",
                "acmecorp/vpc/aws",
                false,
            ),
            (RegistryType::Go, "acme/**", "acme/x", true),
            (RegistryType::Go, "acme/**", "acme-public/x", false),
            (RegistryType::Go, "Acme/**", "acme/x", false),
            (RegistryType::Maven, "com.corp.**", "com.corp:lib", true),
            (
                RegistryType::Maven,
                "com.corp.**",
                "com.corporate:lib",
                false,
            ),
            (RegistryType::Npm, "@Scope/*", "@scope/pkg", false),
        ];
        for (registry, pattern, name, holds) in named {
            assert_eq!(
                curation_glob_match(registry, pattern, name),
                holds,
                "{registry:?} {pattern} {name}"
            );
        }
    }

    fn body() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9._-]{0,8}"
    }

    proptest! {
        // A pattern's body counts in the registry's form in every syntax: writing the body in
        // that form changes nothing, for any name.
        #[test]
        fn a_pattern_body_counts_in_the_registry_form(body in body(), tail in "[a-zA-Z0-9._/:-]{0,6}") {
            for &registry in RegistryType::all() {
                let formed = curation_name(registry, &body);
                prop_assert_eq!(curation_name(registry, &formed), formed.clone(), "{:?} {}", registry, body);
                for name in [formed.clone(), format!("{formed}{tail}"), format!("{tail}{formed}"), curation_name(registry, &format!("{body}{tail}"))] {
                    for (pattern, in_form) in [
                        (body.clone(), formed.clone()),
                        (format!("{body}*"), format!("{formed}*")),
                        (format!("*{body}"), format!("*{formed}")),
                        (format!("{body}.**"), format!("{formed}.**")),
                        (format!("{body}/**"), format!("{formed}/**")),
                    ] {
                        prop_assert_eq!(
                            curation_glob_match(registry, &pattern, &name),
                            curation_glob_match(registry, &in_form, &name),
                            "{:?} {} {} {}", registry, pattern, in_form, name
                        );
                    }
                }
            }
        }
    }
}

/// PyPI file versions as pip 26.2.1 reads them (measured: `.tgz` is a candidate, `.egg` is
/// unsupported), and the fuzzed copy in step.
#[cfg(test)]
mod pypi_files_as_pip_reads_them {
    use super::{parse_pypi_version, pep503_normalize};

    // pip reads `flask-1.0.tgz` as 1.0.
    #[test]
    fn a_tgz_sdist_reads_its_version() {
        assert_eq!(
            parse_pypi_version("flask", "flask-1.0.tgz").as_deref(),
            Some("1.0")
        );
    }

    // P02/P03: the fuzzed copy reads every extension NORA serves as curation does.
    #[test]
    fn the_fuzzed_copy_reads_every_served_extension_as_curation() {
        for file in [
            "flask-1.0.tgz",
            "flask-1.0-py3.8.egg",
            "Flask-1.0.tar.gz",
            "flask-1.0.zip",
            "flask-1.0-py3-none-any.whl",
        ] {
            assert_eq!(
                parse_pypi_version("flask", file),
                nora_registry::version_fuzz::parse_pypi_version("flask", file),
                "{file}"
            );
        }
    }

    // pip's canonicalize_name folds case as Python's `str.lower` does: project `Flas\u{212A}`
    // (KELVIN SIGN) is `flask`, and pip reads `flask-1.0.tar.gz` as its 1.0.
    #[test]
    fn a_project_name_folds_case_as_pip() {
        let project = pep503_normalize("Flas\u{212A}");
        assert_eq!(project, "flask");
        assert_eq!(
            parse_pypi_version(&project, "flask-1.0.tar.gz").as_deref(),
            Some("1.0")
        );
    }
}
