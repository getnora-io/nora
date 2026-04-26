// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Curation layer — package access control for proxy registries.
//!
//! This module provides the skeleton for the curation filter chain:
//! - [`ProxyFilter`] trait that individual filters implement
//! - [`CurationEngine`] that evaluates a chain of filters
//! - [`BlockedResponse`] for generating 403 responses
//! - [`CurationMetrics`] for raw counters
//!
//! Issue #184 — config skeleton + trait. No actual filters yet.

use crate::config::{CurationConfig, CurationMode};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Registry Type
// ============================================================================

/// Supported registry formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryType {
    Npm,
    PyPI,
    Maven,
    Cargo,
    Go,
    Docker,
    Raw,
}

impl fmt::Display for RegistryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryType::Npm => write!(f, "npm"),
            RegistryType::PyPI => write!(f, "pypi"),
            RegistryType::Maven => write!(f, "maven"),
            RegistryType::Cargo => write!(f, "cargo"),
            RegistryType::Go => write!(f, "go"),
            RegistryType::Docker => write!(f, "docker"),
            RegistryType::Raw => write!(f, "raw"),
        }
    }
}

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
    metrics: CurationMetrics,
}

impl CurationEngine {
    /// Create a new engine with no filters.
    pub fn new(config: CurationConfig) -> Self {
        Self {
            config,
            filters: Vec::new(),
            metrics: CurationMetrics::new(),
        }
    }

    /// Add a filter to the end of the chain.
    /// Evaluation order = insertion order.
    pub fn add_filter(&mut self, filter: Box<dyn ProxyFilter>) {
        self.filters.push(filter);
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
// Blocked Response (403 JSON)
// ============================================================================

/// A 403 response body for blocked requests.
/// Used by registry handlers in #185-#189 when curation blocks a request.
#[allow(dead_code)]
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
    pub cve_cache_miss: AtomicU64,
}

impl CurationMetrics {
    fn new() -> Self {
        Self {
            blocked: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            without_integrity: AtomicU64::new(0),
            cve_cache_miss: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{CurationConfig, CurationMode, CurationOnFailure};

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
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(AllowAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("allow-all".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_enforce_block_all() {
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
        assert!(!result.audited);
    }

    #[test]
    fn test_enforce_block_increments_blocked_metric() {
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(BlockAllFilter));
        engine.evaluate(&make_request("lodash"));
        assert_eq!(engine.metrics().blocked.load(Ordering::Relaxed), 1);
        assert_eq!(engine.metrics().allowed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_enforce_allow_increments_allowed_metric() {
        let mut engine = CurationEngine::new(enforce_config());
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
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(BlockAllFilter));
        engine.add_filter(Box::new(AllowAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
    }

    #[test]
    fn test_chain_first_allow_wins() {
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(AllowAllFilter));
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("allow-all".to_string()));
    }

    #[test]
    fn test_chain_skip_then_block() {
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(SkipFilter));
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_request("lodash"));
        assert!(matches!(result.decision, Decision::Block { .. }));
        assert_eq!(result.decided_by, Some("block-all".to_string()));
    }

    #[test]
    fn test_chain_all_skip_allows() {
        let mut engine = CurationEngine::new(enforce_config());
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
        let mut engine = CurationEngine::new(enforce_config());
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
        let mut engine = CurationEngine::new(enforce_config());
        engine.add_filter(Box::new(BlockAllFilter));
        let result = engine.evaluate(&make_bypass_request("lodash"));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.decided_by, Some("bypass".to_string()));
    }

    #[test]
    fn test_bypass_increments_allowed() {
        let mut engine = CurationEngine::new(enforce_config());
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
        let mut engine = CurationEngine::new(enforce_config());
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
}
