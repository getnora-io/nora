// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Per-registry circuit breaker for upstream proxy requests.
//!
//! When an upstream registry is repeatedly failing, the circuit breaker
//! "opens" to fail fast (503) instead of waiting for timeouts.
//!
//! State machine: Closed → Open → HalfOpen → Closed
//!
//! Experimental — disabled by default (`circuit_breaker.enabled = false`).

use crate::config::CircuitBreakerConfig;
use crate::metrics::{CIRCUIT_BREAKER_REJECTIONS, CIRCUIT_BREAKER_STATE};
use crate::registry::ProxyError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    fn as_gauge(self) -> i64 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::Open => 1,
            BreakerState::HalfOpen => 2,
        }
    }
}

#[derive(Debug)]
struct BreakerInner {
    state: BreakerState,
    failures: u32,
    last_failure: Option<Instant>,
    half_open_in_flight: bool,
}

impl BreakerInner {
    fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            failures: 0,
            last_failure: None,
            half_open_in_flight: false,
        }
    }
}

/// Per-registry circuit breaker registry.
///
/// All methods are no-ops when `config.enabled == false`.
pub(crate) struct CircuitBreakerRegistry {
    config: CircuitBreakerConfig,
    breakers: RwLock<HashMap<String, BreakerInner>>,
}

impl CircuitBreakerRegistry {
    pub(crate) fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            breakers: RwLock::new(HashMap::new()),
        }
    }

    /// Create a disabled (no-op) circuit breaker registry.
    pub(crate) fn noop() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if a request to `registry` should proceed.
    /// Returns `Err(ProxyError::CircuitOpen)` if the breaker is open.
    pub(crate) fn check(&self, registry: &str) -> Result<(), ProxyError> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        match breaker.state {
            BreakerState::Closed => Ok(()),
            BreakerState::Open => {
                let elapsed = breaker
                    .last_failure
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(u64::MAX);
                if elapsed >= self.config.reset_timeout {
                    // Transition to HalfOpen — allow one probe
                    breaker.state = BreakerState::HalfOpen;
                    breaker.half_open_in_flight = true;
                    CIRCUIT_BREAKER_STATE
                        .with_label_values(&[registry])
                        .set(BreakerState::HalfOpen.as_gauge());
                    tracing::info!(
                        registry = registry,
                        "Circuit breaker half-open, allowing probe"
                    );
                    Ok(())
                } else {
                    CIRCUIT_BREAKER_REJECTIONS
                        .with_label_values(&[registry])
                        .inc();
                    Err(ProxyError::CircuitOpen(registry.to_string()))
                }
            }
            BreakerState::HalfOpen => {
                if breaker.half_open_in_flight {
                    // Already probing — reject additional requests
                    CIRCUIT_BREAKER_REJECTIONS
                        .with_label_values(&[registry])
                        .inc();
                    Err(ProxyError::CircuitOpen(registry.to_string()))
                } else {
                    // Probe slot free — allow
                    breaker.half_open_in_flight = true;
                    Ok(())
                }
            }
        }
    }

    /// Record a successful upstream response.
    pub(crate) fn record_success(&self, registry: &str) {
        if !self.config.enabled {
            return;
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        if breaker.state != BreakerState::Closed {
            tracing::info!(
                registry = registry,
                previous_state = ?breaker.state,
                "Circuit breaker recovered — closing"
            );
        }
        breaker.state = BreakerState::Closed;
        breaker.failures = 0;
        breaker.half_open_in_flight = false;
        CIRCUIT_BREAKER_STATE
            .with_label_values(&[registry])
            .set(BreakerState::Closed.as_gauge());
    }

    /// Record a failed upstream response.
    pub(crate) fn record_failure(&self, registry: &str) {
        if !self.config.enabled {
            return;
        }

        let now = Instant::now();
        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        match breaker.state {
            BreakerState::Closed => {
                breaker.failures += 1;
                breaker.last_failure = Some(now);
                if breaker.failures >= self.config.failure_threshold {
                    breaker.state = BreakerState::Open;
                    CIRCUIT_BREAKER_STATE
                        .with_label_values(&[registry])
                        .set(BreakerState::Open.as_gauge());
                    tracing::warn!(
                        registry = registry,
                        failures = breaker.failures,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker OPEN — upstream failing"
                    );
                }
            }
            BreakerState::HalfOpen => {
                // Probe failed — back to Open
                breaker.state = BreakerState::Open;
                breaker.last_failure = Some(now);
                breaker.half_open_in_flight = false;
                CIRCUIT_BREAKER_STATE
                    .with_label_values(&[registry])
                    .set(BreakerState::Open.as_gauge());
                tracing::warn!(
                    registry = registry,
                    "Circuit breaker probe failed — re-opening"
                );
            }
            BreakerState::Open => {
                // Already open — just update timestamp
                breaker.last_failure = Some(now);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn enabled_config(threshold: u32, reset_timeout: u64) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: true,
            failure_threshold: threshold,
            reset_timeout,
        }
    }

    fn disabled_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: false,
            failure_threshold: 5,
            reset_timeout: 30,
        }
    }

    #[test]
    fn test_disabled_is_noop() {
        let cb = CircuitBreakerRegistry::new(disabled_config());
        // Even with many failures, check always succeeds
        for _ in 0..100 {
            cb.record_failure("npm");
        }
        assert!(cb.check("npm").is_ok());
    }

    #[test]
    fn test_closed_allows_requests() {
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        assert!(cb.check("npm").is_ok());
        assert!(cb.check("pypi").is_ok());
    }

    #[test]
    fn test_threshold_boundary() {
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        // 4 failures should not trip
        for _ in 0..4 {
            cb.record_failure("npm");
        }
        assert!(cb.check("npm").is_ok());

        // 5th failure trips
        cb.record_failure("npm");
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        for _ in 0..4 {
            cb.record_failure("npm");
        }
        cb.record_success("npm");
        // After reset, 4 more failures should not trip
        for _ in 0..4 {
            cb.record_failure("npm");
        }
        assert!(cb.check("npm").is_ok());
    }

    #[test]
    fn test_open_to_halfopen_after_timeout() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0)); // 0s timeout = immediate
        cb.record_failure("npm");
        cb.record_failure("npm");
        // Should be open, but timeout=0 means immediate half-open transition
        assert!(cb.check("npm").is_ok()); // transitions to HalfOpen, probe allowed
    }

    #[test]
    fn test_halfopen_probe_success_closes() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm");
        cb.record_failure("npm");
        // Transition to half-open
        assert!(cb.check("npm").is_ok());
        // Probe success
        cb.record_success("npm");
        // Should be closed now
        assert!(cb.check("npm").is_ok());
    }

    #[test]
    fn test_halfopen_probe_failure_reopens() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm");
        cb.record_failure("npm");
        // Transition to half-open
        assert!(cb.check("npm").is_ok());
        // Probe fails
        cb.record_failure("npm");
        // Should be open again — next check transitions to half-open (timeout=0)
        // but the FIRST check after re-open with timeout=0 transitions immediately
        let result = cb.check("npm");
        assert!(result.is_ok()); // timeout=0 → immediate half-open again
    }

    #[test]
    fn test_halfopen_rejects_concurrent() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm");
        cb.record_failure("npm");
        // First check — probe allowed
        assert!(cb.check("npm").is_ok());
        // Second check — probe in flight, reject
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
    }

    #[test]
    fn test_per_registry_isolation() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 30));
        cb.record_failure("npm");
        cb.record_failure("npm");
        // npm is open
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
        // pypi is unaffected
        assert!(cb.check("pypi").is_ok());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let cb = Arc::new(CircuitBreakerRegistry::new(enabled_config(100, 30)));
        let mut handles = vec![];

        for i in 0..10 {
            let cb = cb.clone();
            let registry = format!("reg{}", i % 3);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let _ = cb.check(&registry);
                    cb.record_failure(&registry);
                    cb.record_success(&registry);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // No panics = success
    }
}

/// Integration tests — verify 503 response through the full HTTP router.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};

    /// P0 regression: circuit breaker open MUST return 503 + Retry-After,
    /// not 404 (silent swallow) or 502 (wrong code).
    #[tokio::test]
    async fn test_circuit_open_returns_503_npm() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.npm.proxy = Some("http://127.0.0.1:1".into());
        });

        // Trip the breaker
        ctx.state.circuit_breaker.record_failure("npm");
        ctx.state.circuit_breaker.record_failure("npm");

        // Request a package NOT in local storage → proxy path → cb.check() → 503
        let response = send(&ctx.app, Method::GET, "/npm/nonexistent-pkg", "").await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        let body = body_bytes(response).await;
        assert!(String::from_utf8_lossy(&body).contains("temporarily unavailable"));
    }

    /// Same test for PyPI — different handler code path (if-let vs match).
    #[tokio::test]
    async fn test_circuit_open_returns_503_pypi() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxy = Some("http://127.0.0.1:1".into());
        });

        ctx.state.circuit_breaker.record_failure("pypi");
        ctx.state.circuit_breaker.record_failure("pypi");

        let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
    }

    /// When circuit breaker is disabled (default), proxy errors should NOT
    /// produce 503 — they fall through to 404 or 502 as before.
    #[tokio::test]
    async fn test_circuit_disabled_no_503() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = false;
            cfg.npm.proxy = Some("http://127.0.0.1:1".into());
        });

        // Flood failures — should be ignored
        for _ in 0..100 {
            ctx.state.circuit_breaker.record_failure("npm");
        }

        let response = send(&ctx.app, Method::GET, "/npm/nonexistent-pkg", "").await;

        // Should NOT be 503 — breaker is disabled, falls through to network error / 404
        assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Local storage reads must work even when circuit breaker is open.
    /// Circuit breaker only affects upstream proxy, not local data.
    #[tokio::test]
    async fn test_local_read_unaffected_by_open_breaker() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 3600;
        });

        // Publish a package to local storage
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball")
            .await
            .unwrap();

        // Trip the breaker
        ctx.state.circuit_breaker.record_failure("pypi");

        // Local read should still succeed
        let response = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], b"fake-tarball");
    }
}
