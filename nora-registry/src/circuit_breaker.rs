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
    /// When the current half-open probe started. Used to release a probe slot
    /// that was never reported back (a `check()` that returned Ok but whose
    /// caller exited without `record_success`/`record_failure`, e.g. a 4xx or
    /// body-extract path), so the breaker cannot wedge at 503 forever (#585).
    half_open_started: Option<Instant>,
}

impl BreakerInner {
    fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            failures: 0,
            last_failure: None,
            half_open_in_flight: false,
            half_open_started: None,
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

    /// Initialize gauge to 0 (Closed) for all known registries so Prometheus
    /// exports the metric immediately, even before any state transition (#441).
    pub(crate) fn init_gauges(&self, registries: &[&str]) {
        if !self.config.enabled {
            return;
        }
        for name in registries {
            CIRCUIT_BREAKER_STATE
                .with_label_values(&[name])
                .set(BreakerState::Closed.as_gauge());
        }
    }

    /// Resolve the failure threshold for a given registry key, checking overrides first.
    fn threshold_for(&self, registry: &str) -> u32 {
        self.config
            .overrides
            .get(registry)
            .and_then(|o| o.failure_threshold)
            .unwrap_or(self.config.failure_threshold)
    }

    /// Resolve the reset timeout for a given registry key, checking overrides first.
    fn reset_timeout_for(&self, registry: &str) -> u64 {
        self.config
            .overrides
            .get(registry)
            .and_then(|o| o.reset_timeout)
            .unwrap_or(self.config.reset_timeout)
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
                if elapsed >= self.reset_timeout_for(registry) {
                    // Transition to HalfOpen — allow one probe
                    breaker.state = BreakerState::HalfOpen;
                    breaker.half_open_in_flight = true;
                    breaker.half_open_started = Some(Instant::now());
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
                // A probe slot is held until the caller reports back via
                // `record_success`/`record_failure`. Some upstream outcomes
                // exit without reporting (4xx, body-extract error), which would
                // otherwise pin the slot and 503 every request forever. Treat a
                // probe outstanding longer than the reset timeout as lost and
                // start a fresh one (#585). `reset_timeout == 0` is the
                // degenerate "retry immediately" mode and keeps the strict
                // single-probe behavior.
                //
                // The complementary fix (#606): a 4xx upstream probe means the
                // upstream is alive, so call-sites now `record_alive()` which
                // closes the breaker from HalfOpen instead of leaving it to
                // slow-probe here forever.
                let reset = self.reset_timeout_for(registry);
                let probe_stalled = reset > 0
                    && breaker
                        .half_open_started
                        .is_none_or(|t| t.elapsed().as_secs() >= reset);
                if breaker.half_open_in_flight && !probe_stalled {
                    // Probe genuinely in flight — reject additional requests.
                    CIRCUIT_BREAKER_REJECTIONS
                        .with_label_values(&[registry])
                        .inc();
                    Err(ProxyError::CircuitOpen(registry.to_string()))
                } else {
                    if probe_stalled {
                        tracing::warn!(
                            registry = registry,
                            "Circuit breaker probe stalled (no result within reset timeout) — starting fresh probe"
                        );
                    }
                    // Slot free, or previous probe was lost — start a fresh probe.
                    breaker.half_open_in_flight = true;
                    breaker.half_open_started = Some(Instant::now());
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
        breaker.half_open_started = None;
        CIRCUIT_BREAKER_STATE
            .with_label_values(&[registry])
            .set(BreakerState::Closed.as_gauge());
    }

    /// Record that the upstream is alive and answered, without it being a
    /// successful fetch — specifically a 4xx response (e.g. artifact not found).
    ///
    /// In **HalfOpen** this closes the breaker: the probe proved the upstream is
    /// reachable, which is exactly the recovery #606 wants. In **Closed** it is a
    /// deliberate no-op — a 4xx must NOT reset the accumulated failure count, or
    /// an upstream interleaving 4xx (cache-miss probes) with 5xx (real failures)
    /// would never trip the breaker. This is stronger than `record_success`,
    /// which always resets `failures` and would mask such a partial outage.
    pub(crate) fn record_alive(&self, registry: &str) {
        if !self.config.enabled {
            return;
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        // Only HalfOpen transitions on an "alive" signal; Closed/Open are left
        // untouched so a 4xx never clears a real failure tally.
        if breaker.state == BreakerState::HalfOpen {
            tracing::info!(
                registry = registry,
                "Circuit breaker probe answered (4xx) — closing"
            );
            breaker.state = BreakerState::Closed;
            breaker.failures = 0;
            breaker.half_open_in_flight = false;
            breaker.half_open_started = None;
            CIRCUIT_BREAKER_STATE
                .with_label_values(&[registry])
                .set(BreakerState::Closed.as_gauge());
        }
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
                if breaker.failures >= self.threshold_for(registry) {
                    breaker.state = BreakerState::Open;
                    CIRCUIT_BREAKER_STATE
                        .with_label_values(&[registry])
                        .set(BreakerState::Open.as_gauge());
                    tracing::warn!(
                        registry = registry,
                        failures = breaker.failures,
                        threshold = self.threshold_for(registry),
                        "Circuit breaker OPEN — upstream failing"
                    );
                }
            }
            BreakerState::HalfOpen => {
                // Probe failed — back to Open
                breaker.state = BreakerState::Open;
                breaker.last_failure = Some(now);
                breaker.half_open_in_flight = false;
                breaker.half_open_started = None;
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
            overrides: std::collections::HashMap::new(),
        }
    }

    fn disabled_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: false,
            failure_threshold: 5,
            reset_timeout: 30,
            overrides: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_init_gauges_sets_closed() {
        // Use unique names to avoid interference from other tests (global metrics)
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        cb.init_gauges(&["init_test_a", "init_test_b"]);
        assert_eq!(
            CIRCUIT_BREAKER_STATE
                .with_label_values(&["init_test_a"])
                .get(),
            0,
            "gauge must be 0 (Closed) after init (#441)"
        );
        assert_eq!(
            CIRCUIT_BREAKER_STATE
                .with_label_values(&["init_test_b"])
                .get(),
            0,
        );
    }

    #[test]
    fn test_init_gauges_noop_when_disabled() {
        let cb = CircuitBreakerRegistry::new(disabled_config());
        // Should not panic or set anything
        cb.init_gauges(&["init_disabled_a"]);
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

    /// #606: a 4xx (`record_alive`) in the Closed state must NOT reset the
    /// failure counter — otherwise an upstream interleaving 4xx with 5xx would
    /// never trip the breaker. This is the masking regression a plain
    /// `record_success` on 4xx would introduce.
    #[test]
    fn test_record_alive_closed_preserves_failure_count() {
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        for _ in 0..4 {
            cb.record_failure("npm");
        }
        // An "alive" 4xx must leave the 4 accumulated failures intact...
        cb.record_alive("npm");
        // ...so the 5th real failure still trips the breaker.
        cb.record_failure("npm");
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
    }

    /// #606: a 4xx (`record_alive`) on the half-open probe means the upstream is
    /// alive, so it closes the breaker (recovery), unlike the Closed-state no-op.
    #[test]
    fn test_record_alive_halfopen_closes() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm");
        cb.record_failure("npm");
        // Open + reset_timeout 0 → next check transitions to HalfOpen (probe).
        assert!(cb.check("npm").is_ok());
        // The probe answered 4xx → upstream alive → breaker closes.
        cb.record_alive("npm");
        // Closed: repeated checks pass (not the single-probe HalfOpen behavior).
        assert!(cb.check("npm").is_ok());
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

    /// Regression for #585: a half-open probe that never reports back (a 4xx or
    /// body-extract path that skipped `record_*`) must NOT wedge the breaker at
    /// 503 forever. After the reset timeout the stalled slot is released and a
    /// fresh probe is allowed. Drives the real `check()` path; probe age is
    /// controlled by backdating the stored `Instant`s (deterministic, no sleep).
    #[test]
    fn test_halfopen_stalled_probe_recovers() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 1));
        cb.record_failure("npm");
        cb.record_failure("npm");

        // Backdate last_failure so the Open→HalfOpen transition fires now.
        {
            let mut b = cb.breakers.write();
            let br = b.get_mut("npm").unwrap();
            br.last_failure = Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
        }
        // First check → HalfOpen, probe in flight.
        assert!(cb.check("npm").is_ok());
        // Concurrency still holds within the window: a fresh probe is rejected.
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));

        // Simulate the probe being lost: backdate its start past the reset
        // timeout (this is the 4xx/extract-error exit that never recorded).
        {
            let mut b = cb.breakers.write();
            let br = b.get_mut("npm").unwrap();
            br.half_open_started =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(2));
        }
        // Next check must release the stalled slot and allow a fresh probe —
        // not 503 forever.
        assert!(
            cb.check("npm").is_ok(),
            "stalled half-open probe must be released, not wedge at 503 (#585)"
        );
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

    #[test]
    fn test_per_registry_override_threshold() {
        use crate::config::CircuitBreakerOverride;

        let mut overrides = std::collections::HashMap::new();
        overrides.insert(
            "docker:https://registry-1.docker.io".to_string(),
            CircuitBreakerOverride {
                failure_threshold: Some(10),
                reset_timeout: Some(120),
            },
        );
        let config = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            reset_timeout: 30,
            overrides,
        };
        let cb = CircuitBreakerRegistry::new(config);

        // Default key trips after 2 failures
        cb.record_failure("npm");
        cb.record_failure("npm");
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));

        // Docker Hub override requires 10 failures
        let docker_key = "docker:https://registry-1.docker.io";
        for _ in 0..9 {
            cb.record_failure(docker_key);
        }
        assert!(cb.check(docker_key).is_ok());
        // 10th trips it
        cb.record_failure(docker_key);
        assert!(matches!(
            cb.check(docker_key),
            Err(ProxyError::CircuitOpen(_))
        ));
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

    /// Regression for #606: a 4xx from upstream means the upstream is alive, so
    /// the half-open probe must `record_success` and close the breaker — not be
    /// "lost" (leaving it to slow-probe forever). Drives the real proxy path
    /// (`proxy_fetch_core`) against a mock upstream returning 404.
    #[tokio::test]
    async fn test_circuit_recovers_on_4xx_probe() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Upstream that is alive but answers 404 to everything.
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 0; // Open → HalfOpen immediately
            cfg.npm.proxy = Some(upstream.uri());
        });

        // Trip the breaker into Open.
        ctx.state.circuit_breaker.record_failure("npm");
        ctx.state.circuit_breaker.record_failure("npm");

        // Request now: Open + reset_timeout 0 → HalfOpen probe → upstream answers
        // 404 → record_success → breaker closes. The probe must reach upstream,
        // not be rejected with 503.
        let resp = send(&ctx.app, Method::GET, "/npm/nonexistent-pkg", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the half-open probe must reach upstream, not be rejected with 503"
        );

        // The 4xx probe recovered the breaker — it is Closed again. Before #606
        // the probe was 'lost' (no record), so the breaker stayed half-open and
        // this check would return CircuitOpen.
        assert!(
            ctx.state.circuit_breaker.check("npm").is_ok(),
            "a 4xx upstream response must close the breaker (#606)"
        );
    }
}
