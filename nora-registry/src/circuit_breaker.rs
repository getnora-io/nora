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

use crate::config::{CircuitBreakerConfig, CircuitBreakerOverride};
use crate::metrics::{CIRCUIT_BREAKER_REJECTIONS, CIRCUIT_BREAKER_STATE};
use crate::registry::ProxyError;
use crate::registry_type::RegistryType;
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Instant;

/// Breaker key of one configured upstream of `registry`:
/// `"<registry>:<upstream url>"`, trailing `/` trimmed and any `user:pass@`
/// userinfo dropped (the key is a metric label and a log field).
///
/// The URL must be the CONFIGURED upstream, never a URL the upstream returned
/// (a PyPI file href, a Terraform download_url): those hosts are chosen by the
/// upstream, and keying on them would let it mint unbounded breaker entries and
/// `nora_circuit_breaker_state` series. This is the key overrides are written
/// against (`[circuit_breaker.overrides."docker:https://registry-1.docker.io"]`).
pub(crate) fn upstream_key(registry: &str, upstream_url: &str) -> String {
    let url = upstream_url.trim_end_matches('/');
    let url = match url.find("://") {
        Some(sep) => {
            let (scheme, rest) = url.split_at(sep + 3);
            let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            match rest[..authority_end].rfind('@') {
                Some(at) => Cow::Owned(format!("{scheme}{}", &rest[at + 1..])),
                None => Cow::Borrowed(url),
            }
        }
        None => Cow::Borrowed(url),
    };
    format!("{registry}:{url}")
}

/// The format part of a breaker key: `"pypi:https://…"` → `"pypi"`, `"npm"` → `"npm"`.
fn registry_of(key: &str) -> &str {
    key.split_once(':').map_or(key, |(registry, _)| registry)
}

/// Breaker keys whose `nora_circuit_breaker_state` series is exported at
/// startup (#441): one per configured upstream for the formats keyed per
/// upstream (Docker, PyPI), the format name for every other format. A format
/// keyed per upstream gets no format-named series — it would sit at 0 (closed)
/// forever while the real state moves on the per-upstream series.
pub(crate) fn initial_gauge_keys(config: &crate::config::Config) -> Vec<String> {
    let mut keys = Vec::new();
    for rt in RegistryType::all() {
        match rt {
            RegistryType::Docker => keys.extend(
                config
                    .docker
                    .upstreams
                    .iter()
                    .map(|up| upstream_key(rt.as_str(), &up.url)),
            ),
            RegistryType::PyPI => keys.extend(
                config
                    .pypi
                    .upstreams()
                    .iter()
                    .map(|up| upstream_key(rt.as_str(), up.url())),
            ),
            _ => keys.push(rt.as_str().to_string()),
        }
    }
    keys
}

/// Which breaker an upstream call reports to: the format's shared breaker
/// (`From<RegistryType>`, key = the format name) or the breaker of one
/// configured upstream of that format ([`BreakerScope::upstream`], key =
/// [`upstream_key`]). Metrics other than the breaker's own stay per format.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BreakerScope<'a> {
    registry: RegistryType,
    upstream: Option<&'a str>,
}

impl<'a> BreakerScope<'a> {
    /// The breaker of the configured upstream `upstream_url` of `registry`.
    pub(crate) fn upstream(registry: RegistryType, upstream_url: &'a str) -> Self {
        Self {
            registry,
            upstream: Some(upstream_url),
        }
    }

    /// The format this call belongs to (the label of the per-format metrics).
    pub(crate) fn registry(&self) -> RegistryType {
        self.registry
    }

    /// The breaker key.
    pub(crate) fn key(&self) -> Cow<'static, str> {
        match self.upstream {
            Some(url) => Cow::Owned(upstream_key(self.registry.as_str(), url)),
            None => Cow::Borrowed(self.registry.as_str()),
        }
    }
}

impl From<RegistryType> for BreakerScope<'_> {
    fn from(registry: RegistryType) -> Self {
        Self {
            registry,
            upstream: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    /// Rank for "worst state" aggregation: open > half_open > closed.
    fn severity(self) -> u8 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::HalfOpen => 1,
            BreakerState::Open => 2,
        }
    }

    fn as_gauge(self) -> i64 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::Open => 1,
            BreakerState::HalfOpen => 2,
        }
    }

    /// Stable string used in the `/health` API. Mirrors the
    /// `nora_circuit_breaker_state` gauge semantics (0=closed, 1=open,
    /// 2=half_open) so operators see the same labels in both places.
    fn as_health_str(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

/// Read-only snapshot of one upstream's circuit-breaker state for the `/health`
/// API. Built from cached in-memory state only — never triggers a live upstream
/// probe, so the health endpoint stays fast and non-blocking.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UpstreamHealth {
    /// Breaker state: `closed` (healthy), `open` (failing fast), or
    /// `half_open` (probing recovery). The caller reports `disabled` when the
    /// circuit-breaker feature is off.
    pub status: &'static str,
    /// Accumulated consecutive-failure count (resets to 0 on success).
    pub failure_count: u32,
    /// Seconds since the most recent recorded failure, or `null` if the
    /// upstream has not failed since startup.
    pub last_failure_seconds_ago: Option<u64>,
}

/// Identifies the probe a caller was allowed to run, so a later
/// `record_success`/`record_failure`/`record_alive` can be FENCED. When the
/// #585 stall-recovery starts a fresh probe, the old probe is superseded; its
/// late report carries an older generation and must NOT mutate the breaker
/// ("treat as lost" — the comment's intent, now enforced). A non-probe
/// (Closed-path) request carries [`ProbeToken::BACKGROUND`], which is never
/// fenced — its failure simply accrues to the Closed-path tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeToken(u64);

impl ProbeToken {
    /// Not a probe — a Closed-path request. Its outcome accrues normally and is
    /// never fenced.
    pub(crate) const BACKGROUND: ProbeToken = ProbeToken(0);
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
    /// Monotonic generation of the CURRENT probe. Bumped each time `check()`
    /// grants a probe slot (Open→HalfOpen, or a fresh probe after a #585 stall).
    /// A probe holds the generation it was granted; `record_*` fence on it so a
    /// superseded ("lost") probe's late report is ignored (contract
    /// `circuit-breaker-probe-fenced`).
    probe_gen: u64,
}

impl BreakerInner {
    fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            failures: 0,
            last_failure: None,
            half_open_in_flight: false,
            half_open_started: None,
            probe_gen: 0,
        }
    }

    /// Grant a fresh probe slot: bump the generation and return its token.
    fn grant_probe(&mut self) -> ProbeToken {
        self.probe_gen += 1;
        self.half_open_in_flight = true;
        self.half_open_started = Some(Instant::now());
        ProbeToken(self.probe_gen)
    }

    /// True if `token` is NOT the current probe and not a background request —
    /// i.e. a superseded "lost" probe whose report must be ignored.
    fn is_stale(&self, token: ProbeToken) -> bool {
        token != ProbeToken::BACKGROUND && token.0 != self.probe_gen
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

    /// Whether the circuit-breaker feature is enabled (it is disabled by
    /// default). Used by `/health` to report `disabled` instead of a state.
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Read-only health snapshot for `registry` from cached in-memory state.
    ///
    /// Covers the format's shared breaker (`registry`) and every per-upstream
    /// breaker of it (`registry:<url>`, see [`upstream_key`]); with several, the
    /// worst one is reported (open > half_open > closed, then most failures), so
    /// a sick upstream stays visible even while another one still serves.
    ///
    /// Never performs a live upstream probe, so it is safe to call from the
    /// `/health` request path. Returns `None` when no breaker has been recorded
    /// for `registry` yet (no proxy traffic since startup), which the caller
    /// renders as a healthy `closed` default. The `last_failure` `Instant` is a
    /// monotonic clock, so the snapshot reports *seconds ago* rather than a
    /// wall-clock timestamp.
    pub(crate) fn health_snapshot(&self, registry: &str) -> Option<UpstreamHealth> {
        let breakers = self.breakers.read();
        let breaker = breakers
            .iter()
            .filter(|(key, _)| registry_of(key) == registry)
            .map(|(_, b)| b)
            .max_by_key(|b| (b.state.severity(), b.failures))?;
        Some(UpstreamHealth {
            status: breaker.state.as_health_str(),
            failure_count: breaker.failures,
            last_failure_seconds_ago: breaker.last_failure.map(|t| t.elapsed().as_secs()),
        })
    }

    /// Every breaker key recorded so far, sorted. Tests use it to pin the key
    /// set — one entry per configured upstream, never one per URL an upstream
    /// pointed at.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.breakers.read().keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Backdate `key`'s last failure past any reset timeout, so the next
    /// `check()` moves an Open breaker to HalfOpen without sleeping.
    #[cfg(test)]
    pub(crate) fn expire_open_for_test(&self, key: &str) {
        if let Some(b) = self.breakers.write().get_mut(key) {
            b.last_failure = Instant::now().checked_sub(std::time::Duration::from_secs(1 << 20));
        }
    }

    /// One override field for a breaker key: the key's own override, else the
    /// override of its format (so `overrides.pypi` keeps applying to every pypi
    /// upstream once they are keyed per upstream), else `None`.
    fn override_for<T>(
        &self,
        key: &str,
        field: impl Fn(&CircuitBreakerOverride) -> Option<T>,
    ) -> Option<T> {
        let own = self.config.overrides.get(key).and_then(&field);
        own.or_else(|| {
            let registry = registry_of(key);
            (registry != key)
                .then(|| self.config.overrides.get(registry).and_then(&field))
                .flatten()
        })
    }

    /// Resolve the failure threshold for a given registry key, checking overrides first.
    fn threshold_for(&self, registry: &str) -> u32 {
        self.override_for(registry, |o| o.failure_threshold)
            .unwrap_or(self.config.failure_threshold)
    }

    /// Resolve the reset timeout for a given registry key, checking overrides first.
    fn reset_timeout_for(&self, registry: &str) -> u64 {
        self.override_for(registry, |o| o.reset_timeout)
            .unwrap_or(self.config.reset_timeout)
    }

    /// Check if a request to `registry` should proceed.
    ///
    /// On success returns a [`ProbeToken`] the caller MUST pass back to
    /// `record_success`/`record_failure`/`record_alive` so a superseded probe's
    /// report can be fenced (#585 stall recovery). A Closed-path request gets
    /// [`ProbeToken::BACKGROUND`]; a HalfOpen probe gets its generation's token.
    /// Returns `Err(ProxyError::CircuitOpen)` if the breaker is open.
    pub(crate) fn check(&self, registry: &str) -> Result<ProbeToken, ProxyError> {
        if !self.config.enabled {
            return Ok(ProbeToken::BACKGROUND);
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        match breaker.state {
            BreakerState::Closed => Ok(ProbeToken::BACKGROUND),
            BreakerState::Open => {
                let elapsed = breaker
                    .last_failure
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(u64::MAX);
                if elapsed >= self.reset_timeout_for(registry) {
                    // Transition to HalfOpen — allow one probe (fresh generation).
                    breaker.state = BreakerState::HalfOpen;
                    let token = breaker.grant_probe();
                    CIRCUIT_BREAKER_STATE
                        .with_label_values(&[registry])
                        .set(BreakerState::HalfOpen.as_gauge());
                    tracing::info!(
                        registry = registry,
                        "Circuit breaker half-open, allowing probe"
                    );
                    Ok(token)
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
                    // Slot free, or previous probe was lost — start a fresh probe
                    // (new generation supersedes the lost one; its late report is
                    // fenced in record_*).
                    let token = breaker.grant_probe();
                    Ok(token)
                }
            }
        }
    }

    /// Record a successful upstream response. `token` is the [`ProbeToken`] from
    /// the matching `check()`; a superseded ("lost") probe's report is fenced.
    pub(crate) fn record_success(&self, registry: &str, token: ProbeToken) {
        if !self.config.enabled {
            return;
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        // Fence: ignore a superseded ("lost") probe's late report (#585) so it
        // cannot close/free a breaker that a newer probe now owns.
        if breaker.is_stale(token) {
            return;
        }

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
    pub(crate) fn record_alive(&self, registry: &str, token: ProbeToken) {
        if !self.config.enabled {
            return;
        }

        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        // Fence: ignore a superseded ("lost") probe's late report (#585).
        if breaker.is_stale(token) {
            return;
        }

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

    /// Record a failed upstream response. `token` is the [`ProbeToken`] from the
    /// matching `check()`; a superseded ("lost") probe's report is fenced so it
    /// cannot re-open or ghost-increment a breaker a newer probe now owns.
    pub(crate) fn record_failure(&self, registry: &str, token: ProbeToken) {
        if !self.config.enabled {
            return;
        }

        let now = Instant::now();
        let mut breakers = self.breakers.write();
        let breaker = breakers
            .entry(registry.to_string())
            .or_insert_with(BreakerInner::new);

        // Fence: ignore a superseded ("lost") probe's late report (#585).
        if breaker.is_stale(token) {
            return;
        }

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
            cb.record_failure("npm", ProbeToken::BACKGROUND);
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
            cb.record_failure("npm", ProbeToken::BACKGROUND);
        }
        assert!(cb.check("npm").is_ok());

        // 5th failure trips
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreakerRegistry::new(enabled_config(5, 30));
        for _ in 0..4 {
            cb.record_failure("npm", ProbeToken::BACKGROUND);
        }
        cb.record_success("npm", ProbeToken::BACKGROUND);
        // After reset, 4 more failures should not trip
        for _ in 0..4 {
            cb.record_failure("npm", ProbeToken::BACKGROUND);
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
            cb.record_failure("npm", ProbeToken::BACKGROUND);
        }
        // An "alive" 4xx must leave the 4 accumulated failures intact...
        cb.record_alive("npm", ProbeToken::BACKGROUND);
        // ...so the 5th real failure still trips the breaker.
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));
    }

    /// #606: a 4xx (`record_alive`) on the half-open probe means the upstream is
    /// alive, so it closes the breaker (recovery), unlike the Closed-state no-op.
    #[test]
    fn test_record_alive_halfopen_closes() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        // Open + reset_timeout 0 → next check transitions to HalfOpen (probe).
        assert!(cb.check("npm").is_ok());
        // The probe answered 4xx → upstream alive → breaker closes.
        cb.record_alive("npm", ProbeToken::BACKGROUND);
        // Closed: repeated checks pass (not the single-probe HalfOpen behavior).
        assert!(cb.check("npm").is_ok());
        assert!(cb.check("npm").is_ok());
    }

    #[test]
    fn test_open_to_halfopen_after_timeout() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0)); // 0s timeout = immediate
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        // Should be open, but timeout=0 means immediate half-open transition
        assert!(cb.check("npm").is_ok()); // transitions to HalfOpen, probe allowed
    }

    #[test]
    fn test_halfopen_probe_success_closes() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        // Transition to half-open
        assert!(cb.check("npm").is_ok());
        // Probe success
        cb.record_success("npm", ProbeToken::BACKGROUND);
        // Should be closed now
        assert!(cb.check("npm").is_ok());
    }

    #[test]
    fn test_halfopen_probe_failure_reopens() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        // Transition to half-open
        assert!(cb.check("npm").is_ok());
        // Probe fails
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        // Should be open again — next check transitions to half-open (timeout=0)
        // but the FIRST check after re-open with timeout=0 transitions immediately
        let result = cb.check("npm");
        assert!(result.is_ok()); // timeout=0 → immediate half-open again
    }

    #[test]
    fn test_halfopen_rejects_concurrent() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 0));
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
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
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);

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
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
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
                    cb.record_failure(&registry, ProbeToken::BACKGROUND);
                    cb.record_success(&registry, ProbeToken::BACKGROUND);
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
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        cb.record_failure("npm", ProbeToken::BACKGROUND);
        assert!(matches!(cb.check("npm"), Err(ProxyError::CircuitOpen(_))));

        // Docker Hub override requires 10 failures
        let docker_key = "docker:https://registry-1.docker.io";
        for _ in 0..9 {
            cb.record_failure(docker_key, ProbeToken::BACKGROUND);
        }
        assert!(cb.check(docker_key).is_ok());
        // 10th trips it
        cb.record_failure(docker_key, ProbeToken::BACKGROUND);
        assert!(matches!(
            cb.check(docker_key),
            Err(ProxyError::CircuitOpen(_))
        ));
    }

    /// The Docker key is the one Docker always used —
    /// `docker:<upstream url without trailing />` — now produced by the shared
    /// helper; operators' `overrides."docker:…"` keep matching.
    #[test]
    fn upstream_key_keeps_the_docker_key() {
        assert_eq!(
            upstream_key("docker", "https://registry-1.docker.io/"),
            "docker:https://registry-1.docker.io"
        );
        for url in [
            "https://registry-1.docker.io",
            "https://registry-1.docker.io/",
            "http://127.0.0.1:5000//",
            "https://ghcr.io/v2/",
            "https://Mirror.Example:8443/prefix",
        ] {
            assert_eq!(
                upstream_key("docker", url),
                format!("docker:{}", url.trim_end_matches('/')),
                "{url}"
            );
        }
    }

    /// The key is a metric label and a log field: credentials in the URL's
    /// userinfo never reach it. An `@` outside the authority is left alone.
    #[test]
    fn upstream_key_drops_userinfo_only() {
        assert_eq!(
            upstream_key("pypi", "https://user:s3cret@nexus.example/simple/"),
            "pypi:https://nexus.example/simple"
        );
        assert_eq!(
            upstream_key("pypi", "https://tok@nexus.example"),
            "pypi:https://nexus.example"
        );
        assert_eq!(
            upstream_key("pypi", "https://nexus.example/a@b/simple"),
            "pypi:https://nexus.example/a@b/simple"
        );
        assert_eq!(
            upstream_key("pypi", "https://nexus.example?x=a@b"),
            "pypi:https://nexus.example?x=a@b"
        );
    }

    #[test]
    fn breaker_scope_keys() {
        let format: BreakerScope = RegistryType::Npm.into();
        assert_eq!(format.key(), "npm");
        assert_eq!(format.registry(), RegistryType::Npm);
        let up = BreakerScope::upstream(RegistryType::PyPI, "https://pypi.org/simple/");
        assert_eq!(up.key(), "pypi:https://pypi.org/simple");
        assert_eq!(up.registry(), RegistryType::PyPI);
    }

    #[test]
    fn upstreams_of_one_format_trip_independently() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 30));
        let (a, b) = (
            upstream_key("pypi", "https://a/simple"),
            upstream_key("pypi", "https://b/simple"),
        );
        cb.record_failure(&a, ProbeToken::BACKGROUND);
        cb.record_failure(&a, ProbeToken::BACKGROUND);
        assert!(matches!(cb.check(&a), Err(ProxyError::CircuitOpen(_))));
        assert!(cb.check(&b).is_ok());
    }

    /// `overrides.pypi` keeps applying once pypi is keyed per upstream; an
    /// override of the upstream's own key wins, field by field.
    #[test]
    fn override_falls_back_to_the_format() {
        use crate::config::CircuitBreakerOverride;
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(
            "pypi".to_string(),
            CircuitBreakerOverride {
                failure_threshold: Some(4),
                reset_timeout: Some(77),
            },
        );
        overrides.insert(
            "pypi:https://b/simple".to_string(),
            CircuitBreakerOverride {
                failure_threshold: Some(9),
                reset_timeout: None,
            },
        );
        let cb = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            reset_timeout: 30,
            overrides,
        });
        assert_eq!(cb.threshold_for("pypi:https://a/simple"), 4);
        assert_eq!(cb.reset_timeout_for("pypi:https://a/simple"), 77);
        assert_eq!(cb.threshold_for("pypi:https://b/simple"), 9);
        assert_eq!(cb.reset_timeout_for("pypi:https://b/simple"), 77);
        assert_eq!(cb.threshold_for("pypi"), 4);
        assert_eq!(cb.threshold_for("npm"), 2);
        assert_eq!(
            cb.threshold_for("pypix:https://a"),
            2,
            "format matched whole"
        );
    }

    /// `/health` reports a format by its worst upstream, and only that format's.
    #[test]
    fn health_snapshot_reports_worst_upstream_of_the_format() {
        let cb = CircuitBreakerRegistry::new(enabled_config(2, 3600));
        let (a, b) = (
            upstream_key("pypi", "https://a/simple"),
            upstream_key("pypi", "https://b/simple"),
        );
        assert!(cb.health_snapshot("pypi").is_none());
        cb.record_failure(&a, ProbeToken::BACKGROUND);
        cb.record_failure(&b, ProbeToken::BACKGROUND);
        cb.record_failure(&b, ProbeToken::BACKGROUND);
        cb.record_failure("pip", ProbeToken::BACKGROUND);
        let snap = cb.health_snapshot("pypi").unwrap();
        assert_eq!(snap.status, "open");
        assert_eq!(snap.failure_count, 2);
        assert_eq!(cb.health_snapshot("pip").unwrap().failure_count, 1);
        assert!(cb.health_snapshot("py").is_none(), "format matched whole");
    }

    /// Startup series: per configured upstream for Docker and PyPI, the format
    /// name for the rest — never a format-named series that cannot move.
    #[test]
    fn initial_gauge_keys_follow_the_breaker_keys() {
        let mut config = crate::config::Config::default();
        config.pypi.proxy = Some("https://pypi.org/simple/".into());
        config.docker.upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".into(),
            auth: None,
            namespace: None,
            prefix: None,
        }];
        let keys = initial_gauge_keys(&config);
        assert!(keys.contains(&"pypi:https://pypi.org/simple".to_string()));
        assert!(keys.contains(&"docker:https://registry-1.docker.io".to_string()));
        assert!(keys.contains(&"npm".to_string()));
        assert!(
            !keys.iter().any(|k| k == "pypi" || k == "docker"),
            "{keys:?}"
        );
    }

    /// Regression for the #585 stale-probe race (found by TLA+ model checking of
    /// the probe lifecycle): a probe the breaker has SUPERSEDED (a fresh probe started
    /// after it stalled) must NOT mutate the breaker when it finally reports — its
    /// ProbeToken is fenced. Before the fix, the stale report closed/ghost-failed a
    /// breaker a newer probe owned.
    #[test]
    fn stale_probe_report_is_fenced() {
        use std::thread::sleep;
        use std::time::Duration;
        let cb = CircuitBreakerRegistry::new(enabled_config(1, 1)); // threshold 1, reset 1s
        let reg = "stale_probe_fence_test";

        // Trip to Open (threshold 1).
        cb.record_failure(reg, ProbeToken::BACKGROUND);
        assert!(matches!(cb.check(reg), Err(ProxyError::CircuitOpen(_))));

        // After reset_timeout -> HalfOpen, probe g1.
        sleep(Duration::from_millis(1100));
        let t1 = cb.check(reg).expect("half-open should grant probe g1");

        // g1 stalls (outlives reset_timeout) -> a fresh check grants probe g2;
        // g1 is now superseded ("lost").
        sleep(Duration::from_millis(1100));
        let t2 = cb.check(reg).expect("stalled probe -> fresh probe g2");
        assert_ne!(t1, t2, "fresh probe must be a new generation");

        // The STALE probe g1 reports SUCCESS late: FENCED, so it must NOT close the
        // breaker — g2 is still the live in-flight probe.
        cb.record_success(reg, t1);
        assert!(
            matches!(cb.check(reg), Err(ProxyError::CircuitOpen(_))),
            "stale probe success must not close the breaker (g2 still in flight)"
        );

        // The CURRENT probe g2 closes it correctly.
        cb.record_success(reg, t2);
        assert!(
            cb.check(reg).is_ok(),
            "current probe success closes the breaker"
        );

        // A late STALE g1 FAILURE on the now-Closed breaker must also be fenced — no
        // ghost-increment that could re-trip Open at threshold 1.
        cb.record_failure(reg, t1);
        assert!(
            cb.check(reg).is_ok(),
            "stale probe failure must not ghost-increment / re-open a recovered breaker"
        );
    }
}

/// Integration tests — verify 503 response through the full HTTP router.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use super::ProbeToken;
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
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);

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

        // PyPI keys its breaker per configured upstream.
        let key = super::upstream_key("pypi", "http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);

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

    /// Simple-index page for `demo` listing `files` (absolute hrefs).
    fn demo_index(files: &[String]) -> String {
        let links: String = files
            .iter()
            .map(|url| {
                let name = url.rsplit('/').next().unwrap_or(url);
                format!(r#"<a href="{url}">{name}</a>"#)
            })
            .collect();
        format!("<html><body>{links}</body></html>")
    }

    /// Contract `pypi-multi-upstream-shared-breaker`: a dead upstream opens ITS
    /// breaker only. Upstream #1 answers 500; upstream #2 is healthy and lists
    /// files hosted on a third server (as pypi.org lists files.pythonhosted.org).
    /// Once #1's breaker is open, #2 keeps serving the index and the files, #1 is
    /// no longer contacted, and the file host never becomes a breaker key (its
    /// authority comes from the upstream's HTML, so keying on it would hand the
    /// upstream control of the `nora_circuit_breaker_state` label set).
    #[tokio::test]
    async fn test_dead_pypi_upstream_does_not_open_breaker_of_healthy_one() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dead = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&dead)
            .await;

        let files = MockServer::start().await;
        for name in ["demo-1.0.tar.gz", "demo-2.0.tar.gz"] {
            Mock::given(method("GET"))
                .and(path(format!("/packages/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(name.as_bytes()))
                .mount(&files)
                .await;
        }

        let healthy = MockServer::start().await;
        let listed: Vec<String> = ["demo-1.0.tar.gz", "demo-2.0.tar.gz"]
            .iter()
            .map(|name| format!("{}/packages/{name}", files.uri()))
            .collect();
        Mock::given(method("GET"))
            .and(path("/simple/demo/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(demo_index(&listed)),
            )
            .mount(&healthy)
            .await;

        let dead_url = dead.uri();
        let healthy_url = format!("{}/simple/", healthy.uri());
        let (d, h) = (dead_url.clone(), healthy_url.clone());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxy = None;
            // `PypiProxyEntry` is not re-exported; build the plain-URL form via serde.
            cfg.pypi.proxies = [d, h]
                .into_iter()
                .map(|u| serde_json::from_value(serde_json::Value::String(u)).unwrap())
                .collect();
        });

        // First file: #1 fails (and its breaker opens at threshold 1), #2 serves.
        let resp = send(&ctx.app, Method::GET, "/simple/demo/demo-1.0.tar.gz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the healthy upstream must serve"
        );
        assert_eq!(&body_bytes(resp).await[..], b"demo-1.0.tar.gz");
        let dead_hits = dead.received_requests().await.unwrap().len();
        assert!(dead_hits > 0, "the dead upstream was tried first");

        // #1's breaker is open now: the next file and the index skip #1 without
        // contacting it, and #2 still answers both.
        let resp = send(&ctx.app, Method::GET, "/simple/demo/demo-2.0.tar.gz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an open breaker on upstream #1 must not short-circuit upstream #2"
        );
        assert_eq!(&body_bytes(resp).await[..], b"demo-2.0.tar.gz");
        let resp = send(&ctx.app, Method::GET, "/simple/demo/", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "index merges what answered");
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("demo-2.0.tar.gz"));
        assert_eq!(
            dead.received_requests().await.unwrap().len(),
            dead_hits,
            "upstream #1's breaker is open, so it is not contacted again"
        );

        // One breaker per configured upstream; the file host is not a key.
        let keys = ctx.state.circuit_breaker.keys();
        assert_eq!(
            keys,
            {
                let mut want = vec![
                    format!("pypi:{}", dead_url.trim_end_matches('/')),
                    format!("pypi:{}", healthy_url.trim_end_matches('/')),
                ];
                want.sort();
                want
            },
            "breaker keys are the configured upstreams"
        );
        let file_host = files.uri();
        assert!(
            keys.iter().all(|k| !k.contains(file_host.as_str())),
            "a URL the upstream pointed at must not mint a breaker key: {keys:?}"
        );
    }

    /// Single pypi upstream: the breaker opens, half-opens and closes on the one
    /// key of that upstream, exactly as before the per-upstream split, and
    /// `/health` still reports it under `pypi`.
    #[tokio::test]
    async fn test_single_pypi_upstream_breaker_cycle_unchanged() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxy = Some(uri);
        });

        // Closed → the request reaches upstream, which fails → Open. (Its own
        // status is not pinned: the dates prefetch already trips threshold 1
        // before the page fetch, so this request may itself end in 503.)
        send(&ctx.app, Method::GET, "/simple/demo/demo-1.0.tar.gz", "").await;
        let hits = upstream.received_requests().await.unwrap().len();
        assert!(hits > 0);

        // Open → 503 + Retry-After without contacting upstream.
        let resp = send(&ctx.app, Method::GET, "/simple/demo/demo-1.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        assert_eq!(upstream.received_requests().await.unwrap().len(), hits);
        assert_eq!(
            ctx.state.circuit_breaker.keys().len(),
            1,
            "one upstream, one key"
        );

        let resp = send(&ctx.app, Method::GET, "/health", "").await;
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(json["upstreams"]["pypi"]["status"], "open");
        assert_eq!(json["upstreams"]["pypi"]["failure_count"], 1);

        // Upstream recovers; the half-open probe closes the breaker on that key.
        upstream.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let key = ctx.state.circuit_breaker.keys().remove(0);
        ctx.state.circuit_breaker.expire_open_for_test(&key);
        let resp = send(&ctx.app, Method::GET, "/simple/demo/demo-1.0.tar.gz", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "probe reaches upstream"
        );
        let resp = send(&ctx.app, Method::GET, "/health", "").await;
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(json["upstreams"]["pypi"]["status"], "closed");
    }

    /// Docker keys its breakers through the shared [`super::upstream_key`]: a
    /// configured upstream written with userinfo and a trailing `/` is recorded
    /// under the same key the helper (and `overrides`) produce.
    #[tokio::test]
    async fn test_docker_breaker_key_comes_from_shared_helper() {
        use crate::config::DockerUpstream;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        let configured = upstream.uri().replace("http://", "http://u:p@") + "/";
        let url = configured.clone();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.docker.upstreams = vec![DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        send(
            &ctx.app,
            Method::GET,
            "/v2/library/alpine/manifests/latest",
            "",
        )
        .await;
        assert_eq!(
            ctx.state.circuit_breaker.keys(),
            vec![super::upstream_key("docker", &configured)]
        );
        assert_eq!(
            ctx.state.circuit_breaker.keys(),
            vec![format!("docker:{}", upstream.uri())],
            "no credentials, no trailing slash in the key"
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
            ctx.state
                .circuit_breaker
                .record_failure("npm", ProbeToken::BACKGROUND);
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
            cfg.pypi.proxy = Some("http://127.0.0.1:1".into());
        });

        // Publish a package to local storage
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball")
            .await
            .unwrap();

        // Trip the breaker of the configured pypi upstream
        ctx.state.circuit_breaker.record_failure(
            &super::upstream_key("pypi", "http://127.0.0.1:1"),
            ProbeToken::BACKGROUND,
        );

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
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);

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
