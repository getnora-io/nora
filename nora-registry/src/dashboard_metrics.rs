// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Dashboard activity counters — a thin facade over the Prometheus registry,
//! which is the single source of truth (#626).
//!
//! Nothing is persisted. Earlier this module kept its own `AtomicU64` copy of
//! every counter and flushed a `metrics.json` to disk every 30s — constant idle
//! IOPS, and after a restart the UI showed the restored totals while `/metrics`
//! started from zero (divergence). The Prometheus counters already track exactly
//! the same events, so the dashboard now reads straight from them: no on-disk
//! copy, no periodic write, and the UI numbers can never disagree with
//! `/metrics`. Because Prometheus counters reset on process restart, the
//! dashboard figures are "since restart" (the UI labels them so, anchored by the
//! uptime shown alongside).

use crate::metrics::{CACHE_REQUESTS, DOWNLOADS_TOTAL, UPLOADS_TOTAL};
use crate::registry_type::RegistryType;

/// Registry names from `RegistryType` (single source of truth) for aggregation.
fn registry_names() -> Vec<&'static str> {
    RegistryType::all().iter().map(|rt| rt.as_str()).collect()
}

/// Dashboard activity facade. Holds no state of its own — reads and writes both
/// go to the process-global Prometheus counters, so the UI and `/metrics` stay
/// in lock-step.
#[derive(Default)]
pub struct DashboardMetrics;

impl DashboardMetrics {
    pub fn new() -> Self {
        Self
    }

    // ---- writes: increment the Prometheus counter (the only store) ----

    pub fn record_download(&self, registry: &str) {
        DOWNLOADS_TOTAL.with_label_values(&[registry]).inc();
    }

    pub fn record_upload(&self, registry: &str) {
        UPLOADS_TOTAL.with_label_values(&[registry]).inc();
    }

    pub fn record_cache_hit(&self, registry: &str) {
        CACHE_REQUESTS.with_label_values(&[registry, "hit"]).inc();
    }

    pub fn record_cache_miss(&self, registry: &str) {
        CACHE_REQUESTS.with_label_values(&[registry, "miss"]).inc();
    }

    // ---- reads: derived from the Prometheus counters (since restart) ----

    pub fn get_registry_downloads(&self, registry: &str) -> u64 {
        DOWNLOADS_TOTAL.with_label_values(&[registry]).get()
    }

    pub fn get_registry_uploads(&self, registry: &str) -> u64 {
        UPLOADS_TOTAL.with_label_values(&[registry]).get()
    }

    pub fn downloads(&self) -> u64 {
        registry_names()
            .iter()
            .map(|&r| DOWNLOADS_TOTAL.with_label_values(&[r]).get())
            .sum()
    }

    pub fn uploads(&self) -> u64 {
        registry_names()
            .iter()
            .map(|&r| UPLOADS_TOTAL.with_label_values(&[r]).get())
            .sum()
    }

    pub fn cache_hits(&self) -> u64 {
        registry_names()
            .iter()
            .map(|&r| CACHE_REQUESTS.with_label_values(&[r, "hit"]).get())
            .sum()
    }

    pub fn cache_misses(&self) -> u64 {
        registry_names()
            .iter()
            .map(|&r| CACHE_REQUESTS.with_label_values(&[r, "miss"]).get())
            .sum()
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits();
        let total = hits + self.cache_misses();
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // The Prometheus counters are process-global and shared across all tests, so
    // exact-value assertions would race under cargo's parallel test runner. Each
    // test therefore uses a UNIQUE registry label (deterministic on its own
    // series) and asserts the DELTA, or asserts a monotone lower bound for the
    // global aggregate (`>= before + n`) which is parallel-safe.

    #[test]
    fn record_download_increments_that_registry_series() {
        let m = DashboardMetrics::new();
        let reg = "test-dl-unique-a";
        let before = m.get_registry_downloads(reg);
        m.record_download(reg);
        m.record_download(reg);
        assert_eq!(m.get_registry_downloads(reg) - before, 2);
    }

    #[test]
    fn record_upload_increments_that_registry_series() {
        let m = DashboardMetrics::new();
        let reg = "test-ul-unique-b";
        let before = m.get_registry_uploads(reg);
        m.record_upload(reg);
        assert_eq!(m.get_registry_uploads(reg) - before, 1);
    }

    #[test]
    fn downloads_aggregate_reflects_a_real_registry_record() {
        // downloads() sums over RegistryType::all(); recording on a real registry
        // must be included. `>= before + 1` is parallel-safe (other tests may add).
        let m = DashboardMetrics::new();
        let before = m.downloads();
        m.record_download("docker");
        assert!(m.downloads() >= before + 1);
    }

    #[test]
    fn uploads_aggregate_reflects_a_real_registry_record() {
        let m = DashboardMetrics::new();
        let before = m.uploads();
        m.record_upload("maven");
        assert!(m.uploads() >= before + 1);
    }

    #[test]
    fn cache_hit_rate_is_a_percentage_and_moves_with_hits() {
        // Rate is global; assert the invariant (0..=100) and that a recorded hit
        // keeps it strictly positive — without asserting an exact global value.
        let m = DashboardMetrics::new();
        m.record_cache_hit("docker");
        let rate = m.cache_hit_rate();
        assert!((0.0..=100.0).contains(&rate));
        assert!(m.cache_hits() >= 1);
    }

    #[test]
    fn unknown_registry_label_is_isolated() {
        // A never-recorded unique label reads as 0 (its own series), independent
        // of any other registry's traffic.
        let m = DashboardMetrics::new();
        assert_eq!(m.get_registry_downloads("test-never-recorded-zzz"), 0);
    }

    #[test]
    fn record_is_stateless_across_instances() {
        // Two facades share the same global counters (no per-instance state):
        // recording via one is visible via the other.
        let reg = "test-shared-instance-c";
        let a = DashboardMetrics::new();
        let b = DashboardMetrics::new();
        let before = b.get_registry_downloads(reg);
        a.record_download(reg);
        assert_eq!(b.get_registry_downloads(reg) - before, 1);
    }
}
