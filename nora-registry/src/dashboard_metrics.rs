// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{info, warn};

/// Known registry names for per-registry metrics
const REGISTRIES: &[&str] = &[
    "docker", "maven", "npm", "cargo", "pypi", "pub", "raw", "go",
];

/// Serializable snapshot of metrics for persistence.
/// Uses HashMap for per-registry counters — adding a new registry only
/// requires adding its name to REGISTRIES (one line).
#[derive(Serialize, Deserialize, Default)]
struct MetricsSnapshot {
    downloads: u64,
    uploads: u64,
    cache_hits: u64,
    cache_misses: u64,
    #[serde(default)]
    registry_downloads: HashMap<String, u64>,
    #[serde(default)]
    registry_uploads: HashMap<String, u64>,
}

/// Thread-safe atomic counter map for per-registry metrics.
struct CounterMap(HashMap<String, AtomicU64>);

impl CounterMap {
    fn new(keys: &[&str]) -> Self {
        let mut map = HashMap::with_capacity(keys.len());
        for &k in keys {
            map.insert(k.to_string(), AtomicU64::new(0));
        }
        Self(map)
    }

    fn inc(&self, key: &str) {
        if let Some(counter) = self.0.get(key) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn get(&self, key: &str) -> u64 {
        self.0
            .get(key)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn snapshot(&self) -> HashMap<String, u64> {
        self.0
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }

    fn load_from(&self, data: &HashMap<String, u64>) {
        for (k, v) in data {
            if let Some(counter) = self.0.get(k.as_str()) {
                counter.store(*v, Ordering::Relaxed);
            }
        }
    }
}

/// Dashboard metrics for tracking registry activity.
/// Global counters are separate fields; per-registry counters use CounterMap.
pub struct DashboardMetrics {
    pub downloads: AtomicU64,
    pub uploads: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,

    registry_downloads: CounterMap,
    registry_uploads: CounterMap,

    pub start_time: Instant,
    persist_path: Option<PathBuf>,
}

impl DashboardMetrics {
    pub fn new() -> Self {
        Self {
            downloads: AtomicU64::new(0),
            uploads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            registry_downloads: CounterMap::new(REGISTRIES),
            registry_uploads: CounterMap::new(REGISTRIES),
            start_time: Instant::now(),
            persist_path: None,
        }
    }

    /// Create metrics with persistence — loads existing data from metrics.json
    pub fn with_persistence(storage_path: &str) -> Self {
        let path = Path::new(storage_path).join("metrics.json");
        let mut metrics = Self::new();

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str::<MetricsSnapshot>(&data) {
                    Ok(snap) => {
                        metrics.downloads = AtomicU64::new(snap.downloads);
                        metrics.uploads = AtomicU64::new(snap.uploads);
                        metrics.cache_hits = AtomicU64::new(snap.cache_hits);
                        metrics.cache_misses = AtomicU64::new(snap.cache_misses);
                        metrics
                            .registry_downloads
                            .load_from(&snap.registry_downloads);
                        metrics.registry_uploads.load_from(&snap.registry_uploads);
                        info!(
                            downloads = snap.downloads,
                            uploads = snap.uploads,
                            "Loaded persisted metrics"
                        );
                    }
                    Err(e) => warn!("Failed to parse metrics.json: {}", e),
                },
                Err(e) => warn!("Failed to read metrics.json: {}", e),
            }
        }

        metrics.persist_path = Some(path);
        metrics
    }

    /// Save current metrics to disk (async to avoid blocking the runtime)
    pub async fn save(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let snap = MetricsSnapshot {
            downloads: self.downloads.load(Ordering::Relaxed),
            uploads: self.uploads.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            registry_downloads: self.registry_downloads.snapshot(),
            registry_uploads: self.registry_uploads.snapshot(),
        };
        let tmp = path.with_extension("json.tmp");
        if let Some(parent) = tmp.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if let Ok(data) = serde_json::to_string_pretty(&snap) {
            if tokio::fs::write(&tmp, &data).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, path).await;
            }
        }
    }

    pub fn record_download(&self, registry: &str) {
        self.downloads.fetch_add(1, Ordering::Relaxed);
        self.registry_downloads.inc(registry);
    }

    pub fn record_upload(&self, registry: &str) {
        self.uploads.fetch_add(1, Ordering::Relaxed);
        self.registry_uploads.inc(registry);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }

    pub fn get_registry_downloads(&self, registry: &str) -> u64 {
        self.registry_downloads.get(registry)
    }

    pub fn get_registry_uploads(&self, registry: &str) -> u64 {
        self.registry_uploads.get(registry)
    }
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_new_defaults() {
        let m = DashboardMetrics::new();
        assert_eq!(m.downloads.load(Ordering::Relaxed), 0);
        assert_eq!(m.uploads.load(Ordering::Relaxed), 0);
        assert_eq!(m.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(m.cache_misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_download_all_registries() {
        let m = DashboardMetrics::new();
        for reg in &[
            "docker", "npm", "maven", "cargo", "pypi", "pub", "go", "raw",
        ] {
            m.record_download(reg);
        }
        assert_eq!(m.downloads.load(Ordering::Relaxed), 8);
        assert_eq!(m.get_registry_downloads("docker"), 1);
        assert_eq!(m.get_registry_downloads("npm"), 1);
        assert_eq!(m.get_registry_downloads("maven"), 1);
        assert_eq!(m.get_registry_downloads("cargo"), 1);
        assert_eq!(m.get_registry_downloads("pypi"), 1);
        assert_eq!(m.get_registry_downloads("pub"), 1);
        assert_eq!(m.get_registry_downloads("go"), 1);
        assert_eq!(m.get_registry_downloads("raw"), 1);
    }

    #[test]
    fn test_record_download_unknown_registry() {
        let m = DashboardMetrics::new();
        m.record_download("unknown");
        assert_eq!(m.downloads.load(Ordering::Relaxed), 1);
        assert_eq!(m.get_registry_downloads("docker"), 0);
    }

    #[test]
    fn test_record_upload_all_registries() {
        let m = DashboardMetrics::new();
        for reg in &[
            "docker", "npm", "maven", "cargo", "pypi", "pub", "go", "raw",
        ] {
            m.record_upload(reg);
        }
        assert_eq!(m.uploads.load(Ordering::Relaxed), 8);
        assert_eq!(m.get_registry_uploads("docker"), 1);
        assert_eq!(m.get_registry_uploads("npm"), 1);
        assert_eq!(m.get_registry_uploads("maven"), 1);
        assert_eq!(m.get_registry_uploads("cargo"), 1);
        assert_eq!(m.get_registry_uploads("pypi"), 1);
        assert_eq!(m.get_registry_uploads("pub"), 1);
        assert_eq!(m.get_registry_uploads("go"), 1);
        assert_eq!(m.get_registry_uploads("raw"), 1);
    }

    #[test]
    fn test_record_upload_unknown_registry() {
        let m = DashboardMetrics::new();
        m.record_upload("npm");
        assert_eq!(m.uploads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_hit_rate_zero() {
        let m = DashboardMetrics::new();
        assert_eq!(m.cache_hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_hit_rate_all_hits() {
        let m = DashboardMetrics::new();
        m.record_cache_hit();
        m.record_cache_hit();
        assert_eq!(m.cache_hit_rate(), 100.0);
    }

    #[test]
    fn test_cache_hit_rate_mixed() {
        let m = DashboardMetrics::new();
        m.record_cache_hit();
        m.record_cache_miss();
        assert_eq!(m.cache_hit_rate(), 50.0);
    }

    #[test]
    fn test_get_registry_downloads() {
        let m = DashboardMetrics::new();
        m.record_download("docker");
        m.record_download("docker");
        m.record_download("npm");
        assert_eq!(m.get_registry_downloads("docker"), 2);
        assert_eq!(m.get_registry_downloads("npm"), 1);
        assert_eq!(m.get_registry_downloads("cargo"), 0);
        assert_eq!(m.get_registry_downloads("unknown"), 0);
    }

    #[test]
    fn test_get_registry_uploads() {
        let m = DashboardMetrics::new();
        m.record_upload("docker");
        assert_eq!(m.get_registry_uploads("docker"), 1);
        assert_eq!(m.get_registry_uploads("maven"), 0);
        assert_eq!(m.get_registry_uploads("unknown"), 0);
    }

    #[tokio::test]
    async fn test_persistence_save_and_load() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap();

        {
            let m = DashboardMetrics::with_persistence(path);
            m.record_download("docker");
            m.record_download("docker");
            m.record_upload("maven");
            m.record_cache_hit();
            m.save().await;
        }

        {
            let m = DashboardMetrics::with_persistence(path);
            assert_eq!(m.downloads.load(Ordering::Relaxed), 2);
            assert_eq!(m.uploads.load(Ordering::Relaxed), 1);
            assert_eq!(m.get_registry_downloads("docker"), 2);
            assert_eq!(m.get_registry_uploads("maven"), 1);
            assert_eq!(m.cache_hits.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn test_persistence_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let m = DashboardMetrics::with_persistence(path);
        assert_eq!(m.downloads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_default() {
        let m = DashboardMetrics::default();
        assert_eq!(m.downloads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_go_registry_supported() {
        let m = DashboardMetrics::new();
        m.record_download("go");
        assert_eq!(m.get_registry_downloads("go"), 1);
    }
}
