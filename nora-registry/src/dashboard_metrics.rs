// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{info, warn};

/// Serializable snapshot of metrics for persistence
#[derive(Serialize, Deserialize, Default)]
struct MetricsSnapshot {
    downloads: u64,
    uploads: u64,
    cache_hits: u64,
    cache_misses: u64,
    docker_downloads: u64,
    docker_uploads: u64,
    npm_downloads: u64,
    maven_downloads: u64,
    maven_uploads: u64,
    cargo_downloads: u64,
    pypi_downloads: u64,
    raw_downloads: u64,
    raw_uploads: u64,
}

/// Dashboard metrics for tracking registry activity
/// Uses atomic counters for thread-safe access without locks
pub struct DashboardMetrics {
    // Global counters
    pub downloads: AtomicU64,
    pub uploads: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,

    // Per-registry download counters
    pub docker_downloads: AtomicU64,
    pub docker_uploads: AtomicU64,
    pub npm_downloads: AtomicU64,
    pub maven_downloads: AtomicU64,
    pub maven_uploads: AtomicU64,
    pub cargo_downloads: AtomicU64,
    pub pypi_downloads: AtomicU64,
    pub raw_downloads: AtomicU64,
    pub raw_uploads: AtomicU64,

    pub start_time: Instant,

    /// Path to metrics.json for persistence
    persist_path: Option<PathBuf>,
}

impl DashboardMetrics {
    pub fn new() -> Self {
        Self {
            downloads: AtomicU64::new(0),
            uploads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            docker_downloads: AtomicU64::new(0),
            docker_uploads: AtomicU64::new(0),
            npm_downloads: AtomicU64::new(0),
            maven_downloads: AtomicU64::new(0),
            maven_uploads: AtomicU64::new(0),
            cargo_downloads: AtomicU64::new(0),
            pypi_downloads: AtomicU64::new(0),
            raw_downloads: AtomicU64::new(0),
            raw_uploads: AtomicU64::new(0),
            start_time: Instant::now(),
            persist_path: None,
        }
    }

    /// Create metrics with persistence — loads existing data from metrics.json
    pub fn with_persistence(storage_path: &str) -> Self {
        let path = Path::new(storage_path).join("metrics.json");
        let mut metrics = Self::new();
        metrics.persist_path = Some(path.clone());

        // Load existing metrics if file exists
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str::<MetricsSnapshot>(&data) {
                    Ok(snap) => {
                        metrics.downloads = AtomicU64::new(snap.downloads);
                        metrics.uploads = AtomicU64::new(snap.uploads);
                        metrics.cache_hits = AtomicU64::new(snap.cache_hits);
                        metrics.cache_misses = AtomicU64::new(snap.cache_misses);
                        metrics.docker_downloads = AtomicU64::new(snap.docker_downloads);
                        metrics.docker_uploads = AtomicU64::new(snap.docker_uploads);
                        metrics.npm_downloads = AtomicU64::new(snap.npm_downloads);
                        metrics.maven_downloads = AtomicU64::new(snap.maven_downloads);
                        metrics.maven_uploads = AtomicU64::new(snap.maven_uploads);
                        metrics.cargo_downloads = AtomicU64::new(snap.cargo_downloads);
                        metrics.pypi_downloads = AtomicU64::new(snap.pypi_downloads);
                        metrics.raw_downloads = AtomicU64::new(snap.raw_downloads);
                        metrics.raw_uploads = AtomicU64::new(snap.raw_uploads);
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

        metrics
    }

    /// Save current metrics to disk
    pub fn save(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let snap = MetricsSnapshot {
            downloads: self.downloads.load(Ordering::Relaxed),
            uploads: self.uploads.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            docker_downloads: self.docker_downloads.load(Ordering::Relaxed),
            docker_uploads: self.docker_uploads.load(Ordering::Relaxed),
            npm_downloads: self.npm_downloads.load(Ordering::Relaxed),
            maven_downloads: self.maven_downloads.load(Ordering::Relaxed),
            maven_uploads: self.maven_uploads.load(Ordering::Relaxed),
            cargo_downloads: self.cargo_downloads.load(Ordering::Relaxed),
            pypi_downloads: self.pypi_downloads.load(Ordering::Relaxed),
            raw_downloads: self.raw_downloads.load(Ordering::Relaxed),
            raw_uploads: self.raw_uploads.load(Ordering::Relaxed),
        };
        // Atomic write: write to tmp then rename
        let tmp = path.with_extension("json.tmp");
        if let Ok(data) = serde_json::to_string_pretty(&snap) {
            if std::fs::write(&tmp, &data).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Record a download event for the specified registry
    pub fn record_download(&self, registry: &str) {
        self.downloads.fetch_add(1, Ordering::Relaxed);
        match registry {
            "docker" => self.docker_downloads.fetch_add(1, Ordering::Relaxed),
            "npm" => self.npm_downloads.fetch_add(1, Ordering::Relaxed),
            "maven" => self.maven_downloads.fetch_add(1, Ordering::Relaxed),
            "cargo" => self.cargo_downloads.fetch_add(1, Ordering::Relaxed),
            "pypi" => self.pypi_downloads.fetch_add(1, Ordering::Relaxed),
            "raw" => self.raw_downloads.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Record an upload event for the specified registry
    pub fn record_upload(&self, registry: &str) {
        self.uploads.fetch_add(1, Ordering::Relaxed);
        match registry {
            "docker" => self.docker_uploads.fetch_add(1, Ordering::Relaxed),
            "maven" => self.maven_uploads.fetch_add(1, Ordering::Relaxed),
            "raw" => self.raw_uploads.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Calculate the cache hit rate as a percentage
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

    /// Get download count for a specific registry
    pub fn get_registry_downloads(&self, registry: &str) -> u64 {
        match registry {
            "docker" => self.docker_downloads.load(Ordering::Relaxed),
            "npm" => self.npm_downloads.load(Ordering::Relaxed),
            "maven" => self.maven_downloads.load(Ordering::Relaxed),
            "cargo" => self.cargo_downloads.load(Ordering::Relaxed),
            "pypi" => self.pypi_downloads.load(Ordering::Relaxed),
            "raw" => self.raw_downloads.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Get upload count for a specific registry
    pub fn get_registry_uploads(&self, registry: &str) -> u64 {
        match registry {
            "docker" => self.docker_uploads.load(Ordering::Relaxed),
            "maven" => self.maven_uploads.load(Ordering::Relaxed),
            "raw" => self.raw_uploads.load(Ordering::Relaxed),
            _ => 0,
        }
    }
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self::new()
    }
}
