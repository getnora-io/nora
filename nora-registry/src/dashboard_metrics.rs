// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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
