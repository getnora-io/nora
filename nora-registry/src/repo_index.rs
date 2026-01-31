// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! In-memory repository index with lazy rebuild on invalidation.
//!
//! Design (Torvalds-approved):
//! - Rebuild happens ONLY on write operations, not TTL
//! - Double-checked locking prevents duplicate rebuilds
//! - Arc<Vec> for zero-cost reads
//! - Single rebuild at a time per registry (rebuild_lock)

use crate::storage::Storage;
use crate::ui::components::format_timestamp;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

/// Repository info for UI display
#[derive(Debug, Clone, Serialize)]
pub struct RepoInfo {
    pub name: String,
    pub versions: usize,
    pub size: u64,
    pub updated: String,
}

/// Index for a single registry type
pub struct RegistryIndex {
    data: RwLock<Arc<Vec<RepoInfo>>>,
    dirty: AtomicBool,
    rebuild_lock: AsyncMutex<()>,
}

impl RegistryIndex {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(Arc::new(Vec::new())),
            dirty: AtomicBool::new(true),
            rebuild_lock: AsyncMutex::new(()),
        }
    }

    /// Mark index as needing rebuild
    pub fn invalidate(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    fn get_cached(&self) -> Arc<Vec<RepoInfo>> {
        Arc::clone(&self.data.read())
    }

    fn set(&self, data: Vec<RepoInfo>) {
        *self.data.write() = Arc::new(data);
        self.dirty.store(false, Ordering::Release);
    }

    pub fn count(&self) -> usize {
        self.data.read().len()
    }
}

impl Default for RegistryIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Main repository index for all registries
pub struct RepoIndex {
    pub docker: RegistryIndex,
    pub maven: RegistryIndex,
    pub npm: RegistryIndex,
    pub cargo: RegistryIndex,
    pub pypi: RegistryIndex,
}

impl RepoIndex {
    pub fn new() -> Self {
        Self {
            docker: RegistryIndex::new(),
            maven: RegistryIndex::new(),
            npm: RegistryIndex::new(),
            cargo: RegistryIndex::new(),
            pypi: RegistryIndex::new(),
        }
    }

    /// Invalidate a specific registry index
    pub fn invalidate(&self, registry: &str) {
        match registry {
            "docker" => self.docker.invalidate(),
            "maven" => self.maven.invalidate(),
            "npm" => self.npm.invalidate(),
            "cargo" => self.cargo.invalidate(),
            "pypi" => self.pypi.invalidate(),
            _ => {}
        }
    }

    /// Get index with double-checked locking (prevents race condition)
    pub async fn get(&self, registry: &str, storage: &Storage) -> Arc<Vec<RepoInfo>> {
        let index = match registry {
            "docker" => &self.docker,
            "maven" => &self.maven,
            "npm" => &self.npm,
            "cargo" => &self.cargo,
            "pypi" => &self.pypi,
            _ => return Arc::new(Vec::new()),
        };

        // Fast path: not dirty, return cached
        if !index.is_dirty() {
            return index.get_cached();
        }

        // Slow path: acquire rebuild lock (only one thread rebuilds)
        let _guard = index.rebuild_lock.lock().await;

        // Double-check under lock (another thread may have rebuilt)
        if index.is_dirty() {
            let data = match registry {
                "docker" => build_docker_index(storage).await,
                "maven" => build_maven_index(storage).await,
                "npm" => build_npm_index(storage).await,
                "cargo" => build_cargo_index(storage).await,
                "pypi" => build_pypi_index(storage).await,
                _ => Vec::new(),
            };
            info!(registry = registry, count = data.len(), "Index rebuilt");
            index.set(data);
        }

        index.get_cached()
    }

    /// Get counts for stats (no rebuild, just current state)
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.docker.count(),
            self.maven.count(),
            self.npm.count(),
            self.cargo.count(),
            self.pypi.count(),
        )
    }
}

impl Default for RepoIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Index builders
// ============================================================================

async fn build_docker_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("docker/").await;
    let mut repos: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if key.ends_with(".meta.json") {
            continue;
        }

        if let Some(rest) = key.strip_prefix("docker/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 3 && parts[1] == "manifests" && key.ends_with(".json") {
                let name = parts[0].to_string();
                let entry = repos.entry(name).or_insert((0, 0, 0));
                entry.0 += 1;

                if let Ok(data) = storage.get(key).await {
                    if let Ok(m) = serde_json::from_slice::<serde_json::Value>(&data) {
                        let cfg = m
                            .get("config")
                            .and_then(|c| c.get("size"))
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0);
                        let layers: u64 = m
                            .get("layers")
                            .and_then(|l| l.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|l| l.get("size").and_then(|s| s.as_u64()))
                                    .sum()
                            })
                            .unwrap_or(0);
                        entry.1 += cfg + layers;
                    }
                }

                if let Some(meta) = storage.stat(key).await {
                    if meta.modified > entry.2 {
                        entry.2 = meta.modified;
                    }
                }
            }
        }
    }

    to_sorted_vec(repos)
}

async fn build_maven_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("maven/").await;
    let mut repos: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("maven/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 2 {
                let path = parts[..parts.len() - 1].join("/");
                let entry = repos.entry(path).or_insert((0, 0, 0));
                entry.0 += 1;

                if let Some(meta) = storage.stat(key).await {
                    entry.1 += meta.size;
                    if meta.modified > entry.2 {
                        entry.2 = meta.modified;
                    }
                }
            }
        }
    }

    to_sorted_vec(repos)
}

async fn build_npm_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("npm/").await;
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    // Count tarballs instead of parsing metadata.json (Linus-approved)
    for key in &keys {
        if let Some(rest) = key.strip_prefix("npm/") {
            // Pattern: npm/{package}/tarballs/{file}.tgz
            if rest.contains("/tarballs/") && key.ends_with(".tgz") {
                let parts: Vec<_> = rest.split('/').collect();
                if !parts.is_empty() {
                    let name = parts[0].to_string();
                    let entry = packages.entry(name).or_insert((0, 0, 0));
                    entry.0 += 1;

                    if let Some(meta) = storage.stat(key).await {
                        entry.1 += meta.size;
                        if meta.modified > entry.2 {
                            entry.2 = meta.modified;
                        }
                    }
                }
            }
        }
    }

    to_sorted_vec(packages)
}

async fn build_cargo_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("cargo/").await;
    let mut crates: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if key.ends_with(".crate") {
            if let Some(rest) = key.strip_prefix("cargo/") {
                let parts: Vec<_> = rest.split('/').collect();
                if !parts.is_empty() {
                    let name = parts[0].to_string();
                    let entry = crates.entry(name).or_insert((0, 0, 0));
                    entry.0 += 1;

                    if let Some(meta) = storage.stat(key).await {
                        entry.1 += meta.size;
                        if meta.modified > entry.2 {
                            entry.2 = meta.modified;
                        }
                    }
                }
            }
        }
    }

    to_sorted_vec(crates)
}

async fn build_pypi_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("pypi/").await;
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("pypi/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let entry = packages.entry(name).or_insert((0, 0, 0));
                entry.0 += 1;

                if let Some(meta) = storage.stat(key).await {
                    entry.1 += meta.size;
                    if meta.modified > entry.2 {
                        entry.2 = meta.modified;
                    }
                }
            }
        }
    }

    to_sorted_vec(packages)
}

/// Convert HashMap to sorted Vec<RepoInfo>
fn to_sorted_vec(map: HashMap<String, (usize, u64, u64)>) -> Vec<RepoInfo> {
    let mut result: Vec<_> = map
        .into_iter()
        .map(|(name, (versions, size, modified))| RepoInfo {
            name,
            versions,
            size,
            updated: if modified > 0 {
                format_timestamp(modified)
            } else {
                "N/A".to_string()
            },
        })
        .collect();

    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Pagination helper
pub fn paginate<T: Clone>(data: &[T], page: usize, limit: usize) -> (Vec<T>, usize) {
    let total = data.len();
    let start = page.saturating_sub(1) * limit;

    if start >= total {
        return (Vec::new(), total);
    }

    let end = (start + limit).min(total);
    (data[start..end].to_vec(), total)
}
