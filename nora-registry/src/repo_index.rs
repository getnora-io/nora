// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! In-memory repository index with lazy rebuild on invalidation.
//!
//! Design:
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
    pub go: RegistryIndex,
    pub raw: RegistryIndex,
}

impl RepoIndex {
    pub fn new() -> Self {
        Self {
            docker: RegistryIndex::new(),
            maven: RegistryIndex::new(),
            npm: RegistryIndex::new(),
            cargo: RegistryIndex::new(),
            pypi: RegistryIndex::new(),
            go: RegistryIndex::new(),
            raw: RegistryIndex::new(),
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
            "go" => self.go.invalidate(),
            "raw" => self.raw.invalidate(),
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
            "go" => &self.go,
            "raw" => &self.raw,
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
                "go" => build_go_index(storage).await,
                "raw" => build_raw_index(storage).await,
                _ => Vec::new(),
            };
            info!(registry = registry, count = data.len(), "Index rebuilt");
            index.set(data);
        }

        index.get_cached()
    }

    /// Get counts for stats (no rebuild, just current state)
    pub fn counts(&self) -> (usize, usize, usize, usize, usize, usize, usize) {
        (
            self.docker.count(),
            self.maven.count(),
            self.npm.count(),
            self.cargo.count(),
            self.pypi.count(),
            self.go.count(),
            self.raw.count(),
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
            // Support both single-segment and namespaced images:
            // docker/alpine/manifests/latest.json → name="alpine"
            // docker/library/alpine/manifests/latest.json → name="library/alpine"
            let parts: Vec<_> = rest.split('/').collect();
            let manifest_pos = parts.iter().position(|&p| p == "manifests");
            if let Some(pos) = manifest_pos {
                if pos >= 1 && key.ends_with(".json") {
                    let name = parts[..pos].join("/");
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

    // Count tarballs instead of parsing metadata.json (faster than parsing JSON)
    for key in &keys {
        if let Some(rest) = key.strip_prefix("npm/") {
            // Pattern: npm/{package}/tarballs/{file}.tgz
            // Scoped:  npm/@scope/package/tarballs/{file}.tgz
            if rest.contains("/tarballs/") && key.ends_with(".tgz") {
                let parts: Vec<_> = rest.split('/').collect();
                if !parts.is_empty() {
                    // Scoped packages: @scope/package → parts[0]="@scope", parts[1]="package"
                    let name = if parts[0].starts_with('@') && parts.len() >= 4 {
                        format!("{}/{}", parts[0], parts[1])
                    } else {
                        parts[0].to_string()
                    };
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

async fn build_go_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("go/").await;
    let mut modules: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("go/") {
            // Pattern: go/{module}/@v/{version}.zip
            // Count .zip files as versions (authoritative artifacts)
            if rest.contains("/@v/") && key.ends_with(".zip") {
                // Extract module path: everything before /@v/
                if let Some(pos) = rest.rfind("/@v/") {
                    let module = &rest[..pos];
                    let entry = modules.entry(module.to_string()).or_insert((0, 0, 0));
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

    to_sorted_vec(modules)
}

async fn build_raw_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("raw/").await;
    let mut files: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("raw/") {
            // Group by top-level directory
            let group = rest.split('/').next().unwrap_or(rest).to_string();
            let entry = files.entry(group).or_insert((0, 0, 0));
            entry.0 += 1;
            if let Some(meta) = storage.stat(key).await {
                entry.1 += meta.size;
                if meta.modified > entry.2 {
                    entry.2 = meta.modified;
                }
            }
        }
    }

    to_sorted_vec(files)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginate_first_page() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let (page, total) = paginate(&data, 1, 3);
        assert_eq!(page, vec![1, 2, 3]);
        assert_eq!(total, 10);
    }

    #[test]
    fn test_paginate_second_page() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let (page, total) = paginate(&data, 2, 3);
        assert_eq!(page, vec![4, 5, 6]);
        assert_eq!(total, 10);
    }

    #[test]
    fn test_paginate_last_page_partial() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let (page, total) = paginate(&data, 4, 3);
        assert_eq!(page, vec![10]);
        assert_eq!(total, 10);
    }

    #[test]
    fn test_paginate_beyond_range() {
        let data = vec![1, 2, 3];
        let (page, total) = paginate(&data, 5, 3);
        assert!(page.is_empty());
        assert_eq!(total, 3);
    }

    #[test]
    fn test_paginate_empty_data() {
        let data: Vec<i32> = vec![];
        let (page, total) = paginate(&data, 1, 10);
        assert!(page.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn test_paginate_page_zero() {
        // page 0 with saturating_sub becomes 0, so start = 0
        let data = vec![1, 2, 3];
        let (page, _) = paginate(&data, 0, 2);
        assert_eq!(page, vec![1, 2]);
    }

    #[test]
    fn test_paginate_large_limit() {
        let data = vec![1, 2, 3];
        let (page, total) = paginate(&data, 1, 100);
        assert_eq!(page, vec![1, 2, 3]);
        assert_eq!(total, 3);
    }

    #[test]
    fn test_registry_index_new() {
        let idx = RegistryIndex::new();
        assert_eq!(idx.count(), 0);
        assert!(idx.is_dirty());
    }

    #[test]
    fn test_registry_index_invalidate() {
        let idx = RegistryIndex::new();
        // Initially dirty
        assert!(idx.is_dirty());

        // Set data clears dirty
        idx.set(vec![RepoInfo {
            name: "test".to_string(),
            versions: 1,
            size: 100,
            updated: "2026-01-01".to_string(),
        }]);
        assert!(!idx.is_dirty());
        assert_eq!(idx.count(), 1);

        // Invalidate makes it dirty again
        idx.invalidate();
        assert!(idx.is_dirty());
    }

    #[test]
    fn test_registry_index_get_cached() {
        let idx = RegistryIndex::new();
        idx.set(vec![
            RepoInfo {
                name: "a".to_string(),
                versions: 2,
                size: 200,
                updated: "today".to_string(),
            },
            RepoInfo {
                name: "b".to_string(),
                versions: 1,
                size: 100,
                updated: "yesterday".to_string(),
            },
        ]);

        let cached = idx.get_cached();
        assert_eq!(cached.len(), 2);
        assert_eq!(cached[0].name, "a");
    }

    #[test]
    fn test_registry_index_default() {
        let idx = RegistryIndex::default();
        assert_eq!(idx.count(), 0);
    }

    #[test]
    fn test_repo_index_new() {
        let idx = RepoIndex::new();
        let (d, m, n, c, p, g, r) = idx.counts();
        assert_eq!((d, m, n, c, p, g, r), (0, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_repo_index_invalidate() {
        let idx = RepoIndex::new();
        // Should not panic for any registry
        idx.invalidate("docker");
        idx.invalidate("maven");
        idx.invalidate("npm");
        idx.invalidate("cargo");
        idx.invalidate("pypi");
        idx.invalidate("raw");
        idx.invalidate("unknown"); // should be a no-op
    }

    #[test]
    fn test_repo_index_default() {
        let idx = RepoIndex::default();
        let (d, m, n, c, p, g, r) = idx.counts();
        assert_eq!((d, m, n, c, p, g, r), (0, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn test_to_sorted_vec() {
        let mut map = std::collections::HashMap::new();
        map.insert("zebra".to_string(), (3usize, 100u64, 0u64));
        map.insert("alpha".to_string(), (1, 50, 1700000000));

        let result = to_sorted_vec(map);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "alpha");
        assert_eq!(result[0].versions, 1);
        assert_eq!(result[0].size, 50);
        assert_ne!(result[0].updated, "N/A");
        assert_eq!(result[1].name, "zebra");
        assert_eq!(result[1].versions, 3);
        assert_eq!(result[1].updated, "N/A"); // modified = 0
    }
}
