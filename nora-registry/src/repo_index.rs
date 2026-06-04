// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! In-memory repository index with lazy rebuild on invalidation.
//!
//! Design:
//! - Rebuild happens ONLY on write operations, not TTL
//! - Double-checked locking prevents duplicate rebuilds
//! - Arc<Vec> for zero-cost reads
//! - Single rebuild at a time per registry (rebuild_lock)

use crate::registry_type::RegistryType;
use crate::storage::Storage;
use crate::ui::components::format_timestamp;
use crate::validation::ends_with_ci;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

/// Repository info for UI display
#[derive(Debug, Clone, Serialize, Default)]
pub struct RepoInfo {
    pub name: String,
    pub versions: usize,
    pub size: u64,
    pub updated: String,
    /// True for root-level files in raw storage (not directories)
    #[serde(default)]
    pub is_file: bool,
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

    /// Sum of artifact bytes in this registry's cached index (no rebuild).
    pub fn total_size(&self) -> u64 {
        self.data.read().iter().map(|r| r.size).sum()
    }
}

impl Default for RegistryIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Main repository index for all registries
pub struct RepoIndex {
    indexes: HashMap<RegistryType, RegistryIndex>,
}

impl RepoIndex {
    pub fn new() -> Self {
        let mut indexes = HashMap::new();
        for rt in RegistryType::all() {
            indexes.insert(*rt, RegistryIndex::new());
        }
        Self { indexes }
    }

    /// Invalidate a specific registry index
    pub fn invalidate(&self, registry: &str) {
        if let Some(rt) = RegistryType::from_str_opt(registry) {
            if let Some(idx) = self.indexes.get(&rt) {
                idx.invalidate();
            }
        }
    }

    /// Get index with double-checked locking (prevents race condition)
    pub async fn get(&self, registry: &str, storage: &Storage) -> Arc<Vec<RepoInfo>> {
        let reg_type = match RegistryType::from_str_opt(registry) {
            Some(rt) => rt,
            None => return Arc::new(Vec::new()),
        };
        let index = match self.indexes.get(&reg_type) {
            Some(idx) => idx,
            None => return Arc::new(Vec::new()),
        };

        // Fast path: not dirty, return cached
        if !index.is_dirty() {
            return index.get_cached();
        }

        // Slow path: acquire rebuild lock (only one thread rebuilds)
        let _guard = index.rebuild_lock.lock().await;

        // Double-check under lock (another thread may have rebuilt)
        if index.is_dirty() {
            let data = match reg_type {
                RegistryType::Docker => build_docker_index(storage).await,
                RegistryType::Maven => build_maven_index(storage).await,
                RegistryType::Npm => build_npm_index(storage).await,
                RegistryType::Cargo => build_cargo_index(storage).await,
                RegistryType::PyPI => build_pypi_index(storage).await,
                RegistryType::Go => build_go_index(storage).await,
                RegistryType::Raw => build_raw_index(storage).await,
                RegistryType::Nuget => {
                    let (p, s) = crate::registry::nuget::INDEX_PATTERN;
                    build_generic_index(storage, p, s).await
                }
                RegistryType::Gems => build_gems_index(storage).await,
                RegistryType::Terraform => {
                    let (p, s) = crate::registry::terraform::INDEX_PATTERN;
                    build_generic_index(storage, p, s).await
                }
                RegistryType::Ansible => {
                    let (p, s) = crate::registry::ansible::INDEX_PATTERN;
                    build_generic_index(storage, p, s).await
                }
                RegistryType::PubDart => {
                    let (p, s) = crate::registry::pub_dart::INDEX_PATTERN;
                    build_generic_index(storage, p, s).await
                }
                RegistryType::Conan => build_conan_index(storage).await,
            };
            info!(registry = registry, count = data.len(), "Index rebuilt");
            index.set(data);
        }

        index.get_cached()
    }

    /// Get counts for stats (no rebuild, just current state)
    pub fn counts(&self) -> HashMap<RegistryType, usize> {
        self.indexes
            .iter()
            .map(|(rt, idx)| (*rt, idx.count()))
            .collect()
    }

    /// Get total artifact bytes per registry from the cached index (no rebuild).
    pub fn sizes(&self) -> HashMap<RegistryType, u64> {
        self.indexes
            .iter()
            .map(|(rt, idx)| (*rt, idx.total_size()))
            .collect()
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
    let keys = storage.list("docker/").await.unwrap_or_default();
    let mut repos: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if ends_with_ci(key, ".meta.json") {
            continue;
        }

        if let Some(rest) = key.strip_prefix("docker/") {
            // Support both single-segment and namespaced images:
            // docker/alpine/manifests/latest.json → name="alpine"
            // docker/library/alpine/blobs/sha256:... → name="library/alpine"
            let parts: Vec<_> = rest.split('/').collect();
            // Repo name = everything before the "manifests"/"blobs" segment.
            let Some(boundary) = parts.iter().position(|&p| p == "manifests" || p == "blobs")
            else {
                continue;
            };
            if boundary < 1 {
                continue;
            }
            let raw_name = parts[..boundary].join("/");
            let name = crate::registry::docker::strip_docker_namespace(&raw_name).to_string();
            let entry = repos.entry(name).or_insert((0, 0, 0));

            // Size = ACTUAL on-disk bytes of every file in the repo (blobs +
            // manifests), each counted once. The old code summed the manifest's
            // declared config+layer sizes — a "virtual" size that multi-counts
            // layers shared across tags and ignores real storage, so a 7.2G
            // image tree could be reported as something else entirely (#588).
            if let Some(meta) = storage.stat(key).await {
                entry.1 += meta.size;
                if meta.modified > entry.2 {
                    entry.2 = meta.modified;
                }
            }

            // Count = number of distinct tags. Each push writes BOTH a
            // tag manifest (`manifests/<tag>.json`) and a content-addressed
            // `manifests/sha256:<digest>.json`; counting both double-counted
            // every image (#588). Count only the tag form.
            if parts[boundary] == "manifests" && ends_with_ci(key, ".json") {
                if let Some(reference) = parts.get(boundary + 1) {
                    let reference = reference.trim_end_matches(".json");
                    if !reference.starts_with("sha256:") {
                        entry.0 += 1;
                    }
                }
            }
        }
    }

    to_sorted_vec(repos)
}

async fn build_maven_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("maven/").await.unwrap_or_default();
    let mut repos: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("maven/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 2 {
                let path = parts[..parts.len() - 1].join("/");
                let entry = repos.entry(path).or_insert((0, 0, 0));
                // A Maven artifact ships with a swarm of sidecars — `.sha1`,
                // `.md5`, `.sha256`, `.sha512` and `maven-metadata.xml` — none
                // of which are separate artifacts. Count only primary files so
                // the dashboard doesn't report 5× the real artifact count
                // (#588). Sidecar bytes still count toward size (= on-disk du).
                let is_metadata = key.ends_with("maven-metadata.xml");
                if !crate::gc::is_checksum_sidecar(key) && !is_metadata {
                    entry.0 += 1;
                }

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
    let keys = storage.list("npm/").await.unwrap_or_default();
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    // Count tarballs instead of parsing metadata.json (faster than parsing JSON)
    for key in &keys {
        if let Some(rest) = key.strip_prefix("npm/") {
            // Pattern: npm/{package}/tarballs/{file}.tgz
            // Scoped:  npm/@scope/package/tarballs/{file}.tgz
            if rest.contains("/tarballs/") && ends_with_ci(key, ".tgz") {
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
    let keys = storage.list("cargo/").await.unwrap_or_default();
    let mut crates: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if ends_with_ci(key, ".crate") {
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
    let keys = storage.list("pypi/").await.unwrap_or_default();
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("pypi/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let entry = packages.entry(name).or_insert((0, 0, 0));
                // Count only real distribution files — a checksum sidecar
                // (`<file>.sha256`) is not a separate artifact (#588). Its bytes
                // still count toward size so the total matches on-disk du.
                if !crate::gc::is_checksum_sidecar(key) {
                    entry.0 += 1;
                }

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
    let keys = storage.list("go/").await.unwrap_or_default();
    let mut modules: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("go/") {
            // Pattern: go/{module}/@v/{version}.zip
            // Count .zip files as versions (authoritative artifacts)
            if rest.contains("/@v/") && ends_with_ci(key, ".zip") {
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
    let keys = storage.list("raw/").await.unwrap_or_default();
    // (count, size, modified, is_file)
    let mut groups: HashMap<String, (usize, u64, u64, bool)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("raw/") {
            let is_root_file = !rest.contains('/');
            let group = rest.split('/').next().unwrap_or(rest).to_string();
            let entry = groups.entry(group).or_insert((0, 0, 0, is_root_file));
            entry.0 += 1;
            if let Some(meta) = storage.stat(key).await {
                entry.1 += meta.size;
                if meta.modified > entry.2 {
                    entry.2 = meta.modified;
                }
            }
        }
    }

    let mut result: Vec<_> = groups
        .into_iter()
        .map(|(name, (versions, size, modified, is_file))| RepoInfo {
            name,
            versions,
            size,
            updated: if modified > 0 {
                format_timestamp(modified)
            } else {
                "N/A".to_string()
            },
            is_file,
        })
        .collect();

    // Directories first (alphabetical), then files (alphabetical)
    result.sort_by(|a, b| a.is_file.cmp(&b.is_file).then_with(|| a.name.cmp(&b.name)));
    result
}

/// Generic index builder: groups files under `prefix` by first path segment.
/// Only counts files matching `suffix` (e.g. ".gem", ".nupkg", ".tar.gz").
async fn build_generic_index(storage: &Storage, prefix: &str, suffix: &str) -> Vec<RepoInfo> {
    let keys = storage.list(prefix).await.unwrap_or_default();
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if !key.ends_with(suffix) {
            continue;
        }
        if let Some(rest) = key.strip_prefix(prefix) {
            let name = rest.split('/').next().unwrap_or(rest).to_string();
            if name.is_empty() {
                continue;
            }
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

    to_sorted_vec(packages)
}

/// Gems index: keys like gems/gems/{name}-{version}.gem
/// Uses split_gem_filename to extract package name from flat file layout.
async fn build_gems_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("gems/gems/").await.unwrap_or_default();
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if !key.ends_with(".gem") {
            continue;
        }
        if let Some(rest) = key.strip_prefix("gems/gems/") {
            let stem = rest.strip_suffix(".gem").unwrap_or(rest);
            let name = match crate::registry::gems::split_gem_filename(stem) {
                Some((n, _)) => n,
                None => stem.to_string(),
            };
            if name.is_empty() {
                continue;
            }
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

    to_sorted_vec(packages)
}

/// Conan index: keys like conan/{name}/{ver}/{user}/{chan}/revisions/{rev}/files/{file}
async fn build_conan_index(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("conan/").await.unwrap_or_default();
    let mut packages: HashMap<String, (usize, u64, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("conan/") {
            // First segment is the package name
            let name = rest.split('/').next().unwrap_or(rest).to_string();
            if name.is_empty() {
                continue;
            }
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
            is_file: false,
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
            ..Default::default()
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
                ..Default::default()
            },
            RepoInfo {
                name: "b".to_string(),
                versions: 1,
                size: 100,
                updated: "yesterday".to_string(),
                ..Default::default()
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
        let counts = idx.counts();
        for rt in RegistryType::all() {
            assert_eq!(
                counts.get(rt).copied().unwrap_or(0),
                0,
                "non-zero for {}",
                rt
            );
        }
    }

    #[test]
    fn test_repo_index_invalidate() {
        let idx = RepoIndex::new();
        // Should not panic for any registry (all 13 + unknown)
        for rt in RegistryType::all() {
            idx.invalidate(rt.as_str());
        }
        idx.invalidate("unknown"); // should be a no-op
    }

    #[test]
    fn test_repo_index_default() {
        let idx = RepoIndex::default();
        let counts = idx.counts();
        for rt in RegistryType::all() {
            assert_eq!(
                counts.get(rt).copied().unwrap_or(0),
                0,
                "non-zero for {}",
                rt
            );
        }
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

    // ── #588: dashboard stats must reflect real on-disk data ──────────────
    // count = primary artifacts only (no checksum sidecars / metadata / digest
    // manifests); size = actual on-disk bytes (du), never a manifest "virtual"
    // size. Seed a Storage and exercise the real build_*_index path (PM-4).

    fn temp_storage() -> (tempfile::TempDir, crate::Storage) {
        let dir = tempfile::TempDir::new().unwrap();
        let s = crate::Storage::new_local(dir.path().to_str().unwrap());
        (dir, s)
    }

    #[tokio::test]
    async fn pypi_index_excludes_checksum_sidecars_from_count() {
        let (_d, s) = temp_storage();
        s.put("pypi/six/six-1.16.0-py3-none-any.whl", &[0u8; 100])
            .await
            .unwrap();
        s.put("pypi/six/six-1.16.0-py3-none-any.whl.sha256", b"deadbeef")
            .await
            .unwrap();

        let repos = build_pypi_index(&s).await;
        assert_eq!(repos.len(), 1);
        // ONE artifact, not two — the .sha256 sidecar is not an artifact (#588).
        assert_eq!(repos[0].versions, 1, "checksum sidecar must not be counted");
        // ...but its bytes still count toward size, so size == on-disk du.
        assert_eq!(repos[0].size, 100 + 8);
    }

    #[tokio::test]
    async fn maven_index_counts_only_primary_artifacts() {
        let (_d, s) = temp_storage();
        let base = "maven/com/example/app/1.0";
        s.put(&format!("{base}/app-1.0.jar"), &[0u8; 200])
            .await
            .unwrap();
        s.put(&format!("{base}/app-1.0.pom"), &[0u8; 50])
            .await
            .unwrap();
        for ext in ["jar.sha1", "jar.md5", "jar.sha256", "jar.sha512"] {
            s.put(&format!("{base}/app-1.0.{ext}"), b"x").await.unwrap();
        }
        s.put(&format!("{base}/maven-metadata.xml"), &[0u8; 30])
            .await
            .unwrap();

        let repos = build_maven_index(&s).await;
        let total: usize = repos.iter().map(|r| r.versions).sum();
        // jar + pom = 2 primary; the 4 checksums + metadata.xml are NOT counted
        // (old code reported 7) (#588).
        assert_eq!(total, 2, "only primary artifacts counted, got {total}");
        // size still sums every file on disk (du).
        let size: u64 = repos.iter().map(|r| r.size).sum();
        assert_eq!(size, 200 + 50 + 4 + 30);
    }

    #[tokio::test]
    async fn docker_index_real_size_not_virtual_and_single_count() {
        let (_d, s) = temp_storage();
        // Manifest DECLARES huge layer sizes (virtual) but the actual blob
        // files on disk are tiny — the index must report the on-disk size.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "size": 1_000_000, "digest": "sha256:cfg" },
            "layers": [ { "size": 9_000_000, "digest": "sha256:lyr" } ]
        })
        .to_string();
        // Same image pushed by tag AND its content-addressed digest manifest.
        s.put(
            "docker/library/app/manifests/latest.json",
            manifest.as_bytes(),
        )
        .await
        .unwrap();
        s.put(
            "docker/library/app/manifests/sha256:abc123.json",
            manifest.as_bytes(),
        )
        .await
        .unwrap();
        // Real blobs on disk (tiny).
        s.put("docker/library/app/blobs/sha256:cfg", &[0u8; 120])
            .await
            .unwrap();
        s.put("docker/library/app/blobs/sha256:lyr", &[0u8; 340])
            .await
            .unwrap();

        let repos = build_docker_index(&s).await;
        assert_eq!(repos.len(), 1);
        // Count = 1 tag, NOT 2 (the digest manifest is not a separate image).
        assert_eq!(repos[0].versions, 1, "tag + digest manifest double-counted");
        // Size = actual on-disk bytes (2 manifests + 2 blobs), NOT the
        // declared 10_000_000 virtual size.
        let on_disk = (manifest.len() as u64) * 2 + 120 + 340;
        assert_eq!(
            repos[0].size, on_disk,
            "size must be on-disk du, not virtual"
        );
        assert!(repos[0].size < 10_000_000, "must not report virtual size");
    }
}
