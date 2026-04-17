//! Garbage Collection — orphan detection for all registries.
//!
//! Mark-and-sweep approach:
//! 1. Collect candidate keys (blobs, checksums) per registry
//! 2. Determine which are referenced by parent artifacts
//! 3. Unreferenced = orphans → delete (or dry-run report)
//!
//! Registry-specific strategies:
//! - **Docker**: blobs not referenced by any manifest (config/layers/manifests)
//! - **Maven/npm/PyPI**: checksum sidecar files (.md5/.sha1/.sha256/.sha512)
//!   without a corresponding primary artifact
//! - **Go**: incomplete versions (missing .info or .zip from the expected set)
//! - **Cargo**: cross-check between index entries and .crate files
//! - **Raw**: no orphan detection (no version/reference model)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};
use tracing::info;

use crate::storage::Storage;

// ============================================================================
// Prometheus metrics
// ============================================================================

lazy_static! {
    pub static ref GC_BLOBS_REMOVED: IntCounter = register_int_counter!(
        "nora_gc_blobs_removed_total",
        "Total orphaned blobs/files removed by GC"
    )
    .expect("gc_blobs_removed metric");
    pub static ref GC_BYTES_FREED: IntCounter =
        register_int_counter!("nora_gc_bytes_freed_total", "Total bytes freed by GC")
            .expect("gc_bytes_freed metric");
    pub static ref GC_DURATION: Histogram = register_histogram!(
        "nora_gc_duration_seconds",
        "Duration of GC runs in seconds",
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0]
    )
    .expect("gc_duration metric");
    pub static ref GC_LAST_RUN: IntGauge = register_int_gauge!(
        "nora_gc_last_run_timestamp",
        "Unix timestamp of last GC run"
    )
    .expect("gc_last_run metric");
}

// ============================================================================
// GC Result
// ============================================================================

pub struct GcResult {
    pub total_candidates: usize,
    pub orphaned: usize,
    pub deleted: usize,
    pub bytes_freed: u64,
    pub orphan_keys: Vec<String>,
    pub duration_secs: f64,
    /// Registries with data but no GC orphan detection (name, file_count)
    pub uncovered: Vec<(String, usize)>,
}

// ============================================================================
// Main GC entry point
// ============================================================================

pub async fn run_gc(storage: &Storage, dry_run: bool) -> GcResult {
    let start = Instant::now();
    info!("Starting garbage collection (dry_run={})", dry_run);

    let mut all_orphans: Vec<String> = Vec::new();
    let mut total_candidates = 0usize;

    // Docker orphan detection (existing logic)
    let docker_result = detect_docker_orphans(storage).await;
    total_candidates += docker_result.total;
    all_orphans.extend(docker_result.orphans);

    // Checksum orphan detection (Maven, npm, PyPI)
    let checksum_result = detect_checksum_orphans(storage).await;
    total_candidates += checksum_result.total;
    all_orphans.extend(checksum_result.orphans);

    // Go incomplete version detection
    let go_result = detect_go_incomplete_versions(storage).await;
    total_candidates += go_result.total;
    all_orphans.extend(go_result.orphans);

    // Cargo index/crate cross-check
    let cargo_result = detect_cargo_orphans(storage).await;
    total_candidates += cargo_result.total;
    all_orphans.extend(cargo_result.orphans);

    info!(
        "Found {} orphans out of {} candidates",
        all_orphans.len(),
        total_candidates
    );

    let mut deleted = 0usize;
    let mut bytes_freed = 0u64;

    if !dry_run {
        for key in &all_orphans {
            // Get size before deleting
            if let Some(meta) = storage.stat(key).await {
                bytes_freed += meta.size;
            }
            if storage.delete(key).await.is_ok() {
                deleted += 1;
                info!("Deleted: {}", key);
            }
        }
        info!("Deleted {} orphans, freed {} bytes", deleted, bytes_freed);

        // Update Prometheus metrics
        GC_BLOBS_REMOVED.inc_by(deleted as u64);
        GC_BYTES_FREED.inc_by(bytes_freed);
    } else {
        for key in &all_orphans {
            let size = storage.stat(key).await.map(|m| m.size).unwrap_or(0);
            bytes_freed += size;
            info!("[dry-run] Would delete: {} ({} bytes)", key, size);
        }
    }

    // Detect registries with data but no GC coverage
    // Raw has no version model and no reference graph — nothing to GC by design
    let mut uncovered = Vec::new();
    let count = storage.list("raw/").await.len();
    if count > 0 {
        uncovered.push(("raw".to_string(), count));
    }

    let duration = start.elapsed().as_secs_f64();
    GC_DURATION.observe(duration);
    GC_LAST_RUN.set(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    );

    GcResult {
        total_candidates,
        orphaned: all_orphans.len(),
        deleted,
        bytes_freed,
        orphan_keys: all_orphans,
        duration_secs: duration,
        uncovered,
    }
}

// ============================================================================
// Docker orphan detection
// ============================================================================

struct DetectionResult {
    total: usize,
    orphans: Vec<String>,
}

async fn detect_docker_orphans(storage: &Storage) -> DetectionResult {
    let keys = storage.list("docker/").await;

    let mut blobs: Vec<String> = Vec::new();
    let mut referenced = HashSet::new();

    for key in &keys {
        if key.contains("/blobs/") {
            blobs.push(key.clone());
        }
    }

    // Parse manifests for referenced digests
    for key in &keys {
        if !key.contains("/manifests/") || !key.ends_with(".json") || key.ends_with(".meta.json") {
            continue;
        }

        if let Ok(data) = storage.get(key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                // config digest
                if let Some(digest) = json
                    .get("config")
                    .and_then(|c| c.get("digest"))
                    .and_then(|v| v.as_str())
                {
                    referenced.insert(digest.to_string());
                }
                // layer digests
                if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
                    for layer in layers {
                        if let Some(digest) = layer.get("digest").and_then(|v| v.as_str()) {
                            referenced.insert(digest.to_string());
                        }
                    }
                }
                // manifest list digests
                if let Some(manifests) = json.get("manifests").and_then(|v| v.as_array()) {
                    for m in manifests {
                        if let Some(digest) = m.get("digest").and_then(|v| v.as_str()) {
                            referenced.insert(digest.to_string());
                        }
                    }
                }
            }
        }
    }

    let total = blobs.len();
    let orphans: Vec<String> = blobs
        .into_iter()
        .filter(|key| {
            key.rsplit('/')
                .next()
                .map(|digest| !referenced.contains(digest))
                .unwrap_or(false)
        })
        .collect();

    DetectionResult { total, orphans }
}

// ============================================================================
// Checksum orphan detection (Maven, npm, PyPI)
// ============================================================================

const CHECKSUM_EXTENSIONS: &[&str] = &[".md5", ".sha1", ".sha256", ".sha512"];

fn is_checksum_sidecar(key: &str) -> bool {
    CHECKSUM_EXTENSIONS.iter().any(|ext| key.ends_with(ext))
}

fn primary_key_for_checksum(key: &str) -> Option<&str> {
    for ext in CHECKSUM_EXTENSIONS {
        if let Some(primary) = key.strip_suffix(ext) {
            return Some(primary);
        }
    }
    None
}

async fn detect_checksum_orphans(storage: &Storage) -> DetectionResult {
    let mut checksums: Vec<String> = Vec::new();

    // Scan Maven, npm, PyPI prefixes for checksum sidecar files
    for prefix in &["maven/", "npm/", "pypi/"] {
        let keys = storage.list(prefix).await;
        for key in keys {
            if is_checksum_sidecar(&key) {
                checksums.push(key);
            }
        }
    }

    let total = checksums.len();
    let mut orphans = Vec::new();

    for checksum_key in &checksums {
        if let Some(primary) = primary_key_for_checksum(checksum_key) {
            // If the primary artifact doesn't exist, the checksum is orphaned
            if storage.stat(primary).await.is_none() {
                orphans.push(checksum_key.clone());
            }
        }
    }

    DetectionResult { total, orphans }
}

// ============================================================================
// Go incomplete version detection
// ============================================================================

/// Go modules store 3 files per version: .info, .mod, .zip
/// If any file is missing, the remaining files are orphaned (partial upload or failed delete).
async fn detect_go_incomplete_versions(storage: &Storage) -> DetectionResult {
    let keys = storage.list("go/").await;
    let mut versions: HashMap<String, Vec<String>> = HashMap::new();

    for key in &keys {
        // Pattern: go/{module}/@v/{version}.{info|mod|zip}
        if let Some(at_v_pos) = key.find("/@v/") {
            let file = &key[at_v_pos + 4..];
            let version_base = file
                .strip_suffix(".info")
                .or_else(|| file.strip_suffix(".mod"))
                .or_else(|| file.strip_suffix(".zip"));
            if let Some(ver) = version_base {
                let version_key = format!("{}/@v/{}", &key[..at_v_pos], ver);
                versions.entry(version_key).or_default().push(key.clone());
            }
        }
    }

    let total = versions.values().map(|v| v.len()).sum();
    let mut orphans = Vec::new();
    for (version_key, files) in &versions {
        // A complete version has at least .info and .zip (.mod is optional for some modules)
        let has_info = files.iter().any(|f| f.ends_with(".info"));
        let has_zip = files.iter().any(|f| f.ends_with(".zip"));
        if !has_info || !has_zip {
            info!("Go incomplete version: {} (has {} of 3 expected files)", version_key, files.len());
            orphans.extend(files.clone());
        }
    }

    DetectionResult { total, orphans }
}

// ============================================================================
// Cargo index/crate cross-check
// ============================================================================

/// Cargo stores .crate files and index entries separately.
/// Orphan = index entry without .crate file, or .crate without index entry.
async fn detect_cargo_orphans(storage: &Storage) -> DetectionResult {
    let keys = storage.list("cargo/").await;
    let mut crate_files: HashSet<String> = HashSet::new(); // "name/version"
    let mut index_entries: HashSet<String> = HashSet::new(); // "name"
    let mut crate_keys: Vec<String> = Vec::new();
    let mut index_keys: Vec<String> = Vec::new();

    for key in &keys {
        if key.starts_with("cargo/index/") {
            // cargo/index/XX/XX/name
            if let Some(name) = key.strip_prefix("cargo/index/").and_then(|s| s.split('/').nth(2)) {
                index_entries.insert(name.to_string());
                index_keys.push(key.clone());
            }
        } else if key.ends_with(".crate") {
            // cargo/name/version/name-version.crate
            let parts: Vec<&str> = key.strip_prefix("cargo/").unwrap_or(key).split('/').collect();
            if parts.len() >= 2 {
                crate_files.insert(parts[0].to_string());
                crate_keys.push(key.clone());
            }
        }
    }

    let total = crate_keys.len() + index_keys.len();
    let mut orphans = Vec::new();

    // Index entries without any .crate files
    for key in &index_keys {
        if let Some(name) = key.strip_prefix("cargo/index/").and_then(|s| s.split('/').nth(2)) {
            if !crate_files.contains(name) {
                info!("Cargo orphan index: {} (no .crate files)", key);
                orphans.push(key.clone());
            }
        }
    }

    // .crate files without index entry
    for key in &crate_keys {
        let parts: Vec<&str> = key.strip_prefix("cargo/").unwrap_or(key).split('/').collect();
        if parts.len() >= 2 && !index_entries.contains(parts[0]) {
            info!("Cargo orphan crate: {} (no index entry)", key);
            orphans.push(key.clone());
        }
    }

    DetectionResult { total, orphans }
}

// ============================================================================
// Background scheduler
// ============================================================================

/// Spawn a background GC task that runs periodically.
/// Uses a tokio::sync::Mutex as single-flight lock to prevent overlapping runs.
pub fn spawn_gc_scheduler(storage: Storage, interval_secs: u64, dry_run: bool) {
    let lock = Arc::new(tokio::sync::Mutex::new(()));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // First tick fires immediately — skip it so GC doesn't run on startup
        interval.tick().await;

        loop {
            interval.tick().await;

            // Single-flight: skip if previous run is still going
            let guard = lock.try_lock();
            if guard.is_err() {
                info!("GC: previous run still active, skipping");
                continue;
            }

            info!("GC scheduler: starting periodic run");
            let result = run_gc(&storage, dry_run).await;
            info!(
                "GC scheduler: done in {:.1}s — {} orphans, {} deleted, {} bytes freed",
                result.duration_secs, result.orphaned, result.deleted, result.bytes_freed
            );

            drop(guard);
        }
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_result_defaults() {
        let result = GcResult {
            total_candidates: 0,
            orphaned: 0,
            deleted: 0,
            bytes_freed: 0,
            orphan_keys: vec![],
            duration_secs: 0.0,
            uncovered: vec![],
        };
        assert_eq!(result.total_candidates, 0);
        assert!(result.orphan_keys.is_empty());
    }

    #[test]
    fn test_is_checksum_sidecar() {
        assert!(is_checksum_sidecar("foo.md5"));
        assert!(is_checksum_sidecar("foo.sha1"));
        assert!(is_checksum_sidecar("foo.sha256"));
        assert!(is_checksum_sidecar("foo.sha512"));
        assert!(!is_checksum_sidecar("foo.jar"));
        assert!(!is_checksum_sidecar("foo.pom"));
        assert!(!is_checksum_sidecar("foo.tgz"));
    }

    #[test]
    fn test_primary_key_for_checksum() {
        assert_eq!(primary_key_for_checksum("a.jar.sha256"), Some("a.jar"));
        assert_eq!(primary_key_for_checksum("a.pom.md5"), Some("a.pom"));
        assert_eq!(primary_key_for_checksum("a.tgz.sha1"), Some("a.tgz"));
        assert_eq!(primary_key_for_checksum("a.jar"), None);
    }

    // -- Docker GC tests --

    #[tokio::test]
    async fn test_gc_empty_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = run_gc(&storage, true).await;
        assert_eq!(result.total_candidates, 0);
        assert_eq!(result.orphaned, 0);
        assert_eq!(result.deleted, 0);
    }

    #[tokio::test]
    async fn test_gc_docker_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest = serde_json::json!({
            "config": {"digest": "sha256:configabc"},
            "layers": [{"digest": "sha256:layer111", "size": 100}]
        });
        storage
            .put(
                "docker/test/manifests/latest.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:configabc", b"config-data")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:layer111", b"layer-data")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 0);
    }

    #[tokio::test]
    async fn test_gc_docker_finds_orphans_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest = serde_json::json!({
            "config": {"digest": "sha256:configabc"},
            "layers": [{"digest": "sha256:layer111", "size": 100}]
        });
        storage
            .put(
                "docker/test/manifests/latest.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:configabc", b"config-data")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:layer111", b"layer-data")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:orphan999", b"orphan-data")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 1);
        assert_eq!(result.deleted, 0);
        assert!(result.orphan_keys[0].contains("orphan999"));
        // Orphan still exists (dry run)
        assert!(storage
            .get("docker/test/blobs/sha256:orphan999")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_docker_deletes_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest = serde_json::json!({
            "config": {"digest": "sha256:configabc"},
            "layers": []
        });
        storage
            .put(
                "docker/test/manifests/latest.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:configabc", b"config")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:orphan1", b"orphan")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.orphaned, 1);
        assert_eq!(result.deleted, 1);
        assert!(result.bytes_freed > 0);
        assert!(storage
            .get("docker/test/blobs/sha256:orphan1")
            .await
            .is_err());
        assert!(storage
            .get("docker/test/blobs/sha256:configabc")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_manifest_list_references() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest = serde_json::json!({
            "manifests": [
                {"digest": "sha256:platformA", "size": 100},
                {"digest": "sha256:platformB", "size": 200}
            ]
        });
        storage
            .put(
                "docker/multi/manifests/latest.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:platformA", b"arch-a")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:platformB", b"arch-b")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 0);
    }

    #[tokio::test]
    async fn test_gc_scans_all_registries() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Cargo: crate without index = orphan
        storage
            .put("cargo/serde/1.0.0/serde-1.0.0.crate", b"crate-data")
            .await
            .unwrap();
        // Go: only .zip without .info = incomplete version
        storage
            .put("go/cache/download/mod/@v/v1.0.0.zip", b"zip")
            .await
            .unwrap();
        // Raw: no GC coverage
        storage.put("raw/some-file.txt", b"raw-data").await.unwrap();

        let result = run_gc(&storage, true).await;
        // Cargo crate without index entry = 1 orphan
        // Go .zip without .info = 1 orphan (incomplete version)
        assert_eq!(result.orphaned, 2);
        // Only raw remains uncovered
        assert_eq!(result.uncovered.len(), 1);
        assert_eq!(result.uncovered[0].0, "raw");
    }

    // -- Checksum orphan tests --

    #[tokio::test]
    async fn test_gc_go_complete_version_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage.put("go/example.com/mod/@v/v1.0.0.info", b"{}").await.unwrap();
        storage.put("go/example.com/mod/@v/v1.0.0.mod", b"module").await.unwrap();
        storage.put("go/example.com/mod/@v/v1.0.0.zip", b"zip").await.unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 0, "complete Go version should have no orphans");
    }

    #[tokio::test]
    async fn test_gc_go_incomplete_version() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Only .mod — missing .info and .zip
        storage.put("go/example.com/mod/@v/v1.0.0.mod", b"module").await.unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 1);
        assert!(result.orphan_keys[0].ends_with(".mod"));
    }

    #[tokio::test]
    async fn test_gc_cargo_matching_index_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage.put("cargo/serde/1.0.0/serde-1.0.0.crate", b"crate").await.unwrap();
        storage.put("cargo/index/se/rd/serde", b"index-data").await.unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 0, "cargo with matching index should have no orphans");
    }

    #[tokio::test]
    async fn test_gc_cargo_orphan_index_without_crate() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Index entry but no .crate file
        storage.put("cargo/index/se/rd/serde", b"index-data").await.unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.orphaned, 1);
        assert!(result.orphan_keys[0].contains("index"));
    }

    // -- Checksum orphan tests --

    #[tokio::test]
    async fn test_gc_maven_checksum_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Primary artifact exists with its checksums
        storage
            .put("maven/com/example/1.0/lib.jar", b"jar-data")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/lib.jar.sha256", b"abc123")
            .await
            .unwrap();
        // Orphan checksum — primary artifact was deleted
        storage
            .put("maven/com/example/1.0/old.jar.sha256", b"dead")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/old.jar.md5", b"dead")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.orphaned, 2);
        assert_eq!(result.deleted, 2);
        // Non-orphan checksum still exists
        assert!(storage
            .get("maven/com/example/1.0/lib.jar.sha256")
            .await
            .is_ok());
        // Primary artifact untouched
        assert!(storage.get("maven/com/example/1.0/lib.jar").await.is_ok());
    }

    #[tokio::test]
    async fn test_gc_npm_checksum_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", b"tarball")
            .await
            .unwrap();
        storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz.sha256", b"hash")
            .await
            .unwrap();
        // Orphan: tarball deleted but hash remains
        storage
            .put("npm/lodash/tarballs/lodash-3.0.0.tgz.sha256", b"old-hash")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.orphaned, 1);
        assert_eq!(result.deleted, 1);
        assert!(storage
            .get("npm/lodash/tarballs/lodash-4.17.21.tgz.sha256")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_pypi_checksum_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("pypi/flask/flask-2.0.tar.gz", b"package")
            .await
            .unwrap();
        storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"hash")
            .await
            .unwrap();
        // Orphan
        storage
            .put("pypi/flask/flask-1.0.tar.gz.sha256", b"old-hash")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.orphaned, 1);
        assert_eq!(result.deleted, 1);
    }

    #[tokio::test]
    async fn test_gc_mixed_docker_and_checksum_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Docker: 1 referenced blob + 1 orphan
        let manifest = serde_json::json!({
            "config": {"digest": "sha256:config1"},
            "layers": []
        });
        storage
            .put(
                "docker/app/manifests/v1.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/app/blobs/sha256:config1", b"config")
            .await
            .unwrap();
        storage
            .put("docker/app/blobs/sha256:stale-blob", b"stale")
            .await
            .unwrap();

        // Maven: 1 orphan checksum
        storage
            .put("maven/com/test/1.0/lib.jar.sha1", b"orphan-hash")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.orphaned, 2); // 1 docker blob + 1 maven checksum
        assert_eq!(result.deleted, 2);
    }

    #[tokio::test]
    async fn test_gc_no_checksum_orphans_when_all_valid() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("maven/com/example/1.0/lib.jar", b"data")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/lib.jar.md5", b"hash")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/lib.jar.sha1", b"hash")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/lib.jar.sha256", b"hash")
            .await
            .unwrap();
        storage
            .put("maven/com/example/1.0/lib.jar.sha512", b"hash")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        // 4 checksums scanned, 0 orphans
        assert_eq!(result.total_candidates, 4);
        assert_eq!(result.orphaned, 0);
    }

    #[tokio::test]
    async fn test_gc_bytes_freed_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest = serde_json::json!({"config": {"digest": "sha256:cfg"}, "layers": []});
        storage
            .put(
                "docker/x/manifests/v1.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/x/blobs/sha256:cfg", b"c")
            .await
            .unwrap();
        storage
            .put("docker/x/blobs/sha256:dead", b"12345")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.deleted, 1);
        assert_eq!(result.bytes_freed, 5); // "12345" = 5 bytes
    }
}
