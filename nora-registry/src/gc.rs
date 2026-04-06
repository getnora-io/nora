//! Garbage Collection for orphaned Docker blobs
//!
//! Mark-and-sweep approach:
//! 1. List all Docker blobs
//! 2. Parse Docker manifests to find referenced blobs
//! 3. Blobs not referenced by any manifest = orphans
//! 4. Delete orphans (with --dry-run support)
//!
//! Currently Docker-only. Other registries (npm, maven, cargo, pypi, go,
//! raw) are excluded because no reference resolver exists for their
//! metadata formats.

use std::collections::HashSet;

use tracing::info;

use crate::storage::Storage;

pub struct GcResult {
    pub total_blobs: usize,
    pub referenced_blobs: usize,
    pub orphaned_blobs: usize,
    pub deleted_blobs: usize,
    pub orphan_keys: Vec<String>,
}

pub async fn run_gc(storage: &Storage, dry_run: bool) -> GcResult {
    info!("Starting garbage collection (dry_run={})", dry_run);

    // 1. Collect all blob keys
    let all_blobs = collect_all_blobs(storage).await;
    info!("Found {} total blobs", all_blobs.len());

    // 2. Collect all referenced digests from manifests
    let referenced = collect_referenced_digests(storage).await;
    info!(
        "Found {} referenced digests from manifests",
        referenced.len()
    );

    // 3. Find orphans
    let mut orphan_keys: Vec<String> = Vec::new();
    for key in &all_blobs {
        if let Some(digest) = key.rsplit('/').next() {
            if !referenced.contains(digest) {
                orphan_keys.push(key.clone());
            }
        }
    }

    info!("Found {} orphaned blobs", orphan_keys.len());

    let mut deleted = 0;
    if !dry_run {
        for key in &orphan_keys {
            if storage.delete(key).await.is_ok() {
                deleted += 1;
                info!("Deleted: {}", key);
            }
        }
        info!("Deleted {} orphaned blobs", deleted);
    } else {
        for key in &orphan_keys {
            info!("[dry-run] Would delete: {}", key);
        }
    }

    GcResult {
        total_blobs: all_blobs.len(),
        referenced_blobs: referenced.len(),
        orphaned_blobs: orphan_keys.len(),
        deleted_blobs: deleted,
        orphan_keys,
    }
}

async fn collect_all_blobs(storage: &Storage) -> Vec<String> {
    let mut blobs = Vec::new();
    // Only collect Docker blobs. Other registries (npm, maven, cargo, pypi,
    // go, raw) use storage key schemes that collect_referenced_digests does
    // not understand, so their artifacts would appear as orphans and be
    // deleted. Extending GC to non-Docker registries requires per-registry
    // reference resolution.
    let keys = storage.list("docker/").await;
    for key in keys {
        if key.contains("/blobs/") {
            blobs.push(key);
        }
    }
    blobs
}

async fn collect_referenced_digests(storage: &Storage) -> HashSet<String> {
    let mut referenced = HashSet::new();

    let all_keys = storage.list("docker/").await;
    for key in &all_keys {
        if !key.contains("/manifests/") || !key.ends_with(".json") || key.ends_with(".meta.json") {
            continue;
        }

        if let Ok(data) = storage.get(key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(config) = json.get("config") {
                    if let Some(digest) = config.get("digest").and_then(|v| v.as_str()) {
                        referenced.insert(digest.to_string());
                    }
                }

                if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
                    for layer in layers {
                        if let Some(digest) = layer.get("digest").and_then(|v| v.as_str()) {
                            referenced.insert(digest.to_string());
                        }
                    }
                }

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

    referenced
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_result_defaults() {
        let result = GcResult {
            total_blobs: 0,
            referenced_blobs: 0,
            orphaned_blobs: 0,
            deleted_blobs: 0,
            orphan_keys: vec![],
        };
        assert_eq!(result.total_blobs, 0);
        assert!(result.orphan_keys.is_empty());
    }

    #[tokio::test]
    async fn test_gc_empty_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = run_gc(&storage, true).await;
        assert_eq!(result.total_blobs, 0);
        assert_eq!(result.referenced_blobs, 0);
        assert_eq!(result.orphaned_blobs, 0);
        assert_eq!(result.deleted_blobs, 0);
    }

    #[tokio::test]
    async fn test_gc_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Create a manifest that references a blob
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
        assert_eq!(result.total_blobs, 2);
        assert_eq!(result.orphaned_blobs, 0);
    }

    #[tokio::test]
    async fn test_gc_finds_orphans_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Create a manifest referencing only one blob
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
        // Orphan blob (not referenced)
        storage
            .put("docker/test/blobs/sha256:orphan999", b"orphan-data")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.total_blobs, 3);
        assert_eq!(result.orphaned_blobs, 1);
        assert_eq!(result.deleted_blobs, 0); // dry run
        assert!(result.orphan_keys[0].contains("orphan999"));

        // Verify orphan still exists (dry run)
        assert!(storage
            .get("docker/test/blobs/sha256:orphan999")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_deletes_orphans() {
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
        assert_eq!(result.orphaned_blobs, 1);
        assert_eq!(result.deleted_blobs, 1);

        // Verify orphan is gone
        assert!(storage
            .get("docker/test/blobs/sha256:orphan1")
            .await
            .is_err());
        // Referenced blob still exists
        assert!(storage
            .get("docker/test/blobs/sha256:configabc")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_manifest_list_references() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Multi-arch manifest list
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
        assert_eq!(result.orphaned_blobs, 0);
    }

    #[tokio::test]
    async fn test_gc_ignores_non_docker_registries() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Non-Docker artifacts must not be collected by GC, because
        // collect_referenced_digests only understands Docker manifests.
        // Without this guard, these would all appear as orphans and be deleted.
        storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", b"tarball-data")
            .await
            .unwrap();
        storage
            .put("maven/com/example/lib/1.0/lib-1.0.jar", b"jar-data")
            .await
            .unwrap();
        storage
            .put("cargo/serde/1.0.0/serde-1.0.0.crate", b"crate-data")
            .await
            .unwrap();

        let result = run_gc(&storage, true).await;
        assert_eq!(result.total_blobs, 0);
        assert_eq!(result.orphaned_blobs, 0);
    }

    #[tokio::test]
    async fn test_gc_does_not_delete_npm_tarballs() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Regression test: npm tarballs were previously collected because
        // their keys contain "/tarballs/", but no reference resolver existed
        // for npm metadata, so they were all treated as orphans.
        storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", b"tarball-data")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.deleted_blobs, 0);
        // Verify tarball still exists
        assert!(storage
            .get("npm/lodash/tarballs/lodash-4.17.21.tgz")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_gc_deletes_docker_orphan_but_preserves_npm() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Docker manifest referencing one blob
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
        // Orphan Docker blob
        storage
            .put("docker/test/blobs/sha256:orphan1", b"orphan")
            .await
            .unwrap();
        // npm tarball that must survive
        storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", b"tarball-data")
            .await
            .unwrap();

        let result = run_gc(&storage, false).await;
        assert_eq!(result.total_blobs, 2); // only Docker blobs counted
        assert_eq!(result.orphaned_blobs, 1);
        assert_eq!(result.deleted_blobs, 1);
        // Docker orphan gone
        assert!(storage
            .get("docker/test/blobs/sha256:orphan1")
            .await
            .is_err());
        // Docker referenced blob still exists
        assert!(storage
            .get("docker/test/blobs/sha256:configabc")
            .await
            .is_ok());
        // npm tarball untouched
        assert!(storage
            .get("npm/lodash/tarballs/lodash-4.17.21.tgz")
            .await
            .is_ok());
    }
}
