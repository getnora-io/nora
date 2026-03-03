//! Garbage Collection for orphaned blobs
//!
//! Mark-and-sweep approach:
//! 1. List all blobs across registries
//! 2. Parse all manifests to find referenced blobs
//! 3. Blobs not referenced by any manifest = orphans
//! 4. Delete orphans (with --dry-run support)

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
    let docker_blobs = storage.list("docker/").await;
    for key in docker_blobs {
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
