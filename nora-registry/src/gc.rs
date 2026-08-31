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
use std::sync::LazyLock;
use std::time::Instant;

use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};
use tracing::{info, warn};

use crate::storage::Storage;
use crate::validation::ends_with_ci;
use crate::PublishLocks;

// ============================================================================
// Prometheus metrics
// ============================================================================

pub static GC_BLOBS_REMOVED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_gc_blobs_removed_total",
        "Total orphaned blobs/files removed by GC"
    )
    .expect("gc_blobs_removed metric")
});

pub static GC_BYTES_FREED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!("nora_gc_bytes_freed_total", "Total bytes freed by GC")
        .expect("gc_bytes_freed metric")
});

pub static GC_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "nora_gc_duration_seconds",
        "Duration of GC runs in seconds",
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0]
    )
    .expect("gc_duration metric")
});

pub static GC_LAST_RUN: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_gc_last_run_timestamp",
        "Unix timestamp of last GC run"
    )
    .expect("gc_last_run metric")
});

pub static GC_METADATA_PHANTOMS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_gc_metadata_phantoms_total",
        "Total phantom version entries cleaned from metadata"
    )
    .expect("gc_metadata_phantoms metric")
});

pub static GC_PROXY_CACHE_EVICTED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_gc_proxy_cache_evicted_total",
        "Total proxy-cached files evicted by size-based GC"
    )
    .expect("gc_proxy_cache_evicted metric")
});

pub static GC_PROXY_CACHE_BYTES_FREED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_gc_proxy_cache_bytes_freed_total",
        "Total bytes freed by proxy-cache eviction"
    )
    .expect("gc_proxy_cache_bytes_freed metric")
});

pub static GC_STAT_FAILURES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_gc_stat_failures_total",
        "Orphans GC could not stat (kept, age unknown) — nonzero means GC may be unable to reclaim space; alert on it"
    )
    .expect("gc_stat_failures metric")
});

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
    /// Phantom version entries cleaned from metadata files (npm/PyPI)
    pub metadata_phantoms_removed: usize,
    /// Orphans skipped because they were younger than the grace period —
    /// protected from the write-vs-GC race (#584). Benign: collected next pass.
    pub skipped_recent: usize,
    /// Orphans kept because their age could not be determined (stat failed).
    /// Nonzero is a warning sign: GC may be unable to make progress (disk grows
    /// silently). Tracked separately from `skipped_recent` and metered via
    /// `nora_gc_stat_failures_total` so it can be alerted on.
    pub stat_failures: usize,
    /// Proxy-cache eviction result (#866).
    pub proxy_cache_eviction: ProxyCacheEviction,
}

// ============================================================================
// Main GC entry point
// ============================================================================

/// Current wall-clock time as a Unix timestamp (seconds). Returns 0 if the
/// clock is before the epoch, which makes every file look "in the future" and
/// thus protected by the grace check — a safe (fail-closed) degradation.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn run_gc(
    storage: &Storage,
    publish_locks: &PublishLocks,
    dry_run: bool,
    grace_secs: u64,
    npm_is_proxy: bool,
    proxy_cache_max_bytes: u64,
) -> GcResult {
    let start = Instant::now();
    info!(
        "Starting garbage collection (dry_run={}, grace_secs={})",
        dry_run, grace_secs
    );

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

    // Sort orphans: delete blobs before manifests so that if GC is interrupted
    // mid-run, we only leave harmless orphan blobs — never broken manifests
    // pointing to already-deleted blobs (#305).
    all_orphans.sort_by(|a, b| {
        let a_is_manifest = a.contains("/manifests/");
        let b_is_manifest = b.contains("/manifests/");
        a_is_manifest.cmp(&b_is_manifest)
    });

    let mut deleted = 0usize;
    let mut bytes_freed = 0u64;
    let mut skipped_recent = 0usize;
    let mut stat_failures = 0usize;
    let now = now_unix_secs();

    for key in &all_orphans {
        // Grace period (#584): never reap an orphan whose backing file is
        // younger than `grace_secs`. A blob written by an in-flight push whose
        // referencing manifest PUT has not landed yet looks orphaned but is
        // live — reaping it would strand the about-to-be-written manifest on a
        // missing layer. This is the canonical defence for the write-vs-GC race
        // (the manifest's key does not exist yet, so no lock can serialise
        // against it — only wall-clock age can). Applied to dry-run too, so the
        // preview matches what `--apply` would actually remove.
        //
        // Fail-closed: if the age cannot be determined (stat returned None),
        // keep the artifact rather than risk reaping a live one, and count it
        // separately (`stat_failures`) — a nonzero count means GC may be unable
        // to make progress, which is alertable.
        let Some(meta) = storage.stat(key).await else {
            warn!("GC: cannot stat {}, keeping it (age unknown)", key);
            stat_failures += 1;
            continue;
        };
        if grace_secs > 0 && now.saturating_sub(meta.modified) < grace_secs {
            skipped_recent += 1;
            continue;
        }

        if dry_run {
            bytes_freed += meta.size;
            info!("[dry-run] Would delete: {} ({} bytes)", key, meta.size);
            continue;
        }

        // Serialize with concurrent publish to prevent deleting an artifact
        // under a same-key write.
        let lock = crate::acquire_publish_lock(publish_locks, key);
        let _guard = lock.lock().await;
        if storage.delete(key).await.is_ok() {
            deleted += 1;
            bytes_freed += meta.size;
            info!("Deleted: {}", key);
        }
    }

    if skipped_recent > 0 {
        info!(
            "Skipped {} orphan(s) younger than grace ({}s) — likely in-flight uploads",
            skipped_recent, grace_secs
        );
    }
    if stat_failures > 0 {
        warn!(
            "GC could not stat {} orphan(s); kept them (age unknown). GC may be unable to reclaim space",
            stat_failures
        );
        GC_STAT_FAILURES.inc_by(stat_failures as u64);
    }

    if !dry_run {
        info!("Deleted {} orphans, freed {} bytes", deleted, bytes_freed);
        GC_BLOBS_REMOVED.inc_by(deleted as u64);
        GC_BYTES_FREED.inc_by(bytes_freed);
    }

    // Metadata phantom cleanup (npm/PyPI) — acquires per-key publish_lock
    // to prevent lost-update race with concurrent publish (#529).
    let metadata_phantoms_removed =
        detect_and_clean_metadata_phantoms(storage, publish_locks, dry_run, npm_is_proxy).await;
    if metadata_phantoms_removed > 0 {
        if !dry_run {
            GC_METADATA_PHANTOMS.inc_by(metadata_phantoms_removed as u64);
        }
        info!(
            "Metadata phantoms {}: {}",
            if dry_run { "detected" } else { "cleaned" },
            metadata_phantoms_removed
        );
    }

    // Proxy-cache eviction (#866): size-based LRU for rpm/deb proxy-cached
    // files that have no sidecar and are not indexes.
    let proxy_cache_eviction =
        evict_proxy_cache(storage, publish_locks, proxy_cache_max_bytes, dry_run).await;

    // Detect registries with data but no GC coverage
    // Raw has no version model and no reference graph — nothing to GC by design
    // Terraform/Pub/Ansible/NuGet store only cached metadata — no orphan graph,
    // but we track them so the GC report shows data exists outside coverage
    let mut uncovered = Vec::new();
    for prefix in [
        "raw/",
        "terraform/",
        "pub/",
        "ansible/",
        "nuget/",
        "gems/",
        "conan/",
        "rpm/",
        "deb/",
    ] {
        let keys = storage.list(prefix).await.unwrap_or_else(|e| {
            tracing::error!("GC: storage.list({}) failed: {}", prefix, e);
            Vec::new()
        });
        let count = keys.len();
        if count > 0 {
            let name = prefix.trim_end_matches('/').to_string();
            uncovered.push((name, count));
        }
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
        metadata_phantoms_removed,
        skipped_recent,
        stat_failures,
        proxy_cache_eviction,
    }
}

// ============================================================================
// Docker orphan detection
// ============================================================================

struct DetectionResult {
    total: usize,
    orphans: Vec<String>,
}

/// Extract config.digest + layers[].digest into `referenced`, and
/// manifests[].digest (manifest list entries) into `sub_manifests`.
fn collect_manifest_refs(
    json: &serde_json::Value,
    referenced: &mut HashSet<String>,
    sub_manifests: &mut HashSet<String>,
) {
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
    // manifest list / image index: sub-manifest digests
    if let Some(manifests) = json.get("manifests").and_then(|v| v.as_array()) {
        for m in manifests {
            if let Some(digest) = m.get("digest").and_then(|v| v.as_str()) {
                sub_manifests.insert(digest.to_string());
            }
        }
    }
}

/// Extract config.digest + layers[].digest into `referenced` (blob refs only,
/// no sub-manifest traversal).
fn collect_blob_refs(json: &serde_json::Value, referenced: &mut HashSet<String>) {
    if let Some(digest) = json
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
    {
        referenced.insert(digest.to_string());
    }
    if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            if let Some(digest) = layer.get("digest").and_then(|v| v.as_str()) {
                referenced.insert(digest.to_string());
            }
        }
    }
}

/// True if `ref_name` is a digest reference (sha256:… or sha512:…), not a tag.
fn is_digest_ref(ref_name: &str) -> bool {
    ref_name.starts_with("sha256:") || ref_name.starts_with("sha512:")
}

async fn detect_docker_orphans(storage: &Storage) -> DetectionResult {
    let keys = storage.list("docker/").await.unwrap_or_else(|e| {
        tracing::error!("GC: storage.list(docker/) failed: {}", e);
        Vec::new()
    });

    let mut blobs: Vec<String> = Vec::new();
    let mut all_manifest_keys: Vec<String> = Vec::new();

    for key in &keys {
        if key.contains("/blobs/") {
            blobs.push(key.clone());
        } else if key.contains("/manifests/")
            && ends_with_ci(key, ".json")
            && !ends_with_ci(key, ".meta.json")
        {
            all_manifest_keys.push(key.clone());
        }
    }

    // Step 1: Identify tag manifests (filename does NOT start with sha256:/sha512:)
    let tag_manifests: Vec<&String> = all_manifest_keys
        .iter()
        .filter(|k| {
            let filename = k.rsplit('/').next().unwrap_or("");
            let ref_name = filename.strip_suffix(".json").unwrap_or(filename);
            !is_digest_ref(ref_name)
        })
        .collect();

    // Step 2: Read tag manifests, collect referenced blob digests.
    // For manifest lists, also collect sub-manifest digests to resolve in step 3.
    let mut referenced = HashSet::new();
    let mut sub_manifest_digests: HashSet<String> = HashSet::new();

    for key in &tag_manifests {
        if let Ok(data) = storage.get(key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                collect_manifest_refs(&json, &mut referenced, &mut sub_manifest_digests);
            }
        }
    }

    // Step 3: Resolve sub-manifests (manifest list entries) — these are
    // digest-keyed but reachable from a tag, so their blobs must be kept.
    for key in &all_manifest_keys {
        let filename = key.rsplit('/').next().unwrap_or("");
        let ref_name = filename.strip_suffix(".json").unwrap_or(filename);
        if sub_manifest_digests.contains(ref_name) {
            if let Ok(data) = storage.get(key).await {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                    // Only collect blob refs, not further sub-manifests (2 levels deep enough)
                    collect_blob_refs(&json, &mut referenced);
                }
            }
        }
    }

    // Step 4: Detect orphaned digest manifests — digest-keyed manifests not
    // reachable from any tag (neither directly tagged nor a sub-manifest of a
    // tagged manifest list).
    let mut orphan_digest_manifests: Vec<String> = Vec::new();
    for key in &all_manifest_keys {
        let filename = key.rsplit('/').next().unwrap_or("");
        let ref_name = filename.strip_suffix(".json").unwrap_or(filename);
        if is_digest_ref(ref_name) && !sub_manifest_digests.contains(ref_name) {
            orphan_digest_manifests.push(key.clone());
        }
    }

    let total = blobs.len();
    let mut orphans: Vec<String> = blobs
        .into_iter()
        .filter(|key| {
            key.rsplit('/')
                .next()
                .map(|digest| !referenced.contains(digest))
                .unwrap_or(false)
        })
        .collect();

    // Append orphaned digest manifests — they will be sorted after blobs by
    // the caller (run_gc's #305 invariant: blobs before manifests).
    orphans.extend(orphan_digest_manifests);

    DetectionResult { total, orphans }
}

// ============================================================================
// Checksum orphan detection (Maven, npm, PyPI)
// ============================================================================

const CHECKSUM_EXTENSIONS: &[&str] = &[".md5", ".sha1", ".sha256", ".sha512"];

pub(crate) fn is_checksum_sidecar(key: &str) -> bool {
    CHECKSUM_EXTENSIONS.iter().any(|ext| ends_with_ci(key, ext))
}

fn primary_key_for_checksum(key: &str) -> Option<&str> {
    for ext in CHECKSUM_EXTENSIONS {
        if let Some(primary) = key.strip_suffix(ext) {
            return Some(primary);
        }
    }
    None
}

/// Revalidation validator sidecars (`<key>.meta`, #596) are produced ONLY for
/// npm metadata, so the orphan rule is scoped to the npm prefix — otherwise a
/// Maven artifact that legitimately ends in `.meta` could be false-deleted.
fn is_meta_sidecar(key: &str) -> bool {
    key.starts_with("npm/") && ends_with_ci(key, ".meta")
}

/// True for any sidecar whose orphan rule is "primary artifact absent".
fn is_orphanable_sidecar(key: &str) -> bool {
    is_checksum_sidecar(key) || is_meta_sidecar(key)
}

/// Primary artifact key a sidecar belongs to (checksum or `.meta`).
fn primary_key_for_sidecar(key: &str) -> Option<&str> {
    if is_meta_sidecar(key) {
        return key.strip_suffix(".meta");
    }
    primary_key_for_checksum(key)
}

async fn detect_checksum_orphans(storage: &Storage) -> DetectionResult {
    let mut checksums: Vec<String> = Vec::new();

    // Scan Maven, npm, PyPI prefixes for checksum sidecar files
    for prefix in &["maven/", "npm/", "pypi/"] {
        let keys = storage.list(prefix).await.unwrap_or_else(|e| {
            tracing::error!("GC: storage.list({}) failed: {}", prefix, e);
            Vec::new()
        });
        for key in keys {
            if is_orphanable_sidecar(&key) {
                checksums.push(key);
            }
        }
    }

    let total = checksums.len();
    let mut orphans = Vec::new();

    for checksum_key in &checksums {
        if let Some(primary) = primary_key_for_sidecar(checksum_key) {
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
    let keys = storage.list("go/").await.unwrap_or_else(|e| {
        tracing::error!("GC: storage.list(go/) failed: {}", e);
        Vec::new()
    });
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
        let has_info = files.iter().any(|f| ends_with_ci(f, ".info"));
        let has_zip = files.iter().any(|f| ends_with_ci(f, ".zip"));
        if !has_info || !has_zip {
            info!(
                "Go incomplete version: {} (has {} of 3 expected files)",
                version_key,
                files.len()
            );
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
    let keys = storage.list("cargo/").await.unwrap_or_else(|e| {
        tracing::error!("GC: storage.list(cargo/) failed: {}", e);
        Vec::new()
    });
    let mut crate_files: HashSet<String> = HashSet::new(); // "name/version"
    let mut index_entries: HashSet<String> = HashSet::new(); // "name"
    let mut crate_keys: Vec<String> = Vec::new();
    let mut index_keys: Vec<String> = Vec::new();
    let mut index_entry_keys: Vec<String> = Vec::new(); // per-version cargo/index-entries/ (#39)

    for key in &keys {
        if key.starts_with("cargo/index-entries/") {
            // cargo/index-entries/XX/XX/name/version.json — the scan-regenerate source of truth
            index_entry_keys.push(key.clone());
        } else if key.starts_with("cargo/index/") {
            // cargo/index/XX/XX/name
            if let Some(name) = key
                .strip_prefix("cargo/index/")
                .and_then(|s| s.split('/').nth(2))
            {
                index_entries.insert(name.to_string());
                index_keys.push(key.clone());
            }
        } else if ends_with_ci(key, ".crate") {
            // cargo/name/version/name-version.crate
            let parts: Vec<&str> = key
                .strip_prefix("cargo/")
                .unwrap_or(key)
                .split('/')
                .collect();
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
        if let Some(name) = key
            .strip_prefix("cargo/index/")
            .and_then(|s| s.split('/').nth(2))
        {
            if !crate_files.contains(name) {
                info!("Cargo orphan index: {} (no .crate files)", key);
                orphans.push(key.clone());
                // Also remove the per-version entry keys for this fully-deleted crate (#39
                // layout), else a later publish's regenerate would resurrect index lines that
                // point at missing .crate files.
                let entries_prefix = format!(
                    "{}/",
                    key.replacen("cargo/index/", "cargo/index-entries/", 1)
                );
                for ek in &index_entry_keys {
                    if ek.starts_with(&entries_prefix) {
                        orphans.push(ek.clone());
                    }
                }
            }
        }
    }

    // .crate files without index entry
    for key in &crate_keys {
        let parts: Vec<&str> = key
            .strip_prefix("cargo/")
            .unwrap_or(key)
            .split('/')
            .collect();
        if parts.len() >= 2 && !index_entries.contains(parts[0]) {
            info!("Cargo orphan crate: {} (no index entry)", key);
            orphans.push(key.clone());
        }
    }

    DetectionResult { total, orphans }
}

// ============================================================================
// Metadata phantom detection (npm/PyPI)
// ============================================================================

/// Detect and clean phantom version entries from npm/PyPI metadata files.
///
/// When GC/retention deletes version tarballs, the metadata.json may still
/// reference those deleted versions. This function:
/// 1. Lists all existing tarballs for each package
/// 2. Reads metadata.json and checks which versions have no tarball
/// 3. Removes phantom entries (and rewrites metadata.json if not dry_run)
async fn detect_and_clean_metadata_phantoms(
    storage: &Storage,
    publish_locks: &PublishLocks,
    dry_run: bool,
    npm_is_proxy: bool,
) -> usize {
    let mut total_removed = 0usize;

    // npm metadata cleanup — skip when npm is configured as a proxy (#925).
    // Proxy metadata is upstream-authoritative: absence of a local tarball is
    // expected (on-demand caching), not an orphan signal.
    if npm_is_proxy {
        info!("GC: skipping npm phantom cleanup (proxy mode — tarballs are cached on demand)");
    }
    if !npm_is_proxy {
        let npm_keys = storage.list("npm/").await.unwrap_or_else(|e| {
            tracing::error!("GC: storage.list(npm/) failed: {}", e);
            Vec::new()
        });
        let mut npm_meta_keys: Vec<String> = Vec::new();
        let mut npm_tarball_keys: HashSet<String> = HashSet::new();

        for key in &npm_keys {
            if ends_with_ci(key, "/metadata.json") {
                npm_meta_keys.push(key.clone());
            } else if key.contains("/tarballs/") {
                npm_tarball_keys.insert(key.clone());
            }
        }

        for meta_key in &npm_meta_keys {
            if let Some(removed) =
                clean_npm_metadata(storage, publish_locks, meta_key, &npm_tarball_keys, dry_run)
                    .await
            {
                total_removed += removed;
            }
        }
    }

    // PyPI metadata cleanup
    let pypi_keys = storage.list("pypi/").await.unwrap_or_else(|e| {
        tracing::error!("GC: storage.list(pypi/) failed: {}", e);
        Vec::new()
    });
    let mut pypi_meta_keys: Vec<String> = Vec::new();
    let mut pypi_file_keys: HashSet<String> = HashSet::new();

    for key in &pypi_keys {
        if ends_with_ci(key, "/metadata.json") {
            pypi_meta_keys.push(key.clone());
        } else if !ends_with_ci(key, ".sha256")
            && !ends_with_ci(key, ".md5")
            && !ends_with_ci(key, ".sha1")
            && !ends_with_ci(key, ".sha512")
        {
            pypi_file_keys.insert(key.clone());
        }
    }

    for meta_key in &pypi_meta_keys {
        if let Some(removed) =
            clean_pypi_metadata(storage, publish_locks, meta_key, &pypi_file_keys, dry_run).await
        {
            total_removed += removed;
        }
    }

    total_removed
}

/// Clean phantom versions from a single npm metadata.json.
///
/// npm metadata has `versions` and `time` objects keyed by version string.
/// A phantom = a version key with no corresponding tarball in storage.
async fn clean_npm_metadata(
    storage: &Storage,
    publish_locks: &PublishLocks,
    meta_key: &str,
    all_tarball_keys: &HashSet<String>,
    dry_run: bool,
) -> Option<usize> {
    // LOCK ORDER: cleanup_lock (held by caller) → publish_lock (acquired here).
    // Serialize with npm publish to prevent lost-update race (#529).
    let lock = crate::acquire_publish_lock(publish_locks, meta_key);
    let _guard = lock.lock().await;

    let data = storage.get(meta_key).await.ok()?;
    let mut json: serde_json::Value = serde_json::from_slice(&data).ok()?;

    // Extract package name from key: npm/{name}/metadata.json
    let package_name = meta_key
        .strip_prefix("npm/")?
        .strip_suffix("/metadata.json")?;

    let versions = json.get("versions")?.as_object()?.clone();
    let mut phantoms: Vec<String> = Vec::new();

    for ver_key in versions.keys() {
        // npm tarballs: npm/{name}/tarballs/{name}-{version}.tgz
        // For scoped packages @scope/name, tarball uses just "name" part
        let name_part = if package_name.contains('/') {
            package_name.rsplit('/').next().unwrap_or(package_name)
        } else {
            package_name
        };
        let tarball_key = format!(
            "npm/{}/tarballs/{}-{}.tgz",
            package_name, name_part, ver_key
        );
        if !all_tarball_keys.contains(&tarball_key) {
            phantoms.push(ver_key.clone());
        }
    }

    if phantoms.is_empty() {
        return Some(0);
    }

    let count = phantoms.len();
    for phantom in &phantoms {
        info!(
            "[metadata-gc] npm {}: phantom version {} (no tarball)",
            package_name, phantom
        );
    }

    if !dry_run {
        // Remove phantom entries from versions object
        if let Some(versions_obj) = json.get_mut("versions").and_then(|v| v.as_object_mut()) {
            for phantom in &phantoms {
                versions_obj.remove(phantom.as_str());
            }
        }
        // Remove corresponding time entries
        if let Some(time_obj) = json.get_mut("time").and_then(|v| v.as_object_mut()) {
            for phantom in &phantoms {
                time_obj.remove(phantom.as_str());
            }
        }
        // Also delete the per-version index key (the scan-regenerate source of truth, #39) so a
        // later publish's regenerate does not re-add the phantom from disk.
        for phantom in &phantoms {
            let version_key = format!("npm/{}/versions/{}.json", package_name, phantom);
            let _ = storage.delete(&version_key).await;
        }
        // Rewrite metadata
        if let Ok(new_data) = serde_json::to_vec(&json) {
            if let Err(e) = storage.put(meta_key, &new_data).await {
                tracing::warn!(key = %meta_key, error = %e, "Failed to rewrite npm metadata after phantom cleanup");
            }
        }
    }

    Some(count)
}

/// Clean phantom releases from a single PyPI metadata.json.
///
/// PyPI metadata has `releases` keyed by version, each containing an array of files.
/// A phantom = a version key where none of the referenced files exist in storage.
async fn clean_pypi_metadata(
    storage: &Storage,
    publish_locks: &PublishLocks,
    meta_key: &str,
    all_file_keys: &HashSet<String>,
    dry_run: bool,
) -> Option<usize> {
    // LOCK ORDER: cleanup_lock (held by caller) → publish_lock (acquired here).
    // Serialize with any future metadata writers (#529).
    let lock = crate::acquire_publish_lock(publish_locks, meta_key);
    let _guard = lock.lock().await;

    let data = storage.get(meta_key).await.ok()?;
    let mut json: serde_json::Value = serde_json::from_slice(&data).ok()?;

    // Extract package name from key: pypi/{name}/metadata.json
    let package_name = meta_key
        .strip_prefix("pypi/")?
        .strip_suffix("/metadata.json")?;

    let releases = json.get("releases")?.as_object()?.clone();
    let mut phantoms: Vec<String> = Vec::new();

    for (ver_key, files_val) in &releases {
        let files = match files_val.as_array() {
            Some(arr) => arr,
            None => {
                phantoms.push(ver_key.clone());
                continue;
            }
        };

        // Check if ANY file from this release exists in storage
        let has_file = files.iter().any(|f| {
            if let Some(filename) = f.get("filename").and_then(|v| v.as_str()) {
                let file_key = format!("pypi/{}/{}", package_name, filename);
                all_file_keys.contains(&file_key)
            } else {
                false
            }
        });

        if !has_file && !files.is_empty() {
            phantoms.push(ver_key.clone());
        }
    }

    if phantoms.is_empty() {
        return Some(0);
    }

    let count = phantoms.len();
    for phantom in &phantoms {
        info!(
            "[metadata-gc] pypi {}: phantom release {} (no files)",
            package_name, phantom
        );
    }

    if !dry_run {
        if let Some(releases_obj) = json.get_mut("releases").and_then(|v| v.as_object_mut()) {
            for phantom in &phantoms {
                releases_obj.remove(phantom.as_str());
            }
        }
        if let Ok(new_data) = serde_json::to_vec(&json) {
            if let Err(e) = storage.put(meta_key, &new_data).await {
                tracing::warn!(key = %meta_key, error = %e, "Failed to rewrite PyPI metadata after phantom cleanup");
            }
        }
    }

    Some(count)
}

// ============================================================================
// Proxy-cache eviction (#866)
// ============================================================================

/// Result of proxy-cache eviction.
#[derive(Debug, Clone, Default)]
pub struct ProxyCacheEviction {
    /// Total proxy-cached bytes before eviction.
    pub total_bytes: u64,
    /// Number of files evicted.
    pub evicted_files: usize,
    /// Bytes freed by eviction.
    pub bytes_freed: u64,
}

/// Index files that must never be evicted — they are regenerated indexes,
/// not proxy-cached packages.
fn is_index_file(key: &str) -> bool {
    // rpm: repodata/
    if key.contains("/repodata/") {
        return true;
    }
    // deb: Packages, Packages.gz, Release, InRelease, etc.
    let filename = key.rsplit('/').next().unwrap_or(key);
    matches!(
        filename,
        "Packages"
            | "Packages.gz"
            | "Packages.bz2"
            | "Packages.xz"
            | "Release"
            | "Release.gpg"
            | "InRelease"
    )
}

/// Evict proxy-cached artifacts (rpm/deb) when total size exceeds `max_bytes`.
///
/// Proxy-cached files = files under `rpm/` or `deb/` that:
/// - have NO corresponding `.nora-meta/` sidecar (hosted packages have one)
/// - are NOT themselves under `.nora-meta/`
/// - are NOT index files (repodata/, Packages, Release, etc.)
///
/// Eviction order: oldest by mtime first (LRU approximation; immutable files
/// are never re-written, so mtime ≈ "least recently cached").
async fn evict_proxy_cache(
    storage: &Storage,
    publish_locks: &PublishLocks,
    max_bytes: u64,
    dry_run: bool,
) -> ProxyCacheEviction {
    if max_bytes == 0 {
        return ProxyCacheEviction::default();
    }

    let mut proxy_files: Vec<(String, u64, u64)> = Vec::new(); // (key, size, mtime)
    let mut sidecar_covered: HashSet<String> = HashSet::new();

    for prefix in ["rpm/", "deb/"] {
        let entries = match storage.list_with_meta(prefix).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("GC proxy-cache: list_with_meta({prefix}) failed: {e}");
                continue;
            }
        };

        // First pass: collect sidecar-covered paths
        for (key, _meta) in &entries {
            // {registry}/{repo}/.nora-meta/{path}.json → covers {registry}/{repo}/{path}
            if let Some(rest) = key.strip_prefix(prefix) {
                if let Some((repo, meta_rest)) = rest.split_once("/.nora-meta/") {
                    if let Some(pkg_path) = meta_rest.strip_suffix(".json") {
                        let covered = format!("{prefix}{repo}/{pkg_path}");
                        sidecar_covered.insert(covered);
                    }
                }
            }
        }

        // Second pass: identify proxy-only files
        for (key, meta) in &entries {
            // Skip .nora-meta/ entries themselves
            if key.contains("/.nora-meta/") {
                continue;
            }
            // Skip index files
            if is_index_file(key) {
                continue;
            }
            // Skip hosted files (have sidecar)
            if sidecar_covered.contains(key) {
                continue;
            }
            proxy_files.push((key.clone(), meta.size, meta.modified));
        }
    }

    let total_bytes: u64 = proxy_files.iter().map(|(_, s, _)| s).sum();

    if total_bytes <= max_bytes {
        return ProxyCacheEviction {
            total_bytes,
            evicted_files: 0,
            bytes_freed: 0,
        };
    }

    // Sort by mtime ascending (oldest first) for LRU eviction
    proxy_files.sort_by_key(|&(_, _, mtime)| mtime);

    let mut bytes_freed = 0u64;
    let mut evicted = 0usize;
    let bytes_to_free = total_bytes - max_bytes;

    for (key, size, _mtime) in &proxy_files {
        if bytes_freed >= bytes_to_free {
            break;
        }
        if dry_run {
            info!("[dry-run] proxy-cache evict: {} ({} bytes)", key, size);
        } else {
            let lock = crate::acquire_publish_lock(publish_locks, key);
            let _guard = lock.lock().await;
            if storage.delete(key).await.is_ok() {
                info!("proxy-cache evicted: {} ({} bytes)", key, size);
            }
        }
        bytes_freed += size;
        evicted += 1;
    }

    if !dry_run && evicted > 0 {
        GC_PROXY_CACHE_EVICTED.inc_by(evicted as u64);
        GC_PROXY_CACHE_BYTES_FREED.inc_by(bytes_freed);
    }

    info!(
        "Proxy-cache eviction{}: {} files, {} bytes freed (was {} / cap {})",
        if dry_run { " (dry-run)" } else { "" },
        evicted,
        bytes_freed,
        total_bytes,
        max_bytes
    );

    ProxyCacheEviction {
        total_bytes,
        evicted_files: evicted,
        bytes_freed,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_publish_locks() -> PublishLocks {
        Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()))
    }

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
            metadata_phantoms_removed: 0,
            skipped_recent: 0,
            stat_failures: 0,
            proxy_cache_eviction: ProxyCacheEviction::default(),
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

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.orphaned, 1);
        assert_eq!(result.deleted, 0);
        assert!(result.orphan_keys[0].contains("orphan999"));
        // Orphan still exists (dry run)
        assert!(storage
            .get("docker/test/blobs/sha256:orphan999")
            .await
            .is_ok());
    }

    /// Regression for #584: a freshly-written orphan blob must NOT be deleted —
    /// it may be a layer from an in-flight push whose manifest PUT has not
    /// landed yet, and deleting it would strand that manifest on a missing
    /// layer. With a non-zero grace the orphan is detected but protected; with
    /// grace=0 (read-only maintenance window) it is collected. Drives the real
    /// `run_gc` delete path.
    #[tokio::test]
    async fn test_gc_grace_protects_recent_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // An unreferenced (orphan) blob, just written → mtime ≈ now.
        storage
            .put("docker/test/blobs/sha256:fresh000", b"in-flight-layer")
            .await
            .unwrap();

        // Generous grace: the orphan is detected but must NOT be deleted.
        let result = run_gc(&storage, &test_publish_locks(), false, 3600, false, 0).await;
        assert_eq!(result.orphaned, 1, "orphan should be detected");
        assert_eq!(
            result.deleted, 0,
            "recent orphan must be protected by grace"
        );
        assert_eq!(result.skipped_recent, 1);
        assert!(
            storage
                .get("docker/test/blobs/sha256:fresh000")
                .await
                .is_ok(),
            "blob from a possible in-flight push must survive (#584)"
        );

        // Dry-run honors grace too, so the preview matches `--apply`: a
        // protected orphan is reported as skipped, not as "would delete".
        let preview = run_gc(&storage, &test_publish_locks(), true, 3600, false, 0).await;
        assert_eq!(preview.skipped_recent, 1);
        assert_eq!(
            preview.bytes_freed, 0,
            "dry-run must not count a grace-protected orphan"
        );

        // grace=0 (no concurrent writes): the same orphan is now collected.
        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert_eq!(result.deleted, 1, "grace=0 deletes the orphan");
        assert!(storage
            .get("docker/test/blobs/sha256:fresh000")
            .await
            .is_err());
    }

    /// #610 (hardening for #584): an orphan whose mtime is in the FUTURE (clock
    /// skew, or a file copied with a forward timestamp) must be protected, not
    /// deleted. The grace check uses `saturating_sub`, so `now - future` is 0
    /// (< grace) — never a wrap-around that would make it look ancient.
    #[tokio::test]
    async fn test_gc_grace_protects_future_mtime_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let storage = Storage::new_local(data.to_str().unwrap());

        let key = "docker/test/blobs/sha256:future00";
        storage.put(key, b"x").await.unwrap();

        // Backdate-forward the file's mtime to one hour ahead.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(data.join(key))
            .unwrap()
            .set_modified(future)
            .unwrap();

        // A short grace: a normal old orphan would be deleted, but a future
        // mtime must still be treated as "too young" and kept.
        let result = run_gc(&storage, &test_publish_locks(), false, 60, false, 0).await;
        assert_eq!(
            result.skipped_recent, 1,
            "future-mtime orphan must be protected (saturating_sub)"
        );
        assert_eq!(result.deleted, 0);
        assert!(storage.get(key).await.is_ok());
    }

    /// #610: the grace period applies uniformly to all orphan classes, not just
    /// Docker blobs. A freshly-written non-Docker orphan (here a Maven checksum
    /// sidecar with no primary artifact) must also be protected.
    #[tokio::test]
    async fn test_gc_grace_protects_non_docker_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // A checksum sidecar with no primary artifact → orphan (checksum class).
        let key = "maven/com/example/1.0/old.jar.sha256";
        storage.put(key, b"deadbeef").await.unwrap();

        let result = run_gc(&storage, &test_publish_locks(), false, 3600, false, 0).await;
        assert_eq!(result.orphaned, 1, "checksum orphan should be detected");
        assert_eq!(
            result.deleted, 0,
            "young non-docker orphan must be protected"
        );
        assert_eq!(result.skipped_recent, 1);
        assert!(storage.get(key).await.is_ok());
    }

    /// #610: a backend whose `stat` always returns `None`, to drive GC's
    /// fail-closed "age unknown → keep and count" branch. `list("docker/")`
    /// surfaces a single orphan blob; the rest of the surface is unused on this
    /// code path, so the other methods are inert stubs.
    struct StatNoneBackend {
        orphan: String,
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for StatNoneBackend {
        async fn stat(&self, _key: &str) -> Option<crate::storage::FileMeta> {
            None
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            Ok(if prefix == "docker/" {
                vec![self.orphan.clone()]
            } else {
                Vec::new()
            })
        }
        async fn put(&self, _key: &str, _data: &[u8], _sha256: &str) -> crate::storage::Result<()> {
            Ok(())
        }
        async fn get(
            &self,
            _key: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            Err(crate::storage::StorageError::NotFound)
        }
        async fn pin(&self, _key: &str) -> Option<String> {
            None
        }
        async fn delete(&self, _key: &str) -> crate::storage::Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            0
        }
        fn backend_name(&self) -> &'static str {
            "stat-none-test"
        }
        async fn put_from_path(
            &self,
            _key: &str,
            _src: &std::path::Path,
            _sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            Ok(())
        }
        async fn get_reader(
            &self,
            _key: &str,
        ) -> crate::storage::Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            Err(crate::storage::StorageError::NotFound)
        }
        async fn copy(
            &self,
            _src: &str,
            _dst: &str,
            _sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            Err(crate::storage::StorageError::NotFound)
        }
    }

    /// #610 (hardening for #584): an orphan whose age cannot be determined
    /// (`stat` returns `None`) is FAIL-CLOSED — kept (never reaped) and counted
    /// in `stat_failures`, which feeds `nora_gc_stat_failures_total` so operators
    /// can alert on GC being unable to reclaim space.
    #[tokio::test]
    async fn test_gc_stat_failure_keeps_orphan_and_counts() {
        let before = GC_STAT_FAILURES.get();
        let storage = Storage::from_backend(std::sync::Arc::new(StatNoneBackend {
            orphan: format!("docker/lib/blobs/sha256:{}", "a".repeat(64)),
        }));

        // grace=0 would collect any normal orphan; the un-stattable one must
        // still survive because its age is unknown.
        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;

        assert_eq!(result.orphaned, 1, "the blob is detected as an orphan");
        assert_eq!(
            result.deleted, 0,
            "an orphan that cannot be stat'd must be kept (fail-closed)"
        );
        assert_eq!(
            result.stat_failures, 1,
            "the kept orphan is counted as a stat failure"
        );
        // The per-run count feeds the global counter. A strict `>` over the
        // pre-run value stays robust against other tests touching the same
        // monotonic metric (they only ever add).
        assert!(
            GC_STAT_FAILURES.get() > before,
            "nora_gc_stat_failures_total must increment"
        );
    }

    /// #610 (hardening for #584): the GC delete path and a concurrent publish to
    /// the same key serialise through `publish_lock` — never a torn write, panic
    /// or deadlock. This races `run_gc(grace=0)` (which reaps orphans under the
    /// lock) against a writer re-putting the same keys under the SAME locks.
    /// Non-deterministic by nature; it asserts only that every key ends in a
    /// clean terminal state.
    #[tokio::test]
    async fn test_gc_concurrent_push_and_gc_stay_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let locks = test_publish_locks();

        let keys: Vec<String> = (0..16)
            .map(|i| format!("docker/race/blobs/sha256:race{:04}", i))
            .collect();
        for k in &keys {
            storage.put(k, b"orphan").await.unwrap();
        }

        let writer = {
            let storage = storage.clone();
            let locks = locks.clone();
            let keys = keys.clone();
            async move {
                for k in &keys {
                    let lock = crate::acquire_publish_lock(&locks, k);
                    let _guard = lock.lock().await;
                    let _ = storage.put(k, b"rewritten-by-concurrent-push").await;
                }
            }
        };

        let (_gc, ()) = tokio::join!(run_gc(&storage, &locks, false, 0, false, 0), writer);

        // Every key is either reaped by GC or present with exactly one of the two
        // intended bodies — atomic writes guarantee no partial/torn content.
        for k in &keys {
            if let Ok(bytes) = storage.get(k).await {
                assert!(
                    bytes.as_ref() == b"orphan"
                        || bytes.as_ref() == b"rewritten-by-concurrent-push",
                    "key {k} has a torn body: {:?}",
                    bytes
                );
            }
        }
    }

    /// #596: a `.meta` validator sidecar is reaped when its npm metadata body is
    /// gone (orphan), kept when the body is present, and — crucially — a Maven
    /// artifact ending in `.meta` is NOT treated as a sidecar (no false delete).
    #[tokio::test]
    async fn test_gc_meta_sidecar_orphan_rule_is_npm_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Orphan npm .meta (no primary body) → reaped.
        storage
            .put("npm/orphan/metadata.json.meta", br#"{"etag":"v1"}"#)
            .await
            .unwrap();
        // npm .meta WITH its primary body → kept.
        storage
            .put("npm/live/metadata.json", b"body")
            .await
            .unwrap();
        storage
            .put("npm/live/metadata.json.meta", br#"{"etag":"v2"}"#)
            .await
            .unwrap();
        // Maven artifact literally ending in .meta, no primary → must NOT be a
        // sidecar candidate (false-delete guard).
        storage
            .put("maven/com/x/1.0/thing.meta", b"real-artifact")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert!(result.deleted >= 1);

        assert!(
            storage.get("npm/orphan/metadata.json.meta").await.is_err(),
            "orphan npm .meta must be reaped"
        );
        assert!(
            storage.get("npm/live/metadata.json.meta").await.is_ok(),
            "npm .meta with a live body must be kept"
        );
        assert!(
            storage.get("maven/com/x/1.0/thing.meta").await.is_ok(),
            "a Maven .meta artifact must never be treated as a sidecar"
        );
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
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

    /// Manifest list (image index) tag transitively protects sub-manifest blobs.
    #[tokio::test]
    async fn test_gc_manifest_list_references() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Manifest list (image index) references two sub-manifests by digest.
        let manifest = serde_json::json!({
            "manifests": [
                {"digest": "sha256:platformA", "size": 100},
                {"digest": "sha256:platformB", "size": 200}
            ]
        });
        // Sub-manifests (stored as digest-keyed files) reference actual blobs.
        let sub_a = serde_json::json!({
            "config": {"digest": "sha256:cfg_a"},
            "layers": [{"digest": "sha256:layer_a", "size": 50}]
        });
        let sub_b = serde_json::json!({
            "config": {"digest": "sha256:cfg_b"},
            "layers": [{"digest": "sha256:layer_b", "size": 60}]
        });
        storage
            .put(
                "docker/multi/manifests/latest.json",
                manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put(
                "docker/multi/manifests/sha256:platformA.json",
                sub_a.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put(
                "docker/multi/manifests/sha256:platformB.json",
                sub_b.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:cfg_a", b"cfg-a")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:layer_a", b"layer-a")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:cfg_b", b"cfg-b")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:layer_b", b"layer-b")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.orphaned, 0);
    }

    // -- #655: Tag-rooted Docker GC tests --

    /// #655 (part 2): Two tags with different blobs — all blobs are tag-reachable,
    /// no orphans detected.
    #[tokio::test]
    async fn test_gc_tag_rooted_no_orphans_for_tagged_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let manifest_a = serde_json::json!({
            "config": {"digest": "sha256:cfg_a"},
            "layers": [{"digest": "sha256:layer_a", "size": 100}]
        });
        let manifest_b = serde_json::json!({
            "config": {"digest": "sha256:cfg_b"},
            "layers": [{"digest": "sha256:layer_b", "size": 200}]
        });
        storage
            .put(
                "docker/repo/manifests/v1.json",
                manifest_a.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put(
                "docker/repo/manifests/v2.json",
                manifest_b.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:cfg_a", b"config-a")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:layer_a", b"layer-a")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:cfg_b", b"config-b")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:layer_b", b"layer-b")
            .await
            .unwrap();

        let result = detect_docker_orphans(&storage).await;
        assert_eq!(result.orphans.len(), 0, "all blobs are tag-referenced");
    }

    /// #655 (part 2): Re-pushing a tag with new content makes the OLD digest
    /// manifest and its exclusive blobs orphaned.
    #[tokio::test]
    async fn test_gc_tag_rooted_repush_orphans_old_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Simulate: tag "latest" was pushed with content A, then re-pushed with B.
        // After re-push, the tag manifest points to B's content. The old digest
        // manifest (sha256:old_digest) still exists alongside B.

        let old_manifest = serde_json::json!({
            "config": {"digest": "sha256:old_config"},
            "layers": [{"digest": "sha256:old_layer", "size": 100}]
        });
        let new_manifest = serde_json::json!({
            "config": {"digest": "sha256:new_config"},
            "layers": [{"digest": "sha256:new_layer", "size": 200}]
        });

        // Current tag points to new content
        storage
            .put(
                "docker/repo/manifests/latest.json",
                new_manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        // Old digest manifest lingers from previous push
        storage
            .put(
                "docker/repo/manifests/sha256:old_digest.json",
                old_manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();
        // New digest manifest (current)
        storage
            .put(
                "docker/repo/manifests/sha256:new_digest.json",
                new_manifest.to_string().as_bytes(),
            )
            .await
            .unwrap();

        // Blobs for both versions
        storage
            .put("docker/repo/blobs/sha256:old_config", b"old-cfg")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:old_layer", b"old-layer")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:new_config", b"new-cfg")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:new_layer", b"new-layer")
            .await
            .unwrap();

        let result = detect_docker_orphans(&storage).await;

        // Old blobs (old_config, old_layer) are orphaned because only the tag
        // manifest (latest.json) is consulted, and it references new_* blobs.
        let orphan_blobs: Vec<&String> = result
            .orphans
            .iter()
            .filter(|k| k.contains("/blobs/"))
            .collect();
        assert_eq!(orphan_blobs.len(), 2, "old config + old layer are orphaned");
        assert!(
            orphan_blobs.iter().any(|k| k.contains("old_config")),
            "old config blob must be orphaned"
        );
        assert!(
            orphan_blobs.iter().any(|k| k.contains("old_layer")),
            "old layer blob must be orphaned"
        );

        // New blobs must NOT be orphaned
        assert!(
            !result.orphans.iter().any(|k| k.contains("new_config")),
            "new config blob must be kept"
        );
        assert!(
            !result.orphans.iter().any(|k| k.contains("new_layer")),
            "new layer blob must be kept"
        );

        // The old digest manifest itself should be detected as orphaned
        let orphan_manifests: Vec<&String> = result
            .orphans
            .iter()
            .filter(|k| k.contains("/manifests/"))
            .collect();
        assert_eq!(
            orphan_manifests.len(),
            2,
            "both orphan digest manifests (old + new, new is not tag-reachable as sub-manifest)"
        );
        assert!(
            orphan_manifests
                .iter()
                .any(|k| k.contains("sha256:old_digest")),
            "old digest manifest must be orphaned"
        );
    }

    /// #655 (part 2): A manifest list tag transitively protects sub-manifests'
    /// blobs. Digest-keyed sub-manifests referenced by the index are resolved
    /// in step 3 and their blobs kept.
    #[tokio::test]
    async fn test_gc_tag_rooted_manifest_list_transitive() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Tag "latest" is a manifest list (image index)
        let index = serde_json::json!({
            "manifests": [
                {"digest": "sha256:sub_amd64", "size": 100, "platform": {"architecture": "amd64"}},
                {"digest": "sha256:sub_arm64", "size": 100, "platform": {"architecture": "arm64"}}
            ]
        });
        // Sub-manifest for amd64
        let sub_amd64 = serde_json::json!({
            "config": {"digest": "sha256:cfg_amd64"},
            "layers": [{"digest": "sha256:layer_amd64", "size": 500}]
        });
        // Sub-manifest for arm64
        let sub_arm64 = serde_json::json!({
            "config": {"digest": "sha256:cfg_arm64"},
            "layers": [{"digest": "sha256:layer_arm64", "size": 600}]
        });

        storage
            .put(
                "docker/multi/manifests/latest.json",
                index.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put(
                "docker/multi/manifests/sha256:sub_amd64.json",
                sub_amd64.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put(
                "docker/multi/manifests/sha256:sub_arm64.json",
                sub_arm64.to_string().as_bytes(),
            )
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:cfg_amd64", b"cfg-amd64")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:layer_amd64", b"layer-amd64")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:cfg_arm64", b"cfg-arm64")
            .await
            .unwrap();
        storage
            .put("docker/multi/blobs/sha256:layer_arm64", b"layer-arm64")
            .await
            .unwrap();

        let result = detect_docker_orphans(&storage).await;
        assert_eq!(
            result.orphans.len(),
            0,
            "all blobs and sub-manifests are transitively reachable from the tag"
        );
    }

    /// #655 (part 2): A digest manifest with no tag pointing to it (and not a
    /// sub-manifest of any tagged manifest list) is detected as an orphan.
    #[tokio::test]
    async fn test_gc_tag_rooted_orphan_digest_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let tagged = serde_json::json!({
            "config": {"digest": "sha256:live_cfg"},
            "layers": [{"digest": "sha256:live_layer", "size": 100}]
        });
        let orphan = serde_json::json!({
            "config": {"digest": "sha256:dead_cfg"},
            "layers": [{"digest": "sha256:dead_layer", "size": 200}]
        });

        // A proper tagged manifest
        storage
            .put(
                "docker/repo/manifests/v1.json",
                tagged.to_string().as_bytes(),
            )
            .await
            .unwrap();
        // A digest-only manifest — no tag points to it
        storage
            .put(
                "docker/repo/manifests/sha256:orphan_digest.json",
                orphan.to_string().as_bytes(),
            )
            .await
            .unwrap();

        // Blobs for both
        storage
            .put("docker/repo/blobs/sha256:live_cfg", b"cfg")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:live_layer", b"layer")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:dead_cfg", b"dead-cfg")
            .await
            .unwrap();
        storage
            .put("docker/repo/blobs/sha256:dead_layer", b"dead-layer")
            .await
            .unwrap();

        let result = detect_docker_orphans(&storage).await;

        // The orphan digest manifest itself
        assert!(
            result
                .orphans
                .iter()
                .any(|k| k.contains("sha256:orphan_digest")),
            "digest manifest with no tag must be orphaned"
        );
        // Its exclusive blobs
        assert!(
            result.orphans.iter().any(|k| k.contains("dead_cfg")),
            "blob only referenced by orphaned digest manifest must be orphaned"
        );
        assert!(
            result.orphans.iter().any(|k| k.contains("dead_layer")),
            "blob only referenced by orphaned digest manifest must be orphaned"
        );
        // Live blobs must NOT be orphaned
        assert!(
            !result.orphans.iter().any(|k| k.contains("live_cfg")),
            "tag-referenced blob must be kept"
        );
        assert!(
            !result.orphans.iter().any(|k| k.contains("live_layer")),
            "tag-referenced blob must be kept"
        );
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

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
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

        storage
            .put("go/example.com/mod/@v/v1.0.0.info", b"{}")
            .await
            .unwrap();
        storage
            .put("go/example.com/mod/@v/v1.0.0.mod", b"module")
            .await
            .unwrap();
        storage
            .put("go/example.com/mod/@v/v1.0.0.zip", b"zip")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(
            result.orphaned, 0,
            "complete Go version should have no orphans"
        );
    }

    #[tokio::test]
    async fn test_gc_go_incomplete_version() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Only .mod — missing .info and .zip
        storage
            .put("go/example.com/mod/@v/v1.0.0.mod", b"module")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.orphaned, 1);
        assert!(result.orphan_keys[0].ends_with(".mod"));
    }

    #[tokio::test]
    async fn test_gc_cargo_matching_index_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("cargo/serde/1.0.0/serde-1.0.0.crate", b"crate")
            .await
            .unwrap();
        storage
            .put("cargo/index/se/rd/serde", b"index-data")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(
            result.orphaned, 0,
            "cargo with matching index should have no orphans"
        );
    }

    #[tokio::test]
    async fn test_gc_cargo_orphan_index_without_crate() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Index entry but no .crate file
        storage
            .put("cargo/index/se/rd/serde", b"index-data")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
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

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert_eq!(result.deleted, 1);
        assert_eq!(result.bytes_freed, 5); // "12345" = 5 bytes
    }

    // -- Metadata phantom tests --

    #[tokio::test]
    async fn test_gc_npm_no_phantoms() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // metadata + matching tarball
        let meta = serde_json::json!({
            "versions": {"1.0.0": {"name": "lodash"}},
            "time": {"1.0.0": "2024-01-15T10:30:00Z"}
        });
        storage
            .put(
                "npm/lodash/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("npm/lodash/tarballs/lodash-1.0.0.tgz", b"tarball")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.metadata_phantoms_removed, 0);
    }

    #[tokio::test]
    async fn test_gc_npm_phantom_detected_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // metadata references 1.0.0 and 2.0.0, but only 2.0.0 tarball exists
        let meta = serde_json::json!({
            "versions": {
                "1.0.0": {"name": "lodash"},
                "2.0.0": {"name": "lodash"}
            },
            "time": {
                "1.0.0": "2024-01-01T00:00:00Z",
                "2.0.0": "2024-06-01T00:00:00Z"
            }
        });
        storage
            .put(
                "npm/lodash/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("npm/lodash/tarballs/lodash-2.0.0.tgz", b"tarball")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.metadata_phantoms_removed, 1);

        // Dry run: metadata should be unchanged
        let data = storage.get("npm/lodash/metadata.json").await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(json["versions"]["1.0.0"].is_object()); // still there
    }

    #[tokio::test]
    async fn test_gc_npm_phantom_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let meta = serde_json::json!({
            "versions": {
                "1.0.0": {"name": "lodash"},
                "2.0.0": {"name": "lodash"}
            },
            "time": {
                "1.0.0": "2024-01-01T00:00:00Z",
                "2.0.0": "2024-06-01T00:00:00Z"
            }
        });
        storage
            .put(
                "npm/lodash/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("npm/lodash/tarballs/lodash-2.0.0.tgz", b"tarball")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert_eq!(result.metadata_phantoms_removed, 1);

        // Verify phantom was removed
        let data = storage.get("npm/lodash/metadata.json").await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(json["versions"]["1.0.0"].is_null());
        assert!(json["versions"]["2.0.0"].is_object());
        assert!(json["time"]["1.0.0"].is_null());
        assert!(json["time"]["2.0.0"].is_string());
    }

    #[tokio::test]
    async fn test_gc_pypi_no_phantoms() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let meta = serde_json::json!({
            "releases": {
                "1.0.0": [{"filename": "flask-1.0.0.tar.gz"}]
            }
        });
        storage
            .put(
                "pypi/flask/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("pypi/flask/flask-1.0.0.tar.gz", b"package")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(result.metadata_phantoms_removed, 0);
    }

    #[tokio::test]
    async fn test_gc_pypi_phantom_detected() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let meta = serde_json::json!({
            "releases": {
                "1.0.0": [{"filename": "flask-1.0.0.tar.gz"}],
                "2.0.0": [{"filename": "flask-2.0.0.tar.gz"}]
            }
        });
        storage
            .put(
                "pypi/flask/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        // Only 2.0.0 tarball exists
        storage
            .put("pypi/flask/flask-2.0.0.tar.gz", b"package")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert_eq!(result.metadata_phantoms_removed, 1);

        // Verify phantom was removed
        let data = storage.get("pypi/flask/metadata.json").await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(json["releases"]["1.0.0"].is_null());
        assert!(json["releases"]["2.0.0"].is_array());
    }

    #[tokio::test]
    async fn test_gc_mixed_orphans_and_phantoms() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Docker: 1 orphan blob
        let manifest = serde_json::json!({
            "config": {"digest": "sha256:cfg1"},
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
            .put("docker/app/blobs/sha256:cfg1", b"config")
            .await
            .unwrap();
        storage
            .put("docker/app/blobs/sha256:stale", b"old")
            .await
            .unwrap();

        // npm: 1 phantom version
        let meta = serde_json::json!({
            "versions": {"1.0.0": {}, "2.0.0": {}},
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "2.0.0": "2024-06-01T00:00:00Z"}
        });
        storage
            .put(
                "npm/test-pkg/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("npm/test-pkg/tarballs/test-pkg-2.0.0.tgz", b"tarball")
            .await
            .unwrap();

        let result = run_gc(&storage, &test_publish_locks(), false, 0, false, 0).await;
        assert_eq!(result.orphaned, 1); // docker blob
        assert_eq!(result.deleted, 1);
        assert_eq!(result.metadata_phantoms_removed, 1); // npm phantom
    }

    /// npm phantom cleanup must be skipped when npm is in proxy mode (#925).
    /// Proxy metadata is upstream-authoritative; missing local tarballs are
    /// expected (on-demand caching), not orphan signals.
    #[tokio::test]
    async fn test_gc_npm_proxy_skips_phantom_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // npm metadata with 2 versions, but only 1 tarball — a "phantom" in
        // hosted mode, but legitimate in proxy mode.
        let meta = serde_json::json!({
            "versions": {"1.0.0": {}, "2.0.0": {}},
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "2.0.0": "2024-06-01T00:00:00Z"}
        });
        storage
            .put(
                "npm/express/metadata.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .put("npm/express/tarballs/express-2.0.0.tgz", b"tarball")
            .await
            .unwrap();

        // Hosted mode: phantom is cleaned
        let hosted = run_gc(&storage, &test_publish_locks(), true, 0, false, 0).await;
        assert_eq!(
            hosted.metadata_phantoms_removed, 1,
            "hosted: phantom detected"
        );

        // Proxy mode: phantom cleanup is skipped entirely
        let proxy = run_gc(&storage, &test_publish_locks(), true, 0, true, 0).await;
        assert_eq!(
            proxy.metadata_phantoms_removed, 0,
            "proxy: npm phantom cleanup must be skipped"
        );
    }

    // -- #866: Proxy-cache eviction tests --

    /// Basic eviction: 5 proxy files at 100 bytes each = 500 bytes total.
    /// Cap = 300 → 2 oldest files evicted (freeing 200 bytes → 300 remaining).
    #[tokio::test]
    async fn test_evict_proxy_cache_basic() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let storage = Storage::new_local(data.to_str().unwrap());

        // Create 5 proxy files with staggered mtime
        let payload = vec![0u8; 100];
        for i in 0..5u32 {
            let key = format!("rpm/repo/Packages/{}-1.0.rpm", i);
            storage.put(&key, &payload).await.unwrap();
            // Set mtime: file 0 is oldest, file 4 is newest
            let mtime = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000_000 + u64::from(i) * 1000);
            std::fs::File::options()
                .write(true)
                .open(data.join(&key))
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        }

        let result = evict_proxy_cache(&storage, &test_publish_locks(), 300, false).await;
        assert_eq!(result.total_bytes, 500);
        assert_eq!(result.evicted_files, 2, "2 oldest files evicted");
        assert_eq!(result.bytes_freed, 200);

        // Files 0 and 1 (oldest) should be gone
        assert!(storage.get("rpm/repo/Packages/0-1.0.rpm").await.is_err());
        assert!(storage.get("rpm/repo/Packages/1-1.0.rpm").await.is_err());
        // Files 2-4 still present
        assert!(storage.get("rpm/repo/Packages/2-1.0.rpm").await.is_ok());
        assert!(storage.get("rpm/repo/Packages/3-1.0.rpm").await.is_ok());
        assert!(storage.get("rpm/repo/Packages/4-1.0.rpm").await.is_ok());
    }

    /// Files WITH .nora-meta/ sidecars (hosted packages) must never be evicted.
    #[tokio::test]
    async fn test_evict_proxy_cache_skips_hosted() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let payload = vec![0u8; 200];
        // Hosted package (has sidecar)
        storage
            .put("rpm/myrepo/Packages/hosted-1.0.rpm", &payload)
            .await
            .unwrap();
        storage
            .put("rpm/myrepo/.nora-meta/Packages/hosted-1.0.rpm.json", b"{}")
            .await
            .unwrap();
        // Proxy package (no sidecar)
        storage
            .put("rpm/myrepo/Packages/proxy-1.0.rpm", &payload)
            .await
            .unwrap();

        // Cap = 100 → only proxy file can be evicted
        let result = evict_proxy_cache(&storage, &test_publish_locks(), 100, false).await;
        assert_eq!(result.evicted_files, 1);
        // Hosted file must survive
        assert!(storage
            .get("rpm/myrepo/Packages/hosted-1.0.rpm")
            .await
            .is_ok());
        // Proxy file evicted
        assert!(storage
            .get("rpm/myrepo/Packages/proxy-1.0.rpm")
            .await
            .is_err());
    }

    /// cap=0 means eviction is disabled — nothing evicted regardless of size.
    #[tokio::test]
    async fn test_evict_proxy_cache_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("rpm/repo/Packages/big-1.0.rpm", &vec![0u8; 1000])
            .await
            .unwrap();

        let result = evict_proxy_cache(&storage, &test_publish_locks(), 0, false).await;
        assert_eq!(result.evicted_files, 0);
        assert_eq!(result.total_bytes, 0); // disabled returns immediately
        assert!(storage.get("rpm/repo/Packages/big-1.0.rpm").await.is_ok());
    }

    /// Index files (repodata/repomd.xml, Packages, Release) must never be evicted.
    #[tokio::test]
    async fn test_evict_proxy_cache_skips_index_files() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let payload = vec![0u8; 100];
        // Index files
        storage
            .put("rpm/repo/repodata/repomd.xml", &payload)
            .await
            .unwrap();
        storage
            .put("deb/repo/dists/stable/main/binary-amd64/Packages", &payload)
            .await
            .unwrap();
        storage
            .put("deb/repo/dists/stable/Release", &payload)
            .await
            .unwrap();
        storage
            .put("deb/repo/dists/stable/InRelease", &payload)
            .await
            .unwrap();
        // One real proxy package
        storage
            .put("rpm/repo/Packages/evictme-1.0.rpm", &payload)
            .await
            .unwrap();

        // Cap = 1 → aggressive, but index files must be immune
        let result = evict_proxy_cache(&storage, &test_publish_locks(), 1, false).await;
        assert_eq!(
            result.evicted_files, 1,
            "only the non-index proxy file evicted"
        );
        assert!(storage.get("rpm/repo/repodata/repomd.xml").await.is_ok());
        assert!(storage
            .get("deb/repo/dists/stable/main/binary-amd64/Packages")
            .await
            .is_ok());
        assert!(storage.get("deb/repo/dists/stable/Release").await.is_ok());
        assert!(storage.get("deb/repo/dists/stable/InRelease").await.is_ok());
    }

    /// Both rpm/ and deb/ proxy files count toward the same cap.
    #[tokio::test]
    async fn test_evict_proxy_cache_mixed_rpm_deb() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let storage = Storage::new_local(data.to_str().unwrap());

        let payload = vec![0u8; 100];
        // 2 rpm + 2 deb = 400 bytes total
        for (i, prefix) in ["rpm", "deb", "rpm", "deb"].iter().enumerate() {
            let key = format!("{}/repo/Packages/pkg{}-1.0.pkg", prefix, i);
            storage.put(&key, &payload).await.unwrap();
            let mtime = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_000_000 + i as u64 * 1000);
            std::fs::File::options()
                .write(true)
                .open(data.join(&key))
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        }

        // Cap = 200 → evict 2 oldest (200 bytes freed)
        let result = evict_proxy_cache(&storage, &test_publish_locks(), 200, false).await;
        assert_eq!(result.total_bytes, 400);
        assert_eq!(result.evicted_files, 2);
        assert_eq!(result.bytes_freed, 200);
    }
}
