//! Retention policies — keep_last, age-based, tag exclusion.
//!
//! Pure `plan_deletions` function determines what to delete.
//! CLI commands: `nora retention plan` (dry-run) and `nora retention apply`.
//!
//! Retention is per-registry and operates on "versions" (Maven versions,
//! Docker tags, npm tarballs, PyPI files, Cargo versions, Go modules).

use std::sync::{Arc, LazyLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};
use tracing::info;

use crate::config::RetentionRule;
use crate::storage::Storage;
use crate::validation::ends_with_ci;
use crate::PublishLocks;

// ============================================================================
// Prometheus metrics
// ============================================================================

pub static RETENTION_VERSIONS_DELETED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_retention_versions_deleted_total",
        "Total versions removed by retention policies"
    )
    .expect("retention_versions_deleted metric")
});

pub static RETENTION_BYTES_FREED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_retention_bytes_freed_total",
        "Total bytes freed by retention policies"
    )
    .expect("retention_bytes_freed metric")
});

pub static RETENTION_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "nora_retention_duration_seconds",
        "Duration of retention runs in seconds",
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0]
    )
    .expect("retention_duration metric")
});

pub static RETENTION_LAST_RUN: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_retention_last_run_timestamp",
        "Unix timestamp of last retention run"
    )
    .expect("retention_last_run metric")
});

// ============================================================================
// Retention planner (pure function)
// ============================================================================

/// An artifact version with metadata, used for retention planning.
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// Human-readable version/tag name (e.g., "1.0.0", "latest", "lodash-4.17.21.tgz")
    pub name: String,
    /// Storage keys belonging to this version (primary + checksums + metadata)
    pub keys: Vec<String>,
    /// Last modified timestamp (unix seconds) — max of all keys
    pub modified: u64,
    /// Total size in bytes across all keys
    pub size: u64,
}

/// A planned deletion with reason.
#[derive(Debug, Clone)]
pub struct DeletionPlan {
    pub version_name: String,
    pub keys: Vec<String>,
    pub size: u64,
    pub reason: String,
}

/// Plan which versions to delete based on retention rules.
///
/// This is a **pure function** — no I/O, no side effects. Easy to test.
///
/// Rules applied as AND:
/// - `keep_last`: keep the N most recent versions (by modified time)
/// - `older_than_days`: only delete versions older than X days
/// - `exclude_tags`: glob patterns that protect versions from deletion
///
/// A version is deleted only if ALL conditions agree it should go.
pub fn plan_deletions(
    mut versions: Vec<VersionEntry>,
    rule: &RetentionRule,
    now_secs: u64,
) -> Vec<DeletionPlan> {
    if versions.is_empty() {
        return vec![];
    }

    // Sort by modified descending (newest first), then by name descending as tiebreaker
    versions.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| cmp_version_names(&b.name, &a.name))
    });

    let mut deletions = Vec::new();

    for (i, version) in versions.iter().enumerate() {
        // Check exclusion patterns
        if is_excluded(&version.name, &rule.exclude_tags) {
            continue;
        }

        let mut dominated = false;
        let mut reason_parts = Vec::new();

        // keep_last: versions beyond the Nth newest are candidates
        if let Some(keep_last) = rule.keep_last {
            if i >= keep_last as usize {
                dominated = true;
                reason_parts.push(format!("beyond keep_last={}", keep_last));
            }
        }

        // older_than_days: versions older than threshold are candidates
        if let Some(days) = rule.older_than_days {
            let threshold = now_secs.saturating_sub(days as u64 * 86400);
            if version.modified < threshold {
                if rule.keep_last.is_none() {
                    // If no keep_last, age alone is sufficient
                    dominated = true;
                }
                reason_parts.push(format!("older than {} days", days));
            } else if rule.keep_last.is_some() {
                // If keep_last is set and version is NOT old enough, don't delete
                // (AND logic: both conditions must agree)
                dominated = false;
                reason_parts.clear();
            }
        }

        if dominated {
            deletions.push(DeletionPlan {
                version_name: version.name.clone(),
                keys: version.keys.clone(),
                size: version.size,
                reason: reason_parts.join(", "),
            });
        }
    }

    deletions
}

/// Compare version-ish names the way version schemes expect: digit runs
/// compare numerically (`"1.10" > "1.9"`) and `~` sorts before anything,
/// including end-of-string (`"1.0~rc1" < "1.0"`, as in Debian versions).
/// Only the mtime tiebreaker in [`plan_deletions`] — bulk-imported sidecars
/// often share one mtime, and a lexical tiebreak would evict `1.10` in
/// favour of `1.9`.
fn cmp_version_names(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    fn take_digits<'s>(s: &'s [u8], i: &mut usize) -> &'s [u8] {
        let start = *i;
        while *i < s.len() && s[*i].is_ascii_digit() {
            *i += 1;
        }
        // Numeric comparison: strip leading zeros.
        let run = &s[start..*i];
        let nz = run.iter().position(|c| *c != b'0').unwrap_or(run.len());
        &run[nz..]
    }
    // '~' < end-of-string/digit-run < everything else.
    fn rank(c: Option<&u8>) -> u16 {
        match c {
            Some(b'~') => 0,
            None => 1,
            Some(&c) => 2 + c as u16,
        }
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    loop {
        // Non-digit run, byte by byte.
        loop {
            let ca = a.get(i).filter(|c| !c.is_ascii_digit());
            let cb = b.get(j).filter(|c| !c.is_ascii_digit());
            match rank(ca).cmp(&rank(cb)) {
                Ordering::Equal if ca.is_none() => break,
                Ordering::Equal => {
                    i += 1;
                    j += 1;
                }
                other => return other,
            }
        }
        if i >= a.len() && j >= b.len() {
            return Ordering::Equal;
        }
        let (da, db) = (take_digits(a, &mut i), take_digits(b, &mut j));
        match da.len().cmp(&db.len()).then_with(|| da.cmp(db)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
}

/// Check if a version name matches any exclusion glob pattern.
fn is_excluded(name: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if glob_match(pattern, name) {
            return true;
        }
    }
    false
}

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
/// No path separators — flat matching only.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            // Try consuming 0 chars from text, or 1+ chars
            glob_match_inner(&p[1..], t) || (!t.is_empty() && glob_match_inner(p, &t[1..]))
        }
        (Some('?'), Some(_)) => glob_match_inner(&p[1..], &t[1..]),
        (Some(pc), Some(tc)) if pc == tc => glob_match_inner(&p[1..], &t[1..]),
        _ => false,
    }
}

// ============================================================================
// Version collectors (per-registry)
// ============================================================================

/// Collect Maven versions for a given group/artifact.
async fn collect_maven_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("maven/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list maven/ keys: {}", e);
        Vec::new()
    });
    let mut artifacts: std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<String>>,
    > = std::collections::HashMap::new();

    for key in &all_keys {
        let parts: Vec<&str> = key
            .strip_prefix("maven/")
            .unwrap_or("")
            .split('/')
            .collect();
        // maven/{group...}/{artifact}/{version}/{file}
        // Minimum: maven/g/a/v/f = 4+ segments after maven/
        if parts.len() < 4 {
            continue;
        }
        // Skip maven-metadata.xml at artifact level
        if parts[parts.len() - 1].starts_with("maven-metadata") {
            continue;
        }
        let version = parts[parts.len() - 2];
        let artifact_path = parts[..parts.len() - 2].join("/");
        artifacts
            .entry(artifact_path)
            .or_default()
            .entry(version.to_string())
            .or_default()
            .push(key.clone());
    }

    let mut result = Vec::new();
    for (artifact, versions) in &artifacts {
        let mut entries = Vec::new();
        for (version, keys) in versions {
            let (modified, size) = aggregate_meta(storage, keys).await;
            entries.push(VersionEntry {
                name: version.clone(),
                keys: keys.clone(),
                modified,
                size,
            });
        }
        result.push((format!("maven:{}", artifact), entries));
    }
    result
}

/// Collect rpm package versions per repository from the metadata sidecars
/// (never the .rpm payloads). Group = `rpm:{repo}/{package-name}`; each
/// version's keys are the package file and its sidecar. Deleting a version
/// therefore requires the post-delete index regeneration in `run_retention`.
async fn collect_rpm_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "rpm", |v| {
        let s = |f: &str| v.get(f).and_then(|x| x.as_str()).unwrap_or("").to_string();
        SidecarVersion {
            package: s("name"),
            version: format!("{}-{}.{}", s("version"), s("release"), s("arch")),
            href: s("href"),
            size: v.get("size_package").and_then(|x| x.as_u64()).unwrap_or(0),
            modified: v.get("file_time").and_then(|x| x.as_u64()),
            placement: None,
        }
    })
    .await
}

/// Collect deb package versions per repository — deb counterpart of
/// [`collect_rpm_versions`], same keys/regeneration contract. Structured
/// packages group per placement (`deb:{repo}/{dist}/{component}/{package}`),
/// matching how `regenerate_indexes` rebuilds one index per distribution;
/// flat-root packages group as `deb:{repo}/{package}`.
async fn collect_deb_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "deb", |v| {
        let s = |f: &str| v.get(f).and_then(|x| x.as_str()).unwrap_or("").to_string();
        SidecarVersion {
            package: s("package"),
            version: format!("{}_{}", s("version"), s("arch")),
            href: s("filename"),
            size: v.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
            modified: None, // deb sidecars carry no upload time; use sidecar mtime
            placement: v.get("placement").and_then(|p| {
                let d = p.get("distribution")?.as_str()?;
                let c = p.get("component")?.as_str()?;
                Some(format!("{d}/{c}"))
            }),
        }
    })
    .await
}

struct SidecarVersion {
    package: String,
    version: String,
    href: String,
    size: u64,
    modified: Option<u64>,
    /// `{distribution}/{component}` for structured-layout deb sidecars.
    /// Each distribution is an independent APT index, so retention must
    /// scope `keep_last` per distribution — pooling them would evict a
    /// distribution's only version whenever a sibling distribution holds a
    /// newer one. None = the repo's flat root scope.
    placement: Option<String>,
}

async fn collect_sidecar_versions(
    storage: &Storage,
    registry: &str,
    parse: impl Fn(&serde_json::Value) -> SidecarVersion,
) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage
        .list(&format!("{registry}/"))
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to list {registry}/ keys: {}", e);
            Vec::new()
        });

    let mut groups: std::collections::HashMap<String, Vec<VersionEntry>> =
        std::collections::HashMap::new();
    for key in &all_keys {
        // {registry}/{repo}/.nora-meta/{path}.json
        let Some(rest) = key.strip_prefix(&format!("{registry}/")) else {
            continue;
        };
        let Some((repo, meta_rest)) = rest.split_once("/.nora-meta/") else {
            continue;
        };
        let Some(pkg_path) = meta_rest.strip_suffix(".json") else {
            continue;
        };
        let Ok(data) = storage.get(key).await else {
            tracing::warn!(key = %key, "retention: sidecar unreadable — version skipped (kept)");
            continue;
        };
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) else {
            tracing::warn!(key = %key, "retention: sidecar unparsable — version skipped (kept)");
            continue;
        };
        let sv = parse(&json);
        if sv.package.is_empty() || sv.href != pkg_path {
            // href/path divergence means the sidecar does not describe this
            // package file — leave it for `-/reindex` to reconcile.
            tracing::warn!(key = %key, "retention: sidecar/package mismatch — version skipped (kept)");
            continue;
        }
        let package_key = format!("{registry}/{repo}/{pkg_path}");
        let modified = match sv.modified {
            Some(m) => m,
            None => storage.stat(key).await.map(|m| m.modified).unwrap_or(0),
        };
        let group = match &sv.placement {
            Some(placement) => format!("{registry}:{repo}/{placement}/{}", sv.package),
            None => format!("{registry}:{repo}/{}", sv.package),
        };
        groups
            .entry(group)
            .or_default()
            .push(VersionEntry {
                name: sv.version,
                keys: vec![package_key, key.clone()],
                modified,
                size: sv.size,
            });
    }
    groups.into_iter().collect()
}

/// Collect raw "versions" as depth-2 path prefixes: `raw/{top}/{version}/…`
/// groups under `raw:{top}` with every key below the prefix belonging to the
/// version — a directory of related files ages out as one unit. A file
/// directly under `raw/{top}/` is its own single-key version. Keys at the
/// root of `raw/` have no grouping and are never collected (never deleted).
async fn collect_raw_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let keys = match storage.list_with_meta("raw/").await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to list raw/ keys: {}", e);
            return Vec::new();
        }
    };

    // group -> version -> (keys, max_mtime, total_size)
    let mut groups: std::collections::HashMap<
        String,
        std::collections::HashMap<String, (Vec<String>, u64, u64)>,
    > = std::collections::HashMap::new();
    for (key, meta) in &keys {
        let Some(rest) = key.strip_prefix("raw/") else {
            continue;
        };
        let mut segs = rest.splitn(3, '/');
        let (Some(top), Some(second)) = (segs.next(), segs.next()) else {
            continue; // file at raw/ root: ungrouped, never collected
        };
        let entry = groups
            .entry(format!("raw:{top}"))
            .or_default()
            .entry(second.to_string())
            .or_insert((Vec::new(), 0, 0));
        entry.0.push(key.clone());
        entry.1 = entry.1.max(meta.modified);
        entry.2 += meta.size;
    }

    groups
        .into_iter()
        .map(|(group, versions)| {
            (
                group,
                versions
                    .into_iter()
                    .map(|(name, (keys, modified, size))| VersionEntry {
                        name,
                        keys,
                        modified,
                        size,
                    })
                    .collect(),
            )
        })
        .collect()
}

/// Collect Docker tags for each repository.
async fn collect_docker_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("docker/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list docker/ keys: {}", e);
        Vec::new()
    });
    let mut repos: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        // docker/{repo}/manifests/{tag}.json
        if let Some(rest) = key.strip_prefix("docker/") {
            if let Some(idx) = rest.find("/manifests/") {
                let repo = &rest[..idx];
                let tag_file = &rest[idx + "/manifests/".len()..];
                if ends_with_ci(tag_file, ".json") && !ends_with_ci(tag_file, ".meta.json") {
                    let tag = tag_file.strip_suffix(".json").unwrap_or(tag_file);
                    repos
                        .entry(repo.to_string())
                        .or_default()
                        .push((tag.to_string(), key.clone()));
                }
            }
        }
    }

    let mut result = Vec::new();
    for (repo, tags) in &repos {
        let mut entries = Vec::new();
        for (tag, manifest_key) in tags {
            let meta = storage.stat(manifest_key).await;
            let modified = meta.as_ref().map(|m| m.modified).unwrap_or(0);
            let size = meta.as_ref().map(|m| m.size).unwrap_or(0);
            // Note: we don't include blob keys here because blobs may be
            // shared across tags. GC handles orphan blobs separately.
            entries.push(VersionEntry {
                name: tag.clone(),
                keys: vec![manifest_key.clone()],
                modified,
                size,
            });
        }
        result.push((format!("docker:{}", repo), entries));
    }
    result
}

/// Collect npm package versions.
async fn collect_npm_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("npm/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list npm/ keys: {}", e);
        Vec::new()
    });
    let mut packages: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        // npm/{package}/tarballs/{file} — each tarball is a "version"
        // Skip metadata.json and checksum files — they are indexes, not versions.
        if let Some(rest) = key.strip_prefix("npm/") {
            if rest.contains("/tarballs/")
                && !ends_with_ci(key, ".sha256")
                && !ends_with_ci(key, "/metadata.json")
            {
                let pkg = rest.split("/tarballs/").next().unwrap_or("");
                if !pkg.is_empty() {
                    packages
                        .entry(pkg.to_string())
                        .or_default()
                        .push(key.clone());
                }
            }
        }
    }

    let mut result = Vec::new();
    for (pkg, tarball_keys) in &packages {
        let mut entries = Vec::new();
        for key in tarball_keys {
            let filename = key.rsplit('/').next().unwrap_or("");
            let (modified, size) = aggregate_meta(storage, std::slice::from_ref(key)).await;
            // Include associated .sha256
            let mut keys = vec![key.clone()];
            let hash_key = format!("{}.sha256", key);
            if storage.stat(&hash_key).await.is_some() {
                keys.push(hash_key);
            }
            entries.push(VersionEntry {
                name: filename.to_string(),
                keys,
                modified,
                size,
            });
        }
        result.push((format!("npm:{}", pkg), entries));
    }
    result
}

/// Collect PyPI package files.
async fn collect_pypi_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("pypi/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list pypi/ keys: {}", e);
        Vec::new()
    });
    let mut packages: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        if let Some(rest) = key.strip_prefix("pypi/") {
            // Skip checksums and metadata.json — metadata is the package index,
            // not a version artifact. Deleting it makes the package undiscoverable.
            if !ends_with_ci(key, ".sha256")
                && !ends_with_ci(key, ".sha1")
                && !ends_with_ci(key, ".md5")
                && !ends_with_ci(key, ".sha512")
                && !ends_with_ci(key, "/metadata.json")
            {
                let pkg = rest.split('/').next().unwrap_or("");
                if !pkg.is_empty() {
                    packages
                        .entry(pkg.to_string())
                        .or_default()
                        .push(key.clone());
                }
            }
        }
    }

    let mut result = Vec::new();
    for (pkg, file_keys) in &packages {
        let mut entries = Vec::new();
        for key in file_keys {
            let filename = key.rsplit('/').next().unwrap_or("");
            let (modified, size) = aggregate_meta(storage, std::slice::from_ref(key)).await;
            let mut keys = vec![key.clone()];
            let hash_key = format!("{}.sha256", key);
            if storage.stat(&hash_key).await.is_some() {
                keys.push(hash_key);
            }
            entries.push(VersionEntry {
                name: filename.to_string(),
                keys,
                modified,
                size,
            });
        }
        result.push((format!("pypi:{}", pkg), entries));
    }
    result
}

/// Collect Cargo crate versions.
async fn collect_cargo_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("cargo/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list cargo/ keys: {}", e);
        Vec::new()
    });
    let mut crates: std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<String>>,
    > = std::collections::HashMap::new();

    for key in &all_keys {
        // cargo/{crate}/{version}/{crate}-{version}.crate
        // Also: cargo/{crate}/metadata.json, cargo/index/...
        if let Some(rest) = key.strip_prefix("cargo/") {
            if rest.starts_with("index/") {
                continue; // Skip sparse index
            }
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 3 {
                let crate_name = parts[0];
                let version = parts[1];
                if crate_name != "index" && version != "metadata.json" {
                    crates
                        .entry(crate_name.to_string())
                        .or_default()
                        .entry(version.to_string())
                        .or_default()
                        .push(key.clone());
                }
            }
        }
    }

    let mut result = Vec::new();
    for (crate_name, versions) in &crates {
        let mut entries = Vec::new();
        for (version, keys) in versions {
            let (modified, size) = aggregate_meta(storage, keys).await;
            entries.push(VersionEntry {
                name: version.clone(),
                keys: keys.clone(),
                modified,
                size,
            });
        }
        result.push((format!("cargo:{}", crate_name), entries));
    }
    result
}

async fn collect_go_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("go/").await.unwrap_or_else(|e| {
        tracing::error!("Failed to list go/ keys: {}", e);
        Vec::new()
    });
    let mut modules: std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<String>>,
    > = std::collections::HashMap::new();

    for key in &all_keys {
        // go/{module}/@v/{version}.{info|mod|zip}
        if let Some(at_v_pos) = key.find("/@v/") {
            let module = &key["go/".len()..at_v_pos];
            let file = &key[at_v_pos + 4..]; // after "/@v/"
                                             // Extract version: "v1.0.0.info" → "v1.0.0"
            let version = file
                .strip_suffix(".info")
                .or_else(|| file.strip_suffix(".mod"))
                .or_else(|| file.strip_suffix(".zip"));
            if let Some(ver) = version {
                modules
                    .entry(module.to_string())
                    .or_default()
                    .entry(ver.to_string())
                    .or_default()
                    .push(key.clone());
            }
        }
    }

    let mut result = Vec::new();
    for (module, versions) in &modules {
        let mut entries = Vec::new();
        for (version, keys) in versions {
            let (modified, size) = aggregate_meta(storage, keys).await;
            entries.push(VersionEntry {
                name: version.clone(),
                keys: keys.clone(),
                modified,
                size,
            });
        }
        result.push((format!("go:{}", module), entries));
    }
    result
}

/// Get max modified time and total size across keys.
async fn aggregate_meta(storage: &Storage, keys: &[String]) -> (u64, u64) {
    let mut max_modified = 0u64;
    let mut total_size = 0u64;
    for key in keys {
        if let Some(meta) = storage.stat(key).await {
            max_modified = max_modified.max(meta.modified);
            total_size += meta.size;
        }
    }
    (max_modified, total_size)
}

// ============================================================================
// Retention execution
// ============================================================================

/// Result of a retention run.
pub struct RetentionResult {
    pub planned: usize,
    pub deleted_keys: usize,
    pub bytes_freed: u64,
    pub duration_secs: f64,
    pub plans: Vec<(String, Vec<DeletionPlan>)>,
}

/// Run retention across all registries.
///
/// `publish_locks` serializes deletions with concurrent publish operations
/// to prevent race conditions (e.g., deleting a blob while a manifest
/// referencing it is being written).
pub async fn run_retention(
    storage: &Storage,
    publish_locks: &PublishLocks,
    signer: Option<&crate::signing::RepoSigner>,
    rules: &[RetentionRule],
    dry_run: bool,
) -> RetentionResult {
    let start = Instant::now();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Collect versions from all registries
    let mut all_groups: Vec<(String, Vec<VersionEntry>)> = Vec::new();
    all_groups.extend(collect_maven_versions(storage).await);
    all_groups.extend(collect_docker_versions(storage).await);
    all_groups.extend(collect_npm_versions(storage).await);
    all_groups.extend(collect_pypi_versions(storage).await);
    all_groups.extend(collect_cargo_versions(storage).await);
    all_groups.extend(collect_go_versions(storage).await);
    all_groups.extend(collect_rpm_versions(storage).await);
    all_groups.extend(collect_deb_versions(storage).await);
    all_groups.extend(collect_raw_versions(storage).await);

    let mut all_plans: Vec<(String, Vec<DeletionPlan>)> = Vec::new();
    let mut total_planned = 0usize;
    let mut total_deleted_keys = 0usize;
    let mut total_bytes = 0u64;
    // rpm/deb repos whose packages were deleted — their indexes must be
    // rebuilt (and re-signed) afterwards or they keep advertising ghosts.
    let mut regen: std::collections::BTreeSet<(&'static str, String)> =
        std::collections::BTreeSet::new();

    for (group_name, versions) in all_groups {
        // Find matching rule for this group
        let registry = group_name.split(':').next().unwrap_or("");
        let rule = match find_matching_rule(rules, registry, &group_name) {
            Some(r) => r,
            None => continue,
        };

        let plans = plan_deletions(versions, rule, now);
        if plans.is_empty() {
            continue;
        }

        total_planned += plans.len();

        if !dry_run {
            if let Some(repo) = group_name
                .strip_prefix("rpm:")
                .map(|n| ("rpm", n))
                .or_else(|| group_name.strip_prefix("deb:").map(|n| ("deb", n)))
                .and_then(|(fmt, n)| n.split('/').next().map(|r| (fmt, r.to_string())))
            {
                regen.insert((
                    if group_name.starts_with("rpm:") {
                        "rpm"
                    } else {
                        "deb"
                    },
                    repo.1,
                ));
            }
            for plan in &plans {
                for key in &plan.keys {
                    // Serialize with concurrent publish to prevent deleting
                    // an artifact that is being referenced by a new publish.
                    let lock = crate::acquire_publish_lock(publish_locks, key);
                    let _guard = lock.lock().await;
                    if storage.delete(key).await.is_ok() {
                        total_deleted_keys += 1;
                    }
                }
                total_bytes += plan.size;
                info!(
                    group = %group_name,
                    version = %plan.version_name,
                    reason = %plan.reason,
                    "Retention: deleted"
                );
            }
        } else {
            for plan in &plans {
                total_bytes += plan.size;
                info!(
                    group = %group_name,
                    version = %plan.version_name,
                    keys = plan.keys.len(),
                    reason = %plan.reason,
                    "[dry-run] Retention: would delete"
                );
            }
        }

        all_plans.push((group_name, plans));
    }

    // Rebuild + re-sign the indexes of every rpm/deb repo retention touched,
    // under the same per-repo publish lock the handlers use. Fail-open per
    // repo: a failed rebuild logs loudly and the next publish/reindex heals
    // it; the deletions themselves are already durable.
    for (fmt, repo) in &regen {
        let lock_key = match *fmt {
            "rpm" => format!("rpm/{repo}/repodata/repomd.xml"),
            _ => format!("deb/{repo}/Release"),
        };
        let lock = crate::acquire_publish_lock(publish_locks, &lock_key);
        let _guard = lock.lock().await;
        let result = match *fmt {
            "rpm" => crate::registry::rpm::regenerate_repodata(storage, signer, repo).await,
            _ => crate::registry::deb::regenerate_indexes(storage, signer, repo).await,
        };
        if let Err(e) = result {
            tracing::error!(registry = %fmt, repo = %repo, error = %e, "retention: index regeneration failed — run -/reindex to heal");
        } else {
            info!(registry = %fmt, repo = %repo, "retention: indexes regenerated");
        }
    }

    let duration = start.elapsed().as_secs_f64();
    RETENTION_DURATION.observe(duration);
    RETENTION_LAST_RUN.set(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    );

    if !dry_run {
        RETENTION_VERSIONS_DELETED.inc_by(total_planned as u64);
        RETENTION_BYTES_FREED.inc_by(total_bytes);
        if total_planned > 0 {
            info!(
                versions = total_planned,
                keys = total_deleted_keys,
                bytes_freed = total_bytes,
                "Retention complete"
            );
        }
    }

    RetentionResult {
        planned: total_planned,
        deleted_keys: total_deleted_keys,
        bytes_freed: total_bytes,
        duration_secs: duration,
        plans: all_plans,
    }
}

/// Find the first matching retention rule for a registry/group.
fn find_matching_rule<'a>(
    rules: &'a [RetentionRule],
    registry: &str,
    group_name: &str,
) -> Option<&'a RetentionRule> {
    // First rule whose registry matches (or "*") AND whose name_glob (if any)
    // matches the group's name within the registry.
    let name = group_name
        .split_once(':')
        .map(|(_, n)| n)
        .unwrap_or(group_name);
    rules.iter().find(|r| {
        (r.registry == registry || r.registry == "*")
            && r.name_glob.as_deref().is_none_or(|g| glob_match(g, name))
    })
}

// ============================================================================
// Background scheduler
// ============================================================================

/// Spawn a background retention task that runs periodically.
/// Accepts a shared cleanup lock to prevent concurrent runs with GC scheduler.
/// Returns a `JoinHandle` so the caller can await graceful completion on shutdown.
#[allow(clippy::too_many_arguments)]
pub fn spawn_retention_scheduler(
    storage: Storage,
    publish_locks: PublishLocks,
    signer: Option<Arc<crate::signing::RepoSigner>>,
    rules: Vec<RetentionRule>,
    interval_secs: u64,
    dry_run: bool,
    audit: Option<Arc<crate::audit::AuditLog>>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // First tick fires immediately — skip it so retention doesn't run on startup
        interval.tick().await;

        loop {
            // CANCEL-SAFETY: Same as GC — interval.tick() is stateless between polls,
            // cancel.cancelled() is a CancellationToken. Retention work runs to
            // completion within each tick iteration, no partial state on drop.
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Retention scheduler: cancellation requested, stopping");
                    break;
                }
                _ = interval.tick() => {}
            }

            if cancel.is_cancelled() {
                break;
            }

            // Cross-scheduler lock: skip if GC or retention is already running
            let guard = cleanup_lock.try_lock();
            if guard.is_err() {
                info!("Retention: cleanup lock held (GC or retention running), skipping");
                continue;
            }

            info!(
                dry_run = dry_run,
                "Retention scheduler: starting periodic run"
            );
            let result =
                run_retention(&storage, &publish_locks, signer.as_deref(), &rules, dry_run).await;
            info!(
                "Retention scheduler: done in {:.1}s — {} versions, {} keys, {} bytes freed",
                result.duration_secs, result.planned, result.deleted_keys, result.bytes_freed
            );

            if let Some(ref audit_log) = audit {
                if result.planned > 0 {
                    audit_log.log(crate::audit::AuditEntry::new(
                        "retention-apply",
                        "scheduler",
                        &format!("{} versions", result.planned),
                        "*",
                        &format!(
                            "keys={} bytes_freed={} duration={:.1}s",
                            result.deleted_keys, result.bytes_freed, result.duration_secs
                        ),
                    ));
                }
            }

            drop(guard);
        }
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_publish_locks() -> PublishLocks {
        Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()))
    }

    fn make_rule(
        keep_last: Option<u32>,
        older_than_days: Option<u32>,
        exclude_tags: Vec<&str>,
    ) -> RetentionRule {
        RetentionRule {
            registry: "*".to_string(),
            name_glob: None,
            keep_last,
            older_than_days,
            exclude_tags: exclude_tags.into_iter().map(String::from).collect(),
        }
    }

    fn make_version(name: &str, modified: u64, size: u64) -> VersionEntry {
        VersionEntry {
            name: name.to_string(),
            keys: vec![format!("test/{}", name)],
            modified,
            size,
        }
    }

    const NOW: u64 = 1_776_000_000;
    const DAY: u64 = 86400;

    // -- Glob matching --

    #[test]
    fn test_glob_exact() {
        assert!(glob_match("latest", "latest"));
        assert!(!glob_match("latest", "latest2"));
    }

    #[test]
    fn test_glob_star() {
        assert!(glob_match("v*", "v1.0.0"));
        assert!(glob_match("v*", "v"));
        assert!(!glob_match("v*", "1.0.0"));
        assert!(glob_match("*-SNAPSHOT", "1.0.0-SNAPSHOT"));
        assert!(!glob_match("*-SNAPSHOT", "1.0.0"));
    }

    #[test]
    fn test_glob_question() {
        assert!(glob_match("v?.0", "v1.0"));
        assert!(!glob_match("v?.0", "v10.0"));
    }

    #[test]
    fn test_glob_complex() {
        assert!(glob_match("release-*", "release-1.0"));
        assert!(glob_match("release-*", "release-"));
        assert!(!glob_match("release-*", "dev-1.0"));
    }

    // -- plan_deletions --

    #[test]
    fn test_keep_last_basic() {
        let versions = vec![
            make_version("1.0", NOW - 3 * DAY, 100),
            make_version("2.0", NOW - 2 * DAY, 200),
            make_version("3.0", NOW - DAY, 300),
        ];
        let rule = make_rule(Some(2), None, vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.0");
    }

    #[test]
    fn test_keep_last_keeps_all_if_under_limit() {
        let versions = vec![
            make_version("1.0", NOW - DAY, 100),
            make_version("2.0", NOW, 200),
        ];
        let rule = make_rule(Some(5), None, vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert!(plans.is_empty());
    }

    #[test]
    fn test_older_than_days() {
        let versions = vec![
            make_version("old", NOW - 31 * DAY, 100),
            make_version("new", NOW - DAY, 200),
        ];
        let rule = make_rule(None, Some(30), vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "old");
    }

    #[test]
    fn test_keep_last_and_older_than() {
        // AND logic: both must agree
        let versions = vec![
            make_version("1.0", NOW - 60 * DAY, 100), // old + beyond keep_last
            make_version("2.0", NOW - 2 * DAY, 200),  // recent + beyond keep_last
            make_version("3.0", NOW - DAY, 300),      // newest, kept
        ];
        let rule = make_rule(Some(1), Some(30), vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        // 2.0 is beyond keep_last=1 but NOT older than 30 days → NOT deleted
        // 1.0 is beyond keep_last=1 AND older than 30 days → deleted
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.0");
    }

    #[test]
    fn test_exclude_tags() {
        let versions = vec![
            make_version("latest", NOW - 100 * DAY, 100),
            make_version("1.0", NOW - 100 * DAY, 200),
            make_version("2.0", NOW, 300),
        ];
        let rule = make_rule(Some(1), None, vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // "latest" excluded, "2.0" kept (newest), "1.0" deleted
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.0");
    }

    #[test]
    fn test_exclude_glob_pattern() {
        let versions = vec![
            make_version("release-1.0", NOW - 100 * DAY, 100),
            make_version("release-2.0", NOW - 50 * DAY, 200),
            make_version("dev-build", NOW - 100 * DAY, 300),
        ];
        let rule = make_rule(Some(1), None, vec!["release-*"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // Both release-* excluded, only dev-build is candidate (and it's beyond keep_last=1)
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "dev-build");
    }

    #[test]
    fn test_version_name_tiebreak_is_numeric_aware() {
        assert_eq!(
            cmp_version_names("1.10_amd64", "1.9_amd64"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            cmp_version_names("1.0~rc1", "1.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(cmp_version_names("2.0", "2.0"), std::cmp::Ordering::Equal);
        assert_eq!(
            cmp_version_names("1.2.3-4", "1.2.3-10"),
            std::cmp::Ordering::Less
        );

        // Tied mtimes (bulk-imported sidecars): the newer version survives.
        let versions = vec![
            make_version("1.9_amd64", NOW, 100),
            make_version("1.10_amd64", NOW, 100),
        ];
        let rule = make_rule(Some(1), None, vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.9_amd64");
    }

    #[test]
    fn test_empty_versions() {
        let rule = make_rule(Some(1), None, vec![]);
        let plans = plan_deletions(vec![], &rule, NOW);
        assert!(plans.is_empty());
    }

    #[test]
    fn test_deletion_reason_format() {
        let versions = vec![
            make_version("old", NOW - 100 * DAY, 100),
            make_version("new", NOW, 200),
        ];
        let rule = make_rule(Some(1), Some(30), vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].reason.contains("keep_last"));
        assert!(plans[0].reason.contains("older than"));
    }

    // -- Integration tests with storage --

    #[tokio::test]
    async fn test_retention_maven_keep_last() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Create 3 Maven versions (same mtime is fine — tiebreaker is name desc)
        storage
            .put("maven/com/example/lib/1.0/lib-1.0.jar", b"v1")
            .await
            .unwrap();
        storage
            .put("maven/com/example/lib/2.0/lib-2.0.jar", b"v2")
            .await
            .unwrap();
        storage
            .put("maven/com/example/lib/3.0/lib-3.0.jar", b"v3")
            .await
            .unwrap();

        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(result.planned, 2); // 1.0 and 2.0 deleted, 3.0 kept
        assert!(storage
            .get("maven/com/example/lib/3.0/lib-3.0.jar")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_retention_dry_run_preserves() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("maven/com/test/a/1.0/a.jar", b"data")
            .await
            .unwrap();
        storage
            .put("maven/com/test/a/2.0/a.jar", b"data")
            .await
            .unwrap();

        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, true).await;
        assert_eq!(result.planned, 1);
        assert_eq!(result.deleted_keys, 0); // dry run
                                            // Both still exist
        assert!(storage.get("maven/com/test/a/1.0/a.jar").await.is_ok());
        assert!(storage.get("maven/com/test/a/2.0/a.jar").await.is_ok());
    }

    #[tokio::test]
    async fn test_retention_no_matching_rule() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("maven/com/test/a/1.0/a.jar", b"data")
            .await
            .unwrap();

        // Rule for docker, not maven
        let rules = vec![RetentionRule {
            registry: "docker".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(result.planned, 0);
    }

    #[tokio::test]
    async fn test_retention_wildcard_rule() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        storage
            .put("maven/com/test/a/1.0/a.jar", b"data")
            .await
            .unwrap();
        storage
            .put("maven/com/test/a/2.0/a.jar", b"data")
            .await
            .unwrap();

        let rules = vec![RetentionRule {
            registry: "*".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        assert!(result.planned >= 1); // at least 1.0 deleted
    }

    #[tokio::test]
    async fn test_retention_go_keep_last() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // 3 Go module versions with .info, .mod, .zip each
        for ver in &["v1.0.0", "v2.0.0", "v3.0.0"] {
            storage
                .put(&format!("go/github.com/user/repo/@v/{}.info", ver), b"{}")
                .await
                .unwrap();
            storage
                .put(
                    &format!("go/github.com/user/repo/@v/{}.mod", ver),
                    b"module",
                )
                .await
                .unwrap();
            storage
                .put(
                    &format!("go/github.com/user/repo/@v/{}.zip", ver),
                    b"zipdata",
                )
                .await
                .unwrap();
        }

        let rules = vec![RetentionRule {
            registry: "go".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(result.planned, 2); // v1.0.0 and v2.0.0 deleted
        assert_eq!(result.deleted_keys, 6); // 3 files per version * 2
                                            // v3.0.0 kept (newest by name tiebreaker)
        assert!(storage
            .get("go/github.com/user/repo/@v/v3.0.0.zip")
            .await
            .is_ok());
        // v1.0.0 deleted
        assert!(storage
            .get("go/github.com/user/repo/@v/v1.0.0.zip")
            .await
            .is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod format_retention_tests {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    fn rule(
        registry: &str,
        glob: Option<&str>,
        keep: Option<u32>,
        days: Option<u32>,
    ) -> RetentionRule {
        RetentionRule {
            registry: registry.into(),
            name_glob: glob.map(String::from),
            keep_last: keep,
            older_than_days: days,
            exclude_tags: vec![],
        }
    }

    #[test]
    fn test_name_glob_targets_specific_repos() {
        // Specific-first: dev repos age out, stream repos keep a window,
        // anything unmatched (release repos) is untouched.
        let rules = vec![
            rule("rpm", Some("*-dev-*/*"), None, Some(7)),
            rule("rpm", Some("*-stream-*/*"), Some(25), None),
        ];
        assert_eq!(
            find_matching_rule(&rules, "rpm", "rpm:app-dev-x1/pkg").map(|r| r.older_than_days),
            Some(Some(7))
        );
        assert_eq!(
            find_matching_rule(&rules, "rpm", "rpm:app-stream-x/pkg").map(|r| r.keep_last),
            Some(Some(25))
        );
        assert!(
            find_matching_rule(&rules, "rpm", "rpm:app-release/pkg").is_none(),
            "no rule = keep forever"
        );
    }

    fn build_rpm(name: &str, version: &str) -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new(name, version, "MIT", "x86_64", "t")
            .release("1")
            .build()
            .unwrap();
        let mut buf = Vec::new();
        pkg.write(&mut buf).unwrap();
        buf
    }

    /// keep_last over an rpm repo: old versions' packages AND sidecars are
    /// deleted, and the repo's indexes are rebuilt + re-signed afterwards —
    /// no ghosts advertised.
    #[tokio::test]
    async fn test_rpm_retention_deletes_and_regenerates() {
        let ctx = create_test_context();
        for v in ["1.0", "2.0", "3.0"] {
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/rpm/prod/pkg-{v}.rpm"),
                build_rpm("pkg", v),
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }

        let rules = vec![rule("rpm", None, Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 2, "two of three versions dominated");

        // Packages + sidecars of evicted versions are gone.
        let keys = ctx.state.storage.list("rpm/prod/").await.unwrap();
        let rpms: Vec<_> = keys.iter().filter(|k| k.ends_with(".rpm")).collect();
        assert_eq!(rpms.len(), 1, "{rpms:?}");
        let sidecars: Vec<_> = keys.iter().filter(|k| k.ends_with(".json")).collect();
        assert_eq!(sidecars.len(), 1, "{sidecars:?}");

        // Index regenerated: exactly one package advertised, signature fresh.
        let repomd = String::from_utf8(
            body_bytes(send(&ctx.app, Method::GET, "/rpm/prod/repodata/repomd.xml", "").await)
                .await
                .to_vec(),
        )
        .unwrap();
        let start = repomd.find("href=\"").unwrap() + 6;
        let end = repomd[start..].find('"').unwrap() + start;
        let href = repomd[start..end].to_string();
        let gz =
            body_bytes(send(&ctx.app, Method::GET, &format!("/rpm/prod/{href}"), "").await).await;
        let mut primary = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut primary)
            .unwrap();
        assert!(primary.contains("packages=\"1\""), "{primary}");
        let asc = send(
            &ctx.app,
            Method::GET,
            "/rpm/prod/repodata/repomd.xml.asc",
            "",
        )
        .await;
        assert_eq!(asc.status(), StatusCode::OK);
    }

    /// Age-only rule (the dev-repo shape): everything older than the window
    /// goes regardless of count; dry-run touches nothing.
    #[tokio::test]
    async fn test_rpm_age_only_rule_and_dry_run() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/dev1/pkg-1.0.rpm",
            build_rpm("pkg", "1.0"),
        )
        .await;

        // Backdate the version 8 days via its sidecar (also proves the
        // collector takes `modified` from the sidecar's file_time).
        let sc_key = "rpm/dev1/.nora-meta/pkg-1.0.rpm.json";
        let mut sc: serde_json::Value =
            serde_json::from_slice(&ctx.state.storage.get(sc_key).await.unwrap()).unwrap();
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 8 * 86400;
        sc["file_time"] = serde_json::json!(old_ts);
        ctx.state
            .storage
            .put(sc_key, &serde_json::to_vec(&sc).unwrap())
            .await
            .unwrap();

        // Dry run with the dev-repo shape (age-only, 7 days): plans but never
        // deletes and never regenerates.
        let rules = vec![rule("rpm", None, None, Some(7))];
        let before = ctx.state.storage.list("rpm/dev1/").await.unwrap().len();
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            true,
        )
        .await;
        assert_eq!(result.planned, 1);
        assert_eq!(result.deleted_keys, 0);
        assert_eq!(
            ctx.state.storage.list("rpm/dev1/").await.unwrap().len(),
            before
        );

        // Real run deletes the 8-day-old version.
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        let keys = ctx.state.storage.list("rpm/dev1/").await.unwrap();
        assert!(!keys.iter().any(|k| k.ends_with(".rpm")), "{keys:?}");
    }

    /// Deb mirror of the keep_last flow, asserting the Packages index and
    /// signatures follow the deletion.
    #[tokio::test]
    async fn test_deb_retention_deletes_and_regenerates() {
        let ctx = create_test_context();
        for v in ["1.0", "2.0"] {
            let deb = crate::registry::deb::test_fixtures::build_deb("pkg", v);
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/deb/prod/pool/pkg_{v}.deb"),
                deb,
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }

        let rules = vec![rule("deb", None, Some(1), None)];
        run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;

        let packages = String::from_utf8(
            body_bytes(send(&ctx.app, Method::GET, "/deb/prod/Packages", "").await)
                .await
                .to_vec(),
        )
        .unwrap();
        assert_eq!(packages.matches("Package: pkg").count(), 1, "{packages}");
        let inrelease = send(&ctx.app, Method::GET, "/deb/prod/InRelease", "").await;
        assert_eq!(inrelease.status(), StatusCode::OK);
    }

    /// `keep_last` counts per distribution, not per repo: a distribution's
    /// sole version must survive even when a sibling distribution holds a
    /// newer version of the same package (each distribution is an
    /// independent APT index, and `regenerate_indexes` would silently drop
    /// the evicted one).
    #[tokio::test]
    async fn test_deb_keep_last_counts_per_distribution() {
        let ctx = create_test_context();
        for (v, dist) in [("1.5", "jammy"), ("1.8", "jammy"), ("2.0", "focal")] {
            let deb = crate::registry::deb::test_fixtures::build_deb("tree", v);
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/deb/myrepo/pool/tree_{v}_amd64.deb?distribution={dist}"),
                deb,
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }

        let rules = vec![rule("deb", Some("myrepo/*"), Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1, "only jammy exceeds keep_last");

        // jammy keeps its newest (name tiebreak on tied mtimes), focal keeps
        // its only version.
        let jammy = String::from_utf8(
            body_bytes(
                send(
                    &ctx.app,
                    Method::GET,
                    "/deb/myrepo/dists/jammy/main/binary-amd64/Packages",
                    "",
                )
                .await,
            )
            .await
            .to_vec(),
        )
        .unwrap();
        assert!(jammy.contains("Version: 1.8\n"), "{jammy}");
        assert!(!jammy.contains("Version: 1.5\n"), "{jammy}");
        let focal = String::from_utf8(
            body_bytes(
                send(
                    &ctx.app,
                    Method::GET,
                    "/deb/myrepo/dists/focal/main/binary-amd64/Packages",
                    "",
                )
                .await,
            )
            .await
            .to_vec(),
        )
        .unwrap();
        assert!(focal.contains("Version: 2.0\n"), "{focal}");
    }

    /// Raw: a depth-2 prefix is the version unit — the whole CALVER-style
    /// directory ages out together; root-level files are never collected.
    #[tokio::test]
    async fn test_raw_prefix_grouping_and_deletion() {
        let ctx = create_test_context();
        for k in [
            "raw/stream/v1/image.bin",
            "raw/stream/v1/image.bin.sha256",
            "raw/stream/v2/image.bin",
            "raw/rootfile.bin",
        ] {
            ctx.state.storage.put(k, b"data").await.unwrap();
        }

        let groups = collect_raw_versions(&ctx.state.storage).await;
        let stream = groups.iter().find(|(g, _)| g == "raw:stream").unwrap();
        assert_eq!(stream.1.len(), 2, "two prefix versions");
        assert!(
            !groups.iter().any(|(g, _)| g.contains("rootfile")),
            "root-level files are never a version"
        );

        let rules = vec![rule("raw", Some("stream"), Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        let keys = ctx.state.storage.list("raw/").await.unwrap();
        assert!(keys.contains(&"raw/rootfile.bin".to_string()));
        assert_eq!(
            keys.iter().filter(|k| k.starts_with("raw/stream/")).count(),
            1,
            "one prefix version survives: {keys:?}"
        );
    }
}
