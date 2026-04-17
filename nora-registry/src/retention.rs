//! Retention policies — keep_last, age-based, tag exclusion.
//!
//! Pure `plan_deletions` function determines what to delete.
//! CLI commands: `nora retention plan` (dry-run) and `nora retention apply`.
//!
//! Retention is per-registry and operates on "versions" (Maven versions,
//! Docker tags, npm tarballs, PyPI files, Cargo versions, Go modules).

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};
use tracing::info;

use crate::config::RetentionRule;
use crate::storage::Storage;

// ============================================================================
// Prometheus metrics
// ============================================================================

lazy_static! {
    pub static ref RETENTION_VERSIONS_DELETED: IntCounter = register_int_counter!(
        "nora_retention_versions_deleted_total",
        "Total versions removed by retention policies"
    )
    .expect("retention_versions_deleted metric");
    pub static ref RETENTION_BYTES_FREED: IntCounter = register_int_counter!(
        "nora_retention_bytes_freed_total",
        "Total bytes freed by retention policies"
    )
    .expect("retention_bytes_freed metric");
    pub static ref RETENTION_DURATION: Histogram = register_histogram!(
        "nora_retention_duration_seconds",
        "Duration of retention runs in seconds",
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0]
    )
    .expect("retention_duration metric");
    pub static ref RETENTION_LAST_RUN: IntGauge = register_int_gauge!(
        "nora_retention_last_run_timestamp",
        "Unix timestamp of last retention run"
    )
    .expect("retention_last_run metric");
}

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
            .then_with(|| b.name.cmp(&a.name))
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
    let all_keys = storage.list("maven/").await;
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

/// Collect Docker tags for each repository.
async fn collect_docker_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let all_keys = storage.list("docker/").await;
    let mut repos: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        // docker/{repo}/manifests/{tag}.json
        if let Some(rest) = key.strip_prefix("docker/") {
            if let Some(idx) = rest.find("/manifests/") {
                let repo = &rest[..idx];
                let tag_file = &rest[idx + "/manifests/".len()..];
                if tag_file.ends_with(".json") && !tag_file.ends_with(".meta.json") {
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
    let all_keys = storage.list("npm/").await;
    let mut packages: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        // npm/{package}/tarballs/{file} — each tarball is a "version"
        if let Some(rest) = key.strip_prefix("npm/") {
            if rest.contains("/tarballs/") && !key.ends_with(".sha256") {
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
    let all_keys = storage.list("pypi/").await;
    let mut packages: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for key in &all_keys {
        if let Some(rest) = key.strip_prefix("pypi/") {
            if !key.ends_with(".sha256") {
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
    let all_keys = storage.list("cargo/").await;
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
    let all_keys = storage.list("go/").await;
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
pub async fn run_retention(
    storage: &Storage,
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

    let mut all_plans: Vec<(String, Vec<DeletionPlan>)> = Vec::new();
    let mut total_planned = 0usize;
    let mut total_deleted_keys = 0usize;
    let mut total_bytes = 0u64;

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
            for plan in &plans {
                for key in &plan.keys {
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
    _group_name: &str,
) -> Option<&'a RetentionRule> {
    // Simple matching: rule.registry must match (or be "*")
    rules
        .iter()
        .find(|r| r.registry == registry || r.registry == "*")
}

// ============================================================================
// Background scheduler
// ============================================================================

/// Spawn a background retention task that runs periodically.
/// Uses a tokio::sync::Mutex as single-flight lock to prevent overlapping runs.
pub fn spawn_retention_scheduler(
    storage: Storage,
    rules: Vec<RetentionRule>,
    interval_secs: u64,
    dry_run: bool,
    audit: Option<Arc<crate::audit::AuditLog>>,
) {
    let lock = Arc::new(tokio::sync::Mutex::new(()));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // First tick fires immediately — skip it so retention doesn't run on startup
        interval.tick().await;

        loop {
            interval.tick().await;

            // Single-flight: skip if previous run is still going
            let guard = lock.try_lock();
            if guard.is_err() {
                info!("Retention: previous run still active, skipping");
                continue;
            }

            info!(
                dry_run = dry_run,
                "Retention scheduler: starting periodic run"
            );
            let result = run_retention(&storage, &rules, dry_run).await;
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
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_rule(
        keep_last: Option<u32>,
        older_than_days: Option<u32>,
        exclude_tags: Vec<&str>,
    ) -> RetentionRule {
        RetentionRule {
            registry: "*".to_string(),
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
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &rules, false).await;
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
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &rules, true).await;
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
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &rules, false).await;
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
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &rules, false).await;
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
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &rules, false).await;
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
