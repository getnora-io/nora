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
use sha2::Digest as _;
use tracing::info;

use crate::config::{MavenConfig, MavenRepository, RetentionRule};
use crate::storage::{Storage, StorageError};
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
    /// Identity of the planned version directory at collection time.
    /// Maven revalidates this under the GA publish lock before deletion.
    pub modified: u64,
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
                modified: version.modified,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MavenRetentionKind {
    /// Authoritative hosted content. Retention must rewrite artifact-level
    /// discovery metadata before removing a version directory.
    Hosted,
    /// Rebuildable upstream cache. Artifact-level metadata remains
    /// upstream-owned and must never be filtered by local cache retention.
    ProxyCache,
    /// Pre-named layout where hosted/proxy provenance is unknowable. Keep the
    /// old deletion behaviour but never rewrite discovery metadata.
    Legacy,
}

#[derive(Debug)]
struct MavenVersionGroup {
    group_name: String,
    versions: Vec<VersionEntry>,
    kind: MavenRetentionKind,
    storage_prefix: String,
    group_path: String,
    artifact_id: String,
}

#[derive(Debug, Clone)]
struct MavenRetentionContext {
    kind: MavenRetentionKind,
    storage_prefix: String,
    group_path: String,
    artifact_id: String,
}

#[derive(Default)]
struct MavenVersionDirectory {
    keys: Vec<String>,
    modified: u64,
    size: u64,
    has_payload: bool,
}

/// Collect Maven version directories while retaining repository provenance.
///
/// A directory is considered a version only when it contains at least one
/// non-`maven-metadata.xml*` object. Once identified, every object in that
/// directory is retained in the plan, including V-level SNAPSHOT metadata and
/// all of its checksum sidecars. This avoids mistaking the artifact-level
/// `maven-metadata.xml` directory itself for a version.
async fn collect_maven_versions(storage: &Storage, config: &MavenConfig) -> Vec<MavenVersionGroup> {
    let all_entries = match storage.list_with_meta("maven/").await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::error!(%error, "retention: failed to list Maven keys");
            return Vec::new();
        }
    };
    let mut artifacts: std::collections::HashMap<
        (String, String, MavenRetentionKind),
        std::collections::HashMap<String, MavenVersionDirectory>,
    > = std::collections::HashMap::new();

    for (key, meta) in all_entries {
        let Some(after_maven) = key.strip_prefix("maven/") else {
            continue;
        };
        let (repository, relative, kind) =
            if let Some(named) = after_maven.strip_prefix("repositories/") {
                let Some((repository, relative)) = named.split_once('/') else {
                    continue;
                };
                let kind = match config.repository(repository) {
                    Some(MavenRepository::Hosted { .. }) => MavenRetentionKind::Hosted,
                    Some(MavenRepository::Proxy { .. }) => MavenRetentionKind::ProxyCache,
                    Some(MavenRepository::Group { .. }) => {
                        tracing::warn!(
                            repository,
                            key,
                            "retention: group repository unexpectedly owns Maven storage; key kept"
                        );
                        continue;
                    }
                    None => {
                        tracing::warn!(
                            repository,
                            key,
                            "retention: Maven repository is not configured; key kept"
                        );
                        continue;
                    }
                };
                (Some(repository.to_string()), relative, kind)
            } else {
                (None, after_maven, MavenRetentionKind::Legacy)
            };

        let parts: Vec<&str> = relative
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        // {group...}/{artifact}/{version}/{file}
        if parts.len() < 4 {
            continue;
        }
        let filename = parts[parts.len() - 1];
        let version = parts[parts.len() - 2];
        let artifact_path = parts[..parts.len() - 2].join("/");
        let directory = artifacts
            .entry((repository.unwrap_or_default(), artifact_path, kind))
            .or_default()
            .entry(version.to_string())
            .or_default();
        directory.keys.push(key.clone());
        directory.modified = directory.modified.max(meta.modified);
        directory.size += meta.size;
        directory.has_payload |= !filename.starts_with("maven-metadata.xml");
    }

    artifacts
        .into_iter()
        .filter_map(|((repository, artifact_path, kind), versions)| {
            let (group_path, artifact_id) = artifact_path.rsplit_once('/')?;
            let versions: Vec<VersionEntry> = versions
                .into_iter()
                .filter(|(_, directory)| directory.has_payload)
                .map(|(name, directory)| VersionEntry {
                    name,
                    keys: directory.keys,
                    modified: directory.modified,
                    size: directory.size,
                })
                .collect();
            if versions.is_empty() {
                return None;
            }
            let group_name = if repository.is_empty() {
                format!("maven:{artifact_path}")
            } else {
                format!("maven:{repository}:{artifact_path}")
            };
            let storage_prefix = if repository.is_empty() {
                "maven/".to_string()
            } else {
                format!("maven/repositories/{repository}/")
            };
            Some(MavenVersionGroup {
                group_name,
                versions,
                kind,
                storage_prefix,
                group_path: group_path.to_string(),
                artifact_id: artifact_id.to_string(),
            })
        })
        .collect()
}

/// Collect rpm package versions per repository from the metadata sidecars
/// (never the .rpm payloads). Group = `rpm:{repo}/{arch}/{package-name}`;
/// each version's keys are the package file and its sidecar. Deleting a
/// version therefore requires the post-delete index regeneration in
/// `run_retention`.
async fn collect_rpm_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "rpm", |v| {
        let s = |f: &str| v.get(f).and_then(|x| x.as_str()).unwrap_or("").to_string();
        SidecarVersion {
            package: s("name"),
            version: format!("{}-{}.{}", s("version"), s("release"), s("arch")),
            arch: s("arch"),
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
/// packages group per placement and architecture
/// (`deb:{repo}/{dist}/{component}/{arch}/{package}`), matching how
/// `regenerate_indexes` rebuilds one index per distribution × architecture;
/// flat-root packages group as `deb:{repo}/{arch}/{package}`.
async fn collect_deb_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "deb", |v| {
        let s = |f: &str| v.get(f).and_then(|x| x.as_str()).unwrap_or("").to_string();
        SidecarVersion {
            package: s("package"),
            version: format!("{}_{}", s("version"), s("arch")),
            arch: s("arch"),
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
    /// Architecture, its own group axis: each `binary-{arch}` index (deb) is
    /// independent, and rpm `keep_last` should not collapse architectures
    /// either. `all`/`noarch` packages serve every architecture and form
    /// their own group rather than pooling under a concrete one.
    arch: String,
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
            Some(placement) => {
                format!("{registry}:{repo}/{placement}/{}/{}", sv.arch, sv.package)
            }
            None => format!("{registry}:{repo}/{}/{}", sv.arch, sv.package),
        };
        groups.entry(group).or_default().push(VersionEntry {
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

#[derive(Debug, Clone)]
struct NpmVersionGroup {
    group_name: String,
    repository: String,
    package: String,
    versions: Vec<VersionEntry>,
    /// Digest of the complete authoritative hosted package state observed
    /// while planning. Every plan in this package is validated against the
    /// same digest under the exact npm publish lock.
    snapshot_guard: String,
}

#[derive(Debug)]
struct NpmPackageSnapshot {
    versions: Vec<VersionEntry>,
    guard: String,
}

fn is_hosted_npm_object(kind: &crate::npm_layout::NpmObjectKind) -> bool {
    matches!(
        kind,
        crate::npm_layout::NpmObjectKind::HostedPackage
            | crate::npm_layout::NpmObjectKind::HostedVersion(_)
            | crate::npm_layout::NpmObjectKind::HostedPublishComplete(_)
            | crate::npm_layout::NpmObjectKind::HostedTarball(_)
            | crate::npm_layout::NpmObjectKind::HostedBlob { .. }
            | crate::npm_layout::NpmObjectKind::HostedDistTag(_)
            | crate::npm_layout::NpmObjectKind::HostedDeprecation(_)
    )
}

fn npm_guard_bytes(hasher: &mut sha2::Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Read one exact hosted npm package snapshot.
///
/// `LIST` establishes the relevant key set, `HEAD` supplies metadata for every
/// listed key, and mutable/visibility objects are read and hashed. Any
/// uncertainty fails closed for the whole package. Blob bodies are not read:
/// their content-addressed key plus metadata is sufficient identity, while
/// avoiding a retention-time download of every tarball.
async fn npm_package_snapshot(
    storage: &Storage,
    repository: &str,
    package: &str,
    listed_keys: Vec<String>,
) -> Result<NpmPackageSnapshot, String> {
    use std::collections::BTreeMap;

    let mut objects = BTreeMap::new();
    for key in listed_keys {
        let Some(parsed) = crate::npm_layout::parse_npm_object_key(&key) else {
            continue;
        };
        if parsed.repository != repository
            || parsed.package != package
            || !is_hosted_npm_object(&parsed.kind)
        {
            continue;
        }
        let meta = storage
            .stat(&key)
            .await
            .ok_or_else(|| format!("metadata unavailable for {key}"))?;
        let contents = if matches!(
            parsed.kind,
            crate::npm_layout::NpmObjectKind::HostedPackage
                | crate::npm_layout::NpmObjectKind::HostedVersion(_)
                | crate::npm_layout::NpmObjectKind::HostedPublishComplete(_)
                | crate::npm_layout::NpmObjectKind::HostedDistTag(_)
                | crate::npm_layout::NpmObjectKind::HostedDeprecation(_)
        ) {
            let contents = storage
                .get(&key)
                .await
                .map_err(|error| format!("cannot read {key}: {error}"))?;
            if contents.len() as u64 != meta.size {
                return Err(format!("size changed while reading {key}"));
            }
            let after = storage
                .stat(&key)
                .await
                .ok_or_else(|| format!("metadata disappeared for {key}"))?;
            if after.size != meta.size || after.modified != meta.modified {
                return Err(format!("metadata changed while reading {key}"));
            }
            Some(contents)
        } else {
            None
        };
        if objects
            .insert(key.clone(), (parsed.kind, meta, contents))
            .is_some()
        {
            return Err(format!("duplicate key in listing: {key}"));
        }
    }

    let mut hasher = sha2::Sha256::new();
    npm_guard_bytes(&mut hasher, b"nora/npm-retention-package/v1");
    npm_guard_bytes(&mut hasher, repository.as_bytes());
    npm_guard_bytes(&mut hasher, package.as_bytes());
    for (key, (_, meta, contents)) in &objects {
        npm_guard_bytes(&mut hasher, key.as_bytes());
        hasher.update(meta.size.to_be_bytes());
        hasher.update(meta.modified.to_be_bytes());
        match contents {
            Some(contents) => {
                hasher.update([1]);
                npm_guard_bytes(&mut hasher, contents);
            }
            None => hasher.update([0]),
        }
    }

    let mut manifests = BTreeMap::new();
    let mut deprecations = BTreeMap::new();
    let mut completions = BTreeMap::new();
    let mut tags = Vec::new();
    for (key, (kind, _, contents)) in &objects {
        match kind {
            crate::npm_layout::NpmObjectKind::HostedVersion(version) => {
                if manifests
                    .insert(
                        version.clone(),
                        (
                            key.clone(),
                            contents
                                .as_ref()
                                .ok_or_else(|| format!("manifest unreadable: {key}"))?
                                .clone(),
                        ),
                    )
                    .is_some()
                {
                    return Err(format!("duplicate manifest for npm version {version}"));
                }
            }
            crate::npm_layout::NpmObjectKind::HostedDeprecation(version) => {
                deprecations.insert(version.clone(), key.clone());
            }
            crate::npm_layout::NpmObjectKind::HostedPublishComplete(version) => {
                completions.insert(version.clone(), key.clone());
            }
            crate::npm_layout::NpmObjectKind::HostedDistTag(_) => {
                tags.push((
                    key.clone(),
                    contents
                        .as_ref()
                        .ok_or_else(|| format!("dist-tag unreadable: {key}"))?
                        .clone(),
                ));
            }
            _ => {}
        }
    }

    let mut versions = Vec::with_capacity(manifests.len());
    for (version, (manifest_key, manifest)) in manifests {
        let blob_key =
            crate::npm_layout::hosted_blob_key_from_manifest(repository, package, &manifest)
                .ok_or_else(|| {
                    format!("npm version manifest has no valid blob reference: {manifest_key}")
                })?;
        let Some((blob_kind, _, _)) = objects.get(&blob_key) else {
            return Err(format!("npm version blob is missing: {blob_key}"));
        };
        if !matches!(
            blob_kind,
            crate::npm_layout::NpmObjectKind::HostedBlob { .. }
        ) {
            return Err(format!("npm version blob has invalid layout: {blob_key}"));
        }

        let mut keys = vec![manifest_key, blob_key];
        if let Some(key) = completions.get(&version) {
            keys.push(key.clone());
        }
        if let Some(key) = deprecations.get(&version) {
            keys.push(key.clone());
        }
        for (tag_key, target) in &tags {
            if target.as_ref() == version.as_bytes() {
                keys.push(tag_key.clone());
            }
        }
        keys.sort();
        keys.dedup();

        let mut modified = 0u64;
        let mut size = 0u64;
        for key in &keys {
            let (_, meta, _) = objects
                .get(key)
                .ok_or_else(|| format!("snapshot key disappeared: {key}"))?;
            modified = modified.max(meta.modified);
            size += meta.size;
        }
        versions.push(VersionEntry {
            name: version,
            keys,
            modified,
            size,
        });
    }

    Ok(NpmPackageSnapshot {
        versions,
        guard: hex::encode(hasher.finalize()),
    })
}

async fn read_npm_package_snapshot(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<NpmPackageSnapshot, String> {
    let prefix = format!("npm/repositories/{repository}/{package}/");
    let keys = storage
        .list(&prefix)
        .await
        .map_err(|error| format!("cannot list {prefix}: {error}"))?;
    npm_package_snapshot(storage, repository, package, keys).await
}

/// Collect npm packages, including packages that only contain cleanup state.
/// Empty packages are retained in the result so a failed post-commit cleanup
/// is independently discoverable and retryable on the next retention run.
async fn collect_npm_versions(storage: &Storage) -> Vec<NpmVersionGroup> {
    let all_keys = match storage.list("npm/").await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(%error, "retention: failed to list npm keys");
            return Vec::new();
        }
    };
    let mut packages: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for key in all_keys {
        let Some(parsed) = crate::npm_layout::parse_npm_object_key(&key) else {
            continue;
        };
        if is_hosted_npm_object(&parsed.kind) {
            packages
                .entry((parsed.repository, parsed.package))
                .or_default()
                .push(key);
        }
    }

    let mut result = Vec::with_capacity(packages.len());
    for ((repository, package), keys) in packages {
        match npm_package_snapshot(storage, &repository, &package, keys).await {
            Ok(snapshot) => result.push(NpmVersionGroup {
                group_name: format!("npm:{repository}:{package}"),
                repository,
                package,
                versions: snapshot.versions,
                snapshot_guard: snapshot.guard,
            }),
            Err(error) => {
                tracing::warn!(
                    repository,
                    package,
                    %error,
                    "retention: npm package snapshot is uncertain; package skipped"
                );
            }
        }
    }
    result
}

#[derive(Debug, Default)]
struct NpmCleanupOutcome {
    complete: bool,
    deleted_keys: usize,
    bytes_freed: u64,
}

/// Remove package-level hosted state after retention deleted the last version
/// manifest. Empty packages are collected independently, so a partial failure
/// leaves at least one discoverable key and is retried on a later run.
///
/// The caller holds npm's exact package publish lock.
async fn clean_empty_npm_package(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> NpmCleanupOutcome {
    let versions_prefix = format!("npm/repositories/{repository}/{package}/versions/");
    let versions = match storage.list(&versions_prefix).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::warn!(
                repository,
                package,
                error = %error,
                "retention: cannot verify empty npm package; package metadata kept"
            );
            return NpmCleanupOutcome::default();
        }
    };
    if !versions.is_empty() {
        return NpmCleanupOutcome {
            complete: true,
            ..NpmCleanupOutcome::default()
        };
    }

    let package_prefix = format!("npm/repositories/{repository}/{package}/");
    let mut keys = match storage.list(&package_prefix).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::warn!(
                repository,
                package,
                error = %error,
                "retention: cannot list empty npm package state; metadata kept"
            );
            return NpmCleanupOutcome::default();
        }
    };
    keys.sort();
    let mut outcome = NpmCleanupOutcome::default();
    for key in keys {
        let Some(parsed) = crate::npm_layout::parse_npm_object_key(&key) else {
            continue;
        };
        if parsed.repository != repository || parsed.package != package {
            continue;
        }
        if !matches!(
            parsed.kind,
            crate::npm_layout::NpmObjectKind::HostedPackage
                | crate::npm_layout::NpmObjectKind::HostedDistTag(_)
                | crate::npm_layout::NpmObjectKind::HostedDeprecation(_)
                | crate::npm_layout::NpmObjectKind::HostedPublishComplete(_)
        ) {
            continue;
        }
        let Some(meta) = storage.stat(&key).await else {
            tracing::warn!(
                repository,
                package,
                key,
                "retention: cannot stat empty npm package state; cleanup will retry"
            );
            return outcome;
        };
        match storage.delete(&key).await {
            Ok(()) => {
                outcome.deleted_keys += 1;
                outcome.bytes_freed += meta.size;
            }
            Err(error) => {
                tracing::warn!(
                    repository,
                    package,
                    key,
                    %error,
                    "retention: empty npm package cleanup failed; cleanup will retry"
                );
                return outcome;
            }
        }
    }
    outcome.complete = true;
    outcome
}

async fn npm_blob_still_referenced(
    storage: &Storage,
    blob_key: &str,
) -> Result<bool, StorageError> {
    let Some(parsed) = crate::npm_layout::parse_npm_object_key(blob_key) else {
        return Ok(false);
    };
    if !matches!(
        parsed.kind,
        crate::npm_layout::NpmObjectKind::HostedBlob { .. }
    ) {
        return Ok(false);
    }
    let prefix = format!(
        "npm/repositories/{}/{}/versions/",
        parsed.repository, parsed.package
    );
    for manifest_key in storage.list(&prefix).await? {
        let manifest = storage.get(&manifest_key).await?;
        if crate::npm_layout::hosted_blob_key_from_manifest(
            &parsed.repository,
            &parsed.package,
            &manifest,
        )
        .as_deref()
            == Some(blob_key)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Default)]
struct NpmDeleteOutcome {
    applied: bool,
    deleted_keys: usize,
    bytes_freed: u64,
}

/// Delete one hosted npm version with its version manifest as the visibility
/// commit point. Mutable dependants are removed first, with
/// `publish-complete` first of all: if a later pre-commit operation fails, an
/// exact publish retry observes the missing completion marker and can repair
/// the original publish state. Arbitrary tags or deprecations added later are
/// not reconstructible, so this phase is fail-safe rather than atomic. The
/// content-addressed blob is considered only after the manifest commit and may
/// safely remain as a GC-healable orphan.
async fn delete_npm_plan(
    storage: &Storage,
    group_name: &str,
    plan: &DeletionPlan,
) -> NpmDeleteOutcome {
    let mut manifest_key = None;
    let mut completion_keys = Vec::new();
    let mut tag_keys = Vec::new();
    let mut deprecation_keys = Vec::new();
    let mut blob_keys = Vec::new();
    for key in &plan.keys {
        let Some(parsed) = crate::npm_layout::parse_npm_object_key(key) else {
            tracing::error!(
                group = group_name,
                version = %plan.version_name,
                key,
                "retention: npm plan contains an invalid key; deletion aborted"
            );
            return NpmDeleteOutcome::default();
        };
        match parsed.kind {
            crate::npm_layout::NpmObjectKind::HostedVersion(version)
                if version == plan.version_name =>
            {
                if manifest_key.replace(key.clone()).is_some() {
                    tracing::error!(
                        group = group_name,
                        version = %plan.version_name,
                        "retention: npm plan has multiple version manifests; deletion aborted"
                    );
                    return NpmDeleteOutcome::default();
                }
            }
            crate::npm_layout::NpmObjectKind::HostedPublishComplete(version)
                if version == plan.version_name =>
            {
                completion_keys.push(key.clone());
            }
            crate::npm_layout::NpmObjectKind::HostedDeprecation(version)
                if version == plan.version_name =>
            {
                deprecation_keys.push(key.clone());
            }
            crate::npm_layout::NpmObjectKind::HostedDistTag(_) => tag_keys.push(key.clone()),
            crate::npm_layout::NpmObjectKind::HostedBlob { .. } => blob_keys.push(key.clone()),
            _ => {
                tracing::error!(
                    group = group_name,
                    version = %plan.version_name,
                    key,
                    "retention: npm plan contains an unrelated key; deletion aborted"
                );
                return NpmDeleteOutcome::default();
            }
        }
    }
    let Some(manifest_key) = manifest_key else {
        tracing::error!(
            group = group_name,
            version = %plan.version_name,
            "retention: npm plan has no version manifest; deletion aborted"
        );
        return NpmDeleteOutcome::default();
    };
    completion_keys.sort();
    tag_keys.sort();
    deprecation_keys.sort();
    blob_keys.sort();

    let mut outcome = NpmDeleteOutcome::default();

    // Pre-commit phase. A failure may leave already-deleted mutable state, but
    // never removes the version manifest. Deleting the completion marker first
    // makes the original publish state explicitly retryable by npm's
    // exact-publish repair path. Later operator mutations are not
    // reconstructible; the manifest nevertheless remains a safe visibility
    // boundary and no tag can dangle from a deleted version.
    for key in completion_keys
        .iter()
        .chain(tag_keys.iter())
        .chain(deprecation_keys.iter())
    {
        if tag_keys.binary_search(key).is_ok() {
            match storage.get(key).await {
                Ok(target) if target.as_ref() == plan.version_name.as_bytes() => {}
                Ok(_) => {
                    tracing::warn!(
                        group = group_name,
                        version = %plan.version_name,
                        key,
                        "retention: npm dist-tag target changed; deletion aborted"
                    );
                    return outcome;
                }
                Err(error) => {
                    tracing::warn!(
                        group = group_name,
                        version = %plan.version_name,
                        key,
                        %error,
                        "retention: cannot verify npm dist-tag target; deletion aborted"
                    );
                    return outcome;
                }
            }
        }
        let Some(meta) = storage.stat(key).await else {
            tracing::warn!(
                group = group_name,
                version = %plan.version_name,
                key,
                "retention: cannot stat dependent npm object; deletion aborted"
            );
            return outcome;
        };
        match storage.delete(key).await {
            Ok(()) => {
                outcome.deleted_keys += 1;
                outcome.bytes_freed += meta.size;
            }
            Err(error) => {
                tracing::warn!(
                    group = group_name,
                    version = %plan.version_name,
                    key,
                    %error,
                    "retention: dependent npm object deletion failed; manifest kept"
                );
                return outcome;
            }
        }
    }

    let Some(manifest_meta) = storage.stat(&manifest_key).await else {
        tracing::warn!(
            group = group_name,
            version = %plan.version_name,
            key = %manifest_key,
            "retention: cannot stat npm manifest; deletion aborted"
        );
        return outcome;
    };
    match storage.delete(&manifest_key).await {
        Ok(()) => {
            outcome.deleted_keys += 1;
            outcome.bytes_freed += manifest_meta.size;
            outcome.applied = true;
        }
        Err(error) => {
            tracing::warn!(
                group = group_name,
                version = %plan.version_name,
                key = %manifest_key,
                %error,
                "retention: npm manifest deletion failed; blob kept"
            );
            return outcome;
        }
    }

    // Post-commit phase: failures only leave content-addressed orphan blobs.
    for key in blob_keys {
        match npm_blob_still_referenced(storage, &key).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    group = group_name,
                    version = %plan.version_name,
                    key,
                    %error,
                    "retention: cannot prove npm blob is unreferenced; blob kept"
                );
                continue;
            }
        }
        let Some(meta) = storage.stat(&key).await else {
            tracing::warn!(
                group = group_name,
                version = %plan.version_name,
                key,
                "retention: cannot stat unreferenced npm blob; blob kept"
            );
            continue;
        };
        match storage.delete(&key).await {
            Ok(()) => {
                outcome.deleted_keys += 1;
                outcome.bytes_freed += meta.size;
            }
            Err(error) => {
                tracing::warn!(
                    group = group_name,
                    version = %plan.version_name,
                    key,
                    %error,
                    "retention: unreferenced npm blob deletion failed; GC will retry"
                );
            }
        }
    }

    outcome
}

#[derive(Debug, Default)]
struct NpmBatchOutcome {
    applied_versions: usize,
    deleted_keys: usize,
    bytes_freed: u64,
}

/// Validate and apply a complete npm package plan while holding the same lock
/// used by publish, dist-tag and deprecation mutations.
///
/// A package-wide guard is essential: validating only the candidate version
/// would still allow another version to change retention ordering after
/// `keep_last` was planned. The guard is checked once before any mutation and
/// the lock is held across the complete package batch.
async fn apply_npm_plans(
    storage: &Storage,
    publish_locks: &PublishLocks,
    group: &NpmVersionGroup,
    plans: &[DeletionPlan],
) -> NpmBatchOutcome {
    let lock = crate::acquire_publish_lock(publish_locks, &group.group_name);
    let _guard = lock.lock().await;

    let current = match read_npm_package_snapshot(storage, &group.repository, &group.package).await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(
                repository = group.repository,
                package = group.package,
                %error,
                "retention: cannot revalidate npm package snapshot; batch skipped"
            );
            return NpmBatchOutcome::default();
        }
    };
    if current.guard != group.snapshot_guard {
        tracing::info!(
            repository = group.repository,
            package = group.package,
            "retention: npm package changed after planning; batch skipped"
        );
        return NpmBatchOutcome::default();
    }

    let mut outcome = NpmBatchOutcome::default();
    // The hosted packument cache is derived and deliberately excluded from
    // the authoritative retention snapshot. Remove it before the first
    // mutation while holding the exact publish lock; a later read will rebuild
    // from whatever authoritative state the batch commits.
    let cache_key =
        crate::npm_layout::hosted_packument_cache_key(&group.repository, &group.package);
    let cache_size = storage
        .stat(&cache_key)
        .await
        .map(|meta| meta.size)
        .unwrap_or(0);
    match storage.delete(&cache_key).await {
        Ok(()) => {
            outcome.deleted_keys += 1;
            outcome.bytes_freed += cache_size;
        }
        Err(StorageError::NotFound) => {}
        Err(error) => {
            tracing::warn!(
                repository = group.repository,
                package = group.package,
                key = cache_key,
                %error,
                "retention: cannot invalidate npm hosted packument cache; batch skipped"
            );
            return outcome;
        }
    }
    for plan in plans {
        let deleted = delete_npm_plan(storage, &group.group_name, plan).await;
        outcome.deleted_keys += deleted.deleted_keys;
        outcome.bytes_freed += deleted.bytes_freed;
        if !deleted.applied {
            // A pre-commit failure may already have removed mutable state.
            // Stop the package batch. The manifest remains visible and no tag
            // can dangle from a deleted version. Removing publish-complete
            // first also lets an exact retry repair original publish state.
            return outcome;
        }
        outcome.applied_versions += 1;
        info!(
            group = %group.group_name,
            version = %plan.version_name,
            reason = %plan.reason,
            "Retention: deleted"
        );
    }

    let cleanup = clean_empty_npm_package(storage, &group.repository, &group.package).await;
    outcome.deleted_keys += cleanup.deleted_keys;
    outcome.bytes_freed += cleanup.bytes_freed;
    if !cleanup.complete {
        tracing::warn!(
            repository = group.repository,
            package = group.package,
            "retention: empty npm package cleanup remains pending"
        );
    }
    outcome
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

#[derive(Default)]
struct MavenDeletionOutcome {
    applied: bool,
    deleted_keys: usize,
    bytes_freed: u64,
}

fn is_maven_metadata_base(key: &str) -> bool {
    key.rsplit('/').next() == Some("maven-metadata.xml")
}

fn is_maven_metadata_sidecar(key: &str) -> bool {
    matches!(
        key.rsplit('/').next(),
        Some(
            "maven-metadata.xml.md5"
                | "maven-metadata.xml.sha1"
                | "maven-metadata.xml.sha256"
                | "maven-metadata.xml.sha512"
        )
    )
}

fn is_checksum_sidecar(key: &str) -> bool {
    [".md5", ".sha1", ".sha256", ".sha512"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
}

async fn delete_retention_key(storage: &Storage, key: &str) -> Result<(usize, u64), StorageError> {
    let size = storage.stat(key).await.map(|meta| meta.size).unwrap_or(0);
    match storage.delete(key).await {
        Ok(()) => Ok((1, size)),
        Err(StorageError::NotFound) => Ok((0, 0)),
        Err(error) => Err(error),
    }
}

async fn maven_candidate_matches_plan(
    storage: &Storage,
    context: &MavenRetentionContext,
    plan: &DeletionPlan,
) -> Result<bool, StorageError> {
    let prefix = format!(
        "{}{}/{}/{}/",
        context.storage_prefix, context.group_path, context.artifact_id, plan.version_name
    );
    let current = storage.list_with_meta(&prefix).await?;
    let current_keys: std::collections::BTreeSet<&str> =
        current.iter().map(|(key, _)| key.as_str()).collect();
    let planned_keys: std::collections::BTreeSet<&str> =
        plan.keys.iter().map(String::as_str).collect();
    let current_size = current.iter().map(|(_, meta)| meta.size).sum::<u64>();
    let current_modified = current
        .iter()
        .map(|(_, meta)| meta.modified)
        .max()
        .unwrap_or(0);

    Ok(current_keys == planned_keys
        && current_size == plan.size
        && current_modified == plan.modified)
}

/// Delete one Maven version under the exact artifact metadata lock shared with
/// publish/proxy metadata writes.
///
/// Hosted discovery is hidden first: A-level metadata is regenerated (or
/// removed) and V-level metadata sidecars/base are deleted before any payload.
/// A later payload failure therefore leaves only hidden orphan bytes. Proxy and
/// legacy metadata remain untouched because their A-level version list is
/// upstream-owned or has unknowable provenance.
async fn delete_maven_plan(
    storage: &Storage,
    publish_locks: &PublishLocks,
    context: &MavenRetentionContext,
    plan: &DeletionPlan,
) -> MavenDeletionOutcome {
    let metadata_key = format!(
        "{}{}/{}/maven-metadata.xml",
        context.storage_prefix, context.group_path, context.artifact_id
    );
    let lock = crate::acquire_publish_lock(publish_locks, &metadata_key);
    let _guard = lock.lock().await;
    let mut outcome = MavenDeletionOutcome::default();

    match maven_candidate_matches_plan(storage, context, plan).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                group = %context.group_path,
                artifact = %context.artifact_id,
                version = %plan.version_name,
                "retention: Maven version changed after planning; candidate skipped"
            );
            return outcome;
        }
        Err(error) => {
            tracing::error!(
                group = %context.group_path,
                artifact = %context.artifact_id,
                version = %plan.version_name,
                error = %error,
                "retention: cannot revalidate Maven version under publish lock; candidate skipped"
            );
            return outcome;
        }
    }

    if context.kind == MavenRetentionKind::Hosted {
        match crate::registry::update_hosted_metadata_after_retention(
            storage,
            &context.storage_prefix,
            &context.group_path,
            &context.artifact_id,
            &plan.version_name,
        )
        .await
        {
            Ok((deleted_keys, bytes_freed)) => {
                outcome.deleted_keys += deleted_keys;
                outcome.bytes_freed += bytes_freed;
            }
            Err(error) => {
                tracing::error!(
                    group = %context.group_path,
                    artifact = %context.artifact_id,
                    version = %plan.version_name,
                    error = %error,
                    "retention: Maven metadata update failed; version payload kept"
                );
                return outcome;
            }
        }
    }

    // V-level SNAPSHOT discovery must disappear before version payloads.
    for key in plan
        .keys
        .iter()
        .filter(|key| is_maven_metadata_sidecar(key))
    {
        match delete_retention_key(storage, key).await {
            Ok((deleted, bytes)) => {
                outcome.deleted_keys += deleted;
                outcome.bytes_freed += bytes;
            }
            Err(error) => {
                tracing::error!(
                    key,
                    version = %plan.version_name,
                    error = %error,
                    "retention: Maven version metadata sidecar deletion failed; payload kept"
                );
                return outcome;
            }
        }
    }
    for key in plan.keys.iter().filter(|key| is_maven_metadata_base(key)) {
        match delete_retention_key(storage, key).await {
            Ok((deleted, bytes)) => {
                outcome.deleted_keys += deleted;
                outcome.bytes_freed += bytes;
            }
            Err(error) => {
                tracing::error!(
                    key,
                    version = %plan.version_name,
                    error = %error,
                    "retention: Maven version metadata deletion failed; payload kept"
                );
                return outcome;
            }
        }
    }

    let mut payload_keys: Vec<&String> = plan
        .keys
        .iter()
        .filter(|key| !is_maven_metadata_base(key) && !is_maven_metadata_sidecar(key))
        .collect();
    // Remove derived checksum sidecars before their base object. Once A/V
    // discovery is hidden, an interruption can only leave invisible orphans.
    payload_keys.sort_by_key(|key| !is_checksum_sidecar(key));
    for key in payload_keys {
        match delete_retention_key(storage, key).await {
            Ok((deleted, bytes)) => {
                outcome.deleted_keys += deleted;
                outcome.bytes_freed += bytes;
            }
            Err(error) => {
                tracing::error!(
                    key,
                    version = %plan.version_name,
                    error = %error,
                    "retention: Maven version payload deletion failed; remaining objects kept"
                );
                return outcome;
            }
        }
    }

    outcome.applied = true;
    outcome
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
#[cfg(test)]
pub async fn run_retention(
    storage: &Storage,
    publish_locks: &PublishLocks,
    signer: Option<&crate::signing::RepoSigner>,
    rules: &[RetentionRule],
    dry_run: bool,
) -> RetentionResult {
    let maven = MavenConfig::default();
    run_retention_configured(storage, publish_locks, signer, rules, dry_run, &maven, None).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_retention_configured(
    storage: &Storage,
    publish_locks: &PublishLocks,
    signer: Option<&crate::signing::RepoSigner>,
    rules: &[RetentionRule],
    dry_run: bool,
    maven_config: &MavenConfig,
    repo_index: Option<&crate::repo_index::RepoIndex>,
) -> RetentionResult {
    let start = Instant::now();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Collect versions from all registries
    let mut all_groups: Vec<(String, Vec<VersionEntry>)> = Vec::new();
    let mut maven_contexts = std::collections::HashMap::new();
    for group in collect_maven_versions(storage, maven_config).await {
        maven_contexts.insert(
            group.group_name.clone(),
            MavenRetentionContext {
                kind: group.kind,
                storage_prefix: group.storage_prefix,
                group_path: group.group_path,
                artifact_id: group.artifact_id,
            },
        );
        all_groups.push((group.group_name, group.versions));
    }
    all_groups.extend(collect_docker_versions(storage).await);
    let mut npm_groups = std::collections::HashMap::new();
    for group in collect_npm_versions(storage).await {
        all_groups.push((group.group_name.clone(), group.versions.clone()));
        npm_groups.insert(group.group_name.clone(), group);
    }
    all_groups.extend(collect_pypi_versions(storage).await);
    all_groups.extend(collect_cargo_versions(storage).await);
    all_groups.extend(collect_go_versions(storage).await);
    all_groups.extend(collect_rpm_versions(storage).await);
    all_groups.extend(collect_deb_versions(storage).await);
    all_groups.extend(collect_raw_versions(storage).await);

    let mut all_plans: Vec<(String, Vec<DeletionPlan>)> = Vec::new();
    let mut total_planned = 0usize;
    let mut total_applied = 0usize;
    let mut total_deleted_keys = 0usize;
    let mut total_bytes = 0u64;
    let mut mutated_registries: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
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

        // npm is validated and applied as one package batch under its exact
        // publish lock. Empty groups are intentionally retained so cleanup
        // failures after the last manifest commit are retried independently.
        if let Some(group) = npm_groups.get(&group_name) {
            if plans.is_empty() {
                if !dry_run && group.versions.is_empty() {
                    let outcome = apply_npm_plans(storage, publish_locks, group, &[]).await;
                    total_deleted_keys += outcome.deleted_keys;
                    total_bytes += outcome.bytes_freed;
                    if outcome.deleted_keys > 0 {
                        mutated_registries.insert("npm".to_string());
                    }
                }
                continue;
            }

            total_planned += plans.len();
            if dry_run {
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
            } else {
                let outcome = apply_npm_plans(storage, publish_locks, group, &plans).await;
                total_applied += outcome.applied_versions;
                total_deleted_keys += outcome.deleted_keys;
                total_bytes += outcome.bytes_freed;
                if outcome.deleted_keys > 0 {
                    mutated_registries.insert("npm".to_string());
                }
            }
            all_plans.push((group_name, plans));
            continue;
        }

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
                let applied = if let Some(context) = maven_contexts.get(&group_name) {
                    // The helper may have changed A-level sidecars before
                    // returning an error. Invalidate conservatively whenever a
                    // hosted metadata mutation is attempted.
                    if context.kind == MavenRetentionKind::Hosted {
                        mutated_registries.insert("maven".to_string());
                    }
                    let outcome = delete_maven_plan(storage, publish_locks, context, plan).await;
                    total_deleted_keys += outcome.deleted_keys;
                    total_bytes += outcome.bytes_freed;
                    if outcome.deleted_keys > 0 {
                        mutated_registries.insert("maven".to_string());
                    }
                    if !outcome.applied {
                        // A storage failure on one version is evidence that
                        // later deletions in the same GA cannot be trusted.
                        // Stop this artifact group instead of compounding a
                        // partial cleanup with more mutations.
                        break;
                    }
                    total_applied += 1;
                    true
                } else {
                    let mut deleted_any = false;
                    for key in &plan.keys {
                        // Serialize with concurrent publish to prevent deleting
                        // an artifact that is being referenced by a new publish.
                        let lock = crate::acquire_publish_lock(publish_locks, key);
                        let _guard = lock.lock().await;
                        if storage.delete(key).await.is_ok() {
                            total_deleted_keys += 1;
                            deleted_any = true;
                        }
                    }
                    total_applied += 1;
                    total_bytes += plan.size;
                    if deleted_any {
                        mutated_registries.insert(registry.to_string());
                    }
                    true
                };
                if applied {
                    info!(
                        group = %group_name,
                        version = %plan.version_name,
                        reason = %plan.reason,
                        "Retention: deleted"
                    );
                }
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
        if let Some(repo_index) = repo_index {
            for registry in mutated_registries {
                repo_index.invalidate(&registry);
            }
        }
        RETENTION_VERSIONS_DELETED.inc_by(total_applied as u64);
        RETENTION_BYTES_FREED.inc_by(total_bytes);
        if total_applied > 0 {
            info!(
                versions = total_applied,
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
    let npm_package = (registry == "npm")
        .then(|| name.split_once(':').map(|(_, package)| package))
        .flatten();
    rules.iter().find(|r| {
        (r.registry == registry || r.registry == "*")
            && r.name_glob.as_deref().is_none_or(|glob| {
                // Preserve the historical npm package selector across named
                // hosted repositories. A glob containing ':' opts into the
                // qualified `{repository}:{package}` identity.
                if registry == "npm" && !glob.contains(':') {
                    glob_match(glob, npm_package.unwrap_or(name))
                } else {
                    glob_match(glob, name)
                }
            })
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
    maven_config: MavenConfig,
    repo_index: Arc<crate::repo_index::RepoIndex>,
    rules: Vec<RetentionRule>,
    interval_secs: u64,
    dry_run: bool,
    audit: Option<Arc<crate::audit::AuditLog>>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // The interval's first tick fires immediately: retention runs once at
        // boot, then every `interval_secs`. Waiting a full interval instead
        // means a process that restarts more often than the interval NEVER
        // runs retention — deploy-happy environments accumulated unbounded
        // garbage exactly when the schedule looked configured.
        let mut boot_run = true;

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

            // Cross-scheduler lock: skip if GC or retention is already running.
            // The boot run waits for the lock instead — GC's boot pass fires at
            // the same instant, and skipping here would silently postpone the
            // first retention by a whole interval again.
            let guard = if boot_run {
                boot_run = false;
                // CANCEL-SAFETY: the boot pass waits on the lock (vs skip-if-held) so it
                // can't forfeit its first run to GC's simultaneous boot pass — but race
                // the wait against cancellation, so a SIGTERM during boot contention
                // breaks promptly instead of blocking behind the sibling's whole pass.
                // Dropping the not-yet-acquired lock() future only removes this waiter.
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    g = cleanup_lock.lock() => Ok(g),
                }
            } else {
                cleanup_lock.try_lock()
            };
            let Ok(guard) = guard else {
                info!("Retention: cleanup lock held (GC or retention running), skipping");
                continue;
            };

            info!(
                dry_run = dry_run,
                "Retention scheduler: starting periodic run"
            );
            let result = run_retention_configured(
                &storage,
                &publish_locks,
                signer.as_deref(),
                &rules,
                dry_run,
                &maven_config,
                Some(&repo_index),
            )
            .await;
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

    async fn seed_npm_version(
        storage: &Storage,
        prefix: &str,
        package: &str,
        version: &str,
        blob: &[u8],
    ) -> (String, String) {
        use base64::Engine as _;
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(blob))
        );
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": package,
            "version": version,
            "dist": {"integrity": integrity}
        }))
        .unwrap();
        let manifest_key = format!("{prefix}/versions/{version}.json");
        let repository = prefix
            .strip_prefix("npm/repositories/")
            .and_then(|value| value.split_once('/'))
            .map(|(repository, _)| repository)
            .unwrap();
        let blob_key =
            crate::npm_layout::hosted_blob_key_from_manifest(repository, package, &manifest)
                .unwrap();
        storage.put(&blob_key, blob).await.unwrap();
        storage.put(&manifest_key, &manifest).await.unwrap();
        (manifest_key, blob_key)
    }

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
    async fn test_retention_keeps_named_maven_repositories_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        for repository in ["releases", "open"] {
            for version in ["1.0", "2.0"] {
                storage
                    .put(
                        &format!(
                            "maven/repositories/{repository}/com/example/lib/{version}/lib-{version}.jar"
                        ),
                        version.as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        }

        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let mut maven = MavenConfig::default();
        maven.proxies.clear();
        maven.repositories = vec![
            MavenRepository::Hosted {
                name: "releases".to_string(),
                version_policy: crate::config::MavenVersionPolicy::Mixed,
                write_policy: crate::config::MavenWritePolicy::AllowOnce,
            },
            MavenRepository::Proxy {
                name: "open".to_string(),
                url: "https://repo1.maven.org/maven2".to_string(),
                auth: None,
                version_policy: crate::config::MavenVersionPolicy::Mixed,
                metadata_ttl: None,
                negative_ttl: 60,
            },
        ];

        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &maven,
            None,
        )
        .await;

        assert_eq!(result.planned, 2);
        for repository in ["releases", "open"] {
            assert!(storage
                .get(&format!(
                    "maven/repositories/{repository}/com/example/lib/1.0/lib-1.0.jar"
                ))
                .await
                .is_err());
            assert!(storage
                .get(&format!(
                    "maven/repositories/{repository}/com/example/lib/2.0/lib-2.0.jar"
                ))
                .await
                .is_ok());
        }
    }

    fn single_named_maven(repository: MavenRepository) -> MavenConfig {
        let mut config = MavenConfig::default();
        config.proxies.clear();
        config.repositories = vec![repository];
        config
    }

    async fn seed_maven_metadata(storage: &Storage, key: &str, document: &[u8]) {
        storage.put(key, document).await.unwrap();
        for suffix in ["md5", "sha1", "sha256", "sha512"] {
            storage
                .put(&format!("{key}.{suffix}"), b"old-checksum")
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn hosted_maven_retention_hides_discovery_then_removes_v_level_and_rebuilds_index() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/releases/com/example/lib";
        for version in ["1.0-SNAPSHOT", "2.0"] {
            storage
                .put(
                    &format!("{prefix}/{version}/lib-{version}.jar"),
                    version.as_bytes(),
                )
                .await
                .unwrap();
        }
        let v_metadata = format!("{prefix}/1.0-SNAPSHOT/maven-metadata.xml");
        seed_maven_metadata(
            &storage,
            &v_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20260730.010000</timestamp><buildNumber>1</buildNumber></snapshot></versioning></metadata>"#,
        )
        .await;
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        seed_maven_metadata(
            &storage,
            &a_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>1.0-SNAPSHOT</version><version>2.0</version></versions><lastUpdated>20260730010000</lastUpdated></versioning><plugins><plugin><name>Retained</name><prefix>retained</prefix><artifactId>retained-plugin</artifactId></plugin></plugins></metadata>"#,
        )
        .await;

        let repo_index = crate::repo_index::RepoIndex::new();
        let before = repo_index.get("maven", &storage).await;
        assert!(before
            .iter()
            .any(|entry| entry.name.contains("/1.0-SNAPSHOT")));

        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let config = single_named_maven(MavenRepository::Hosted {
            name: "releases".to_string(),
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            write_policy: crate::config::MavenWritePolicy::AllowOnce,
        });
        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &config,
            Some(&repo_index),
        )
        .await;

        assert_eq!(result.planned, 1);
        assert!(storage
            .get(&format!("{prefix}/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"))
            .await
            .is_err());
        for suffix in ["", ".md5", ".sha1", ".sha256", ".sha512"] {
            assert!(storage.get(&format!("{v_metadata}{suffix}")).await.is_err());
        }
        let metadata = storage.get(&a_metadata).await.unwrap();
        let metadata = String::from_utf8_lossy(&metadata);
        assert!(!metadata.contains("<version>1.0-SNAPSHOT</version>"));
        assert!(metadata.contains("<version>2.0</version>"));
        assert!(metadata.contains("<prefix>retained</prefix>"));
        for suffix in ["md5", "sha1", "sha256", "sha512"] {
            assert!(storage.get(&format!("{a_metadata}.{suffix}")).await.is_ok());
        }

        let after = repo_index.get("maven", &storage).await;
        assert!(
            !after
                .iter()
                .any(|entry| entry.name.contains("/1.0-SNAPSHOT")),
            "retention must invalidate and rebuild the non-TTL repository index"
        );
    }

    #[tokio::test]
    async fn hosted_maven_snapshot_changed_after_plan_is_skipped_under_ga_lock() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/snapshots/com/example/lib";
        let snapshot_payload = format!("{prefix}/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        let snapshot_metadata = format!("{prefix}/1.0-SNAPSHOT/maven-metadata.xml");
        storage.put(&snapshot_payload, b"old").await.unwrap();
        storage
            .put(&format!("{prefix}/2.0/lib-2.0.jar"), b"newer-version")
            .await
            .unwrap();
        storage
            .put(
                &snapshot_metadata,
                br#"<metadata><version>1.0-SNAPSHOT</version><versioning><snapshot><buildNumber>1</buildNumber></snapshot></versioning></metadata>"#,
            )
            .await
            .unwrap();
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        seed_maven_metadata(
            &storage,
            &a_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>1.0-SNAPSHOT</version><version>2.0</version></versions><lastUpdated>20260730010000</lastUpdated></versioning></metadata>"#,
        )
        .await;
        let config = single_named_maven(MavenRepository::Hosted {
            name: "snapshots".to_string(),
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            write_policy: crate::config::MavenWritePolicy::Allow,
        });
        let group = collect_maven_versions(&storage, &config)
            .await
            .into_iter()
            .find(|group| group.group_name == "maven:snapshots:com/example/lib")
            .unwrap();
        let rule = RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        };
        let plan = plan_deletions(group.versions, &rule, NOW)
            .into_iter()
            .find(|plan| plan.version_name == "1.0-SNAPSHOT")
            .unwrap();
        let context = MavenRetentionContext {
            kind: group.kind,
            storage_prefix: group.storage_prefix,
            group_path: group.group_path,
            artifact_id: group.artifact_id,
        };

        // Model a mutable SNAPSHOT publish completing after the retention scan
        // but before retention acquires the exact GA metadata lock.
        let republished_payload = b"new-snapshot-bytes-after-plan";
        let republished_v_metadata = br#"<metadata><version>1.0-SNAPSHOT</version><versioning><snapshot><buildNumber>2</buildNumber></snapshot></versioning></metadata>"#;
        let republished_a_metadata = br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>1.0-SNAPSHOT</latest><release>2.0</release><versions><version>1.0-SNAPSHOT</version><version>2.0</version></versions><lastUpdated>20260730020000</lastUpdated></versioning></metadata>"#;
        storage
            .put(&snapshot_payload, republished_payload)
            .await
            .unwrap();
        storage
            .put(&snapshot_metadata, republished_v_metadata)
            .await
            .unwrap();
        storage
            .put(&a_metadata, republished_a_metadata)
            .await
            .unwrap();

        let outcome = delete_maven_plan(&storage, &test_publish_locks(), &context, &plan).await;

        assert!(!outcome.applied);
        assert_eq!(outcome.deleted_keys, 0);
        assert_eq!(
            storage.get(&snapshot_payload).await.unwrap().as_ref(),
            republished_payload
        );
        assert_eq!(
            storage.get(&snapshot_metadata).await.unwrap().as_ref(),
            republished_v_metadata
        );
        assert_eq!(
            storage.get(&a_metadata).await.unwrap().as_ref(),
            republished_a_metadata
        );
    }

    #[tokio::test]
    async fn proxy_maven_retention_keeps_upstream_a_level_discovery_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/central/com/example/lib";
        for version in ["1.0", "2.0"] {
            storage
                .put(
                    &format!("{prefix}/{version}/lib-{version}.jar"),
                    version.as_bytes(),
                )
                .await
                .unwrap();
        }
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        let document = br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>1.0</version><version>2.0</version></versions><lastUpdated>20260730010000</lastUpdated></versioning></metadata>"#;
        seed_maven_metadata(&storage, &a_metadata, document).await;
        let before: Vec<_> = ["", ".md5", ".sha1", ".sha256", ".sha512"]
            .iter()
            .map(|suffix| format!("{a_metadata}{suffix}"))
            .collect();
        let mut before_bytes = Vec::new();
        for key in &before {
            before_bytes.push(storage.get(key).await.unwrap());
        }

        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let config = single_named_maven(MavenRepository::Proxy {
            name: "central".to_string(),
            url: "https://repo1.maven.org/maven2".to_string(),
            auth: None,
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            metadata_ttl: Some(300),
            negative_ttl: 60,
        });
        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &config,
            None,
        )
        .await;

        assert_eq!(result.planned, 1);
        assert!(storage
            .get(&format!("{prefix}/1.0/lib-1.0.jar"))
            .await
            .is_err());
        for (key, expected) in before.iter().zip(before_bytes) {
            assert_eq!(storage.get(key).await.unwrap(), expected);
        }
        let metadata =
            String::from_utf8_lossy(&storage.get(&a_metadata).await.unwrap()).to_string();
        assert!(
            metadata.contains("<version>1.0</version>"),
            "cache eviction must not edit upstream-owned discovery"
        );
    }

    #[tokio::test]
    async fn hosted_maven_v_metadata_delete_failure_keeps_payload_hidden_as_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/releases/com/example/lib";
        for version in ["1.0-SNAPSHOT", "2.0"] {
            inner
                .put(
                    &format!("{prefix}/{version}/lib-{version}.jar"),
                    version.as_bytes(),
                )
                .await
                .unwrap();
        }
        let v_metadata = format!("{prefix}/1.0-SNAPSHOT/maven-metadata.xml");
        seed_maven_metadata(
            &inner,
            &v_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version></metadata>"#,
        )
        .await;
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        seed_maven_metadata(
            &inner,
            &a_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>1.0-SNAPSHOT</version><version>2.0</version></versions></versioning></metadata>"#,
        )
        .await;
        let failed_sidecar = format!("{v_metadata}.md5");
        let backend = crate::test_helpers::FaultInjectBackend::new(inner.clone())
            .fail_delete(&failed_sidecar);
        let attempts = backend.delete_attempts();
        let storage = Storage::from_backend(Arc::new(backend));
        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let config = single_named_maven(MavenRepository::Hosted {
            name: "releases".to_string(),
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            write_policy: crate::config::MavenWritePolicy::AllowOnce,
        });

        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &config,
            None,
        )
        .await;

        assert_eq!(result.planned, 1);
        let payload = format!("{prefix}/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        assert!(inner.get(&payload).await.is_ok());
        assert!(
            !attempts.lock().contains(&payload),
            "payload deletion must fail-stop after V-level metadata failure"
        );
        let metadata = String::from_utf8_lossy(&inner.get(&a_metadata).await.unwrap()).to_string();
        assert!(
            !metadata.contains("<version>1.0-SNAPSHOT</version>"),
            "A-level discovery must be hidden before any version deletion attempt"
        );
    }

    #[tokio::test]
    async fn hosted_maven_a_metadata_failure_deletes_no_version_objects() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/releases/com/example/lib";
        for version in ["1.0", "2.0"] {
            inner
                .put(
                    &format!("{prefix}/{version}/lib-{version}.jar"),
                    version.as_bytes(),
                )
                .await
                .unwrap();
        }
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        seed_maven_metadata(
            &inner,
            &a_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"#,
        )
        .await;
        let failed_sidecar = format!("{a_metadata}.md5");
        let backend = crate::test_helpers::FaultInjectBackend::new(inner.clone())
            .fail_delete(&failed_sidecar);
        let attempts = backend.delete_attempts();
        let storage = Storage::from_backend(Arc::new(backend));
        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let config = single_named_maven(MavenRepository::Hosted {
            name: "releases".to_string(),
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            write_policy: crate::config::MavenWritePolicy::AllowOnce,
        });

        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &config,
            None,
        )
        .await;

        assert_eq!(result.planned, 1);
        let payload = format!("{prefix}/1.0/lib-1.0.jar");
        assert!(inner.get(&payload).await.is_ok());
        let attempts = attempts.lock();
        assert!(attempts.contains(&failed_sidecar));
        assert!(
            !attempts.contains(&payload),
            "A-level metadata failure must abort before every version-object delete"
        );
    }

    #[tokio::test]
    async fn hosted_maven_last_version_retention_removes_a_level_metadata_and_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "maven/repositories/releases/com/example/lib";
        storage
            .put(&format!("{prefix}/1.0/lib-1.0.jar"), b"one")
            .await
            .unwrap();
        let a_metadata = format!("{prefix}/maven-metadata.xml");
        seed_maven_metadata(
            &storage,
            &a_metadata,
            br#"<metadata><groupId>com.example</groupId><artifactId>lib</artifactId><versioning><latest>1.0</latest><release>1.0</release><versions><version>1.0</version></versions></versioning></metadata>"#,
        )
        .await;
        let rules = vec![RetentionRule {
            registry: "maven".to_string(),
            name_glob: None,
            keep_last: Some(0),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let config = single_named_maven(MavenRepository::Hosted {
            name: "releases".to_string(),
            version_policy: crate::config::MavenVersionPolicy::Mixed,
            write_policy: crate::config::MavenWritePolicy::AllowOnce,
        });

        let result = run_retention_configured(
            &storage,
            &test_publish_locks(),
            None,
            &rules,
            false,
            &config,
            None,
        )
        .await;

        assert_eq!(result.planned, 1);
        for suffix in ["", ".md5", ".sha1", ".sha256", ".sha512"] {
            assert!(storage.get(&format!("{a_metadata}{suffix}")).await.is_err());
        }
        assert!(storage
            .get(&format!("{prefix}/1.0/lib-1.0.jar"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_retention_keeps_named_npm_repositories_and_proxy_cache_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        for repository in ["npm-private-a", "npm-private-b"] {
            for version in ["1.0.0", "2.0.0"] {
                seed_npm_version(
                    &storage,
                    &format!("npm/repositories/{repository}/pkg"),
                    "pkg",
                    version,
                    version.as_bytes(),
                )
                .await;
            }
            storage
                .put(
                    &format!("npm/repositories/{repository}/pkg/dist-tags/old"),
                    b"1.0.0",
                )
                .await
                .unwrap();
            storage
                .put(
                    &crate::npm_layout::hosted_packument_cache_key(repository, "pkg"),
                    br#"{"name":"pkg","versions":{},"dist-tags":{}}"#,
                )
                .await
                .unwrap();
        }
        let proxy_key = "npm/repositories/npm-registry/proxy/tarballs/pkg/pkg-1.0.0.tgz";
        storage.put(proxy_key, b"cache").await.unwrap();

        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 2);
        for repository in ["npm-private-a", "npm-private-b"] {
            assert!(storage
                .stat(&format!(
                    "npm/repositories/{repository}/pkg/versions/1.0.0.json"
                ))
                .await
                .is_none());
            assert!(storage
                .stat(&format!(
                    "npm/repositories/{repository}/pkg/blobs/sha512/{}.tgz",
                    hex::encode(sha2::Sha512::digest(b"1.0.0"))
                ))
                .await
                .is_none());
            assert!(storage
                .stat(&format!("npm/repositories/{repository}/pkg/dist-tags/old"))
                .await
                .is_none());
            assert!(storage
                .stat(&format!(
                    "npm/repositories/{repository}/pkg/versions/2.0.0.json"
                ))
                .await
                .is_some());
            assert!(storage
                .stat(&crate::npm_layout::hosted_packument_cache_key(
                    repository, "pkg"
                ))
                .await
                .is_none());
        }
        assert!(storage.get(proxy_key).await.is_ok());
    }

    #[tokio::test]
    async fn test_retention_keeps_blob_referenced_by_remaining_npm_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (_, first_blob) = seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"shared").await;
        let (_, second_blob) = seed_npm_version(&storage, prefix, "pkg", "2.0.0", b"shared").await;
        assert_eq!(first_blob, second_blob);
        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 1);
        assert!(storage
            .stat(&format!("{prefix}/versions/1.0.0.json"))
            .await
            .is_none());
        assert!(storage
            .stat(&format!("{prefix}/versions/2.0.0.json"))
            .await
            .is_some());
        assert!(storage.get(&first_blob).await.is_ok());
    }

    #[tokio::test]
    async fn test_retention_handles_hosted_package_named_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        for version in ["1.0.0", "2.0.0"] {
            seed_npm_version(
                &storage,
                "npm/repositories/npm-private/proxy",
                "proxy",
                version,
                version.as_bytes(),
            )
            .await;
        }

        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 1);
        assert!(storage
            .stat("npm/repositories/npm-private/proxy/versions/1.0.0.json")
            .await
            .is_none());
        assert!(storage
            .stat("npm/repositories/npm-private/proxy/versions/2.0.0.json")
            .await
            .is_some());
    }

    #[tokio::test]
    async fn test_retention_removes_package_state_after_last_npm_version() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"tarball").await;
        storage
            .put(&format!("{prefix}/pkg.json"), br#"{"name":"pkg"}"#)
            .await
            .unwrap();
        storage
            .put(&format!("{prefix}/dist-tags/latest"), b"1.0.0")
            .await
            .unwrap();
        storage
            .put(&format!("{prefix}/deprecations/1.0.0"), b"old")
            .await
            .unwrap();
        storage
            .put(&format!("{prefix}/publish-complete/1.0.0"), b"complete")
            .await
            .unwrap();

        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(0),
            older_than_days: None,
            exclude_tags: vec![],
        }];
        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 1);
        assert!(
            storage
                .list(&format!("{prefix}/"))
                .await
                .unwrap()
                .is_empty(),
            "last-version retention must not leave a 200-but-empty package shadow"
        );
    }

    #[tokio::test]
    async fn test_retention_npm_manifest_delete_failure_keeps_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (manifest, tarball) =
            seed_npm_version(&inner, prefix, "pkg", "1.0.0", b"tarball").await;

        let backend =
            crate::test_helpers::FaultInjectBackend::new(inner.clone()).fail_delete(&manifest);
        let attempts = backend.delete_attempts();
        let storage = Storage::from_backend(Arc::new(backend));
        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(0),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 1);
        assert!(inner.get(&manifest).await.is_ok());
        assert!(inner.get(&tarball).await.is_ok());
        let attempts = attempts.lock();
        assert!(attempts.contains(&manifest));
        assert!(
            !attempts.contains(&tarball),
            "tarball deletion must not be attempted after manifest failure"
        );
    }

    #[tokio::test]
    async fn stale_npm_redeploy_plan_cannot_delete_replacement_manifest_or_blob() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"old-tarball").await;
        seed_npm_version(&storage, prefix, "pkg", "2.0.0", b"newer-version").await;
        let group = collect_npm_versions(&storage)
            .await
            .into_iter()
            .find(|group| group.group_name == "npm:npm-private:pkg")
            .unwrap();
        let rule = RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        };
        let plans = plan_deletions(group.versions.clone(), &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.0.0");

        // Model write_policy=allow replacing the same version after scan and
        // before retention acquires the package publish lock.
        let (replacement_manifest, replacement_blob) =
            seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"replacement-tarball").await;
        let replacement_manifest_bytes = storage.get(&replacement_manifest).await.unwrap();

        let outcome = apply_npm_plans(&storage, &test_publish_locks(), &group, &plans).await;

        assert_eq!(outcome.applied_versions, 0);
        assert_eq!(outcome.deleted_keys, 0);
        assert_eq!(
            storage.get(&replacement_manifest).await.unwrap(),
            replacement_manifest_bytes
        );
        assert!(storage.get(&replacement_blob).await.is_ok());
    }

    #[tokio::test]
    async fn npm_tag_introduced_after_plan_skips_whole_package_batch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (manifest, blob) = seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"old").await;
        seed_npm_version(&storage, prefix, "pkg", "2.0.0", b"new").await;
        let group = collect_npm_versions(&storage)
            .await
            .into_iter()
            .find(|group| group.group_name == "npm:npm-private:pkg")
            .unwrap();
        let rule = RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        };
        let plans = plan_deletions(group.versions.clone(), &rule, NOW);
        let tag = format!("{prefix}/dist-tags/stable");
        storage.put(&tag, b"1.0.0").await.unwrap();

        let outcome = apply_npm_plans(&storage, &test_publish_locks(), &group, &plans).await;

        assert_eq!(outcome.applied_versions, 0);
        assert_eq!(outcome.deleted_keys, 0);
        assert!(storage.get(&manifest).await.is_ok());
        assert!(storage.get(&blob).await.is_ok());
        assert_eq!(storage.get(&tag).await.unwrap().as_ref(), b"1.0.0");
    }

    #[tokio::test]
    async fn npm_new_version_after_plan_invalidates_package_wide_keep_last_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (old_manifest, old_blob) =
            seed_npm_version(&storage, prefix, "pkg", "1.0.0", b"old").await;
        seed_npm_version(&storage, prefix, "pkg", "2.0.0", b"new").await;
        let group = collect_npm_versions(&storage)
            .await
            .into_iter()
            .find(|group| group.group_name == "npm:npm-private:pkg")
            .unwrap();
        let rule = RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        };
        let plans = plan_deletions(group.versions.clone(), &rule, NOW);
        seed_npm_version(&storage, prefix, "pkg", "3.0.0", b"newest").await;

        let outcome = apply_npm_plans(&storage, &test_publish_locks(), &group, &plans).await;

        assert_eq!(outcome.applied_versions, 0);
        assert_eq!(outcome.deleted_keys, 0);
        assert!(storage.get(&old_manifest).await.is_ok());
        assert!(storage.get(&old_blob).await.is_ok());
    }

    #[tokio::test]
    async fn npm_target_tag_delete_failure_keeps_manifest_tag_and_blob() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (manifest, blob) = seed_npm_version(&inner, prefix, "pkg", "1.0.0", b"old").await;
        seed_npm_version(&inner, prefix, "pkg", "2.0.0", b"new").await;
        let completion = format!("{prefix}/publish-complete/1.0.0");
        let tag = format!("{prefix}/dist-tags/stable");
        inner.put(&completion, b"completed").await.unwrap();
        inner.put(&tag, b"1.0.0").await.unwrap();
        let backend = crate::test_helpers::FaultInjectBackend::new(inner.clone()).fail_delete(&tag);
        let attempts = backend.delete_attempts();
        let storage = Storage::from_backend(Arc::new(backend));
        let group = collect_npm_versions(&storage)
            .await
            .into_iter()
            .find(|group| group.group_name == "npm:npm-private:pkg")
            .unwrap();
        let rule = RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            exclude_tags: vec![],
        };
        let plans = plan_deletions(group.versions.clone(), &rule, NOW);

        let outcome = apply_npm_plans(&storage, &test_publish_locks(), &group, &plans).await;

        assert_eq!(outcome.applied_versions, 0);
        assert_eq!(outcome.deleted_keys, 1);
        assert!(
            inner.get(&completion).await.is_err(),
            "publish-complete must be removed first so an exact retry repairs partial state"
        );
        assert_eq!(inner.get(&tag).await.unwrap().as_ref(), b"1.0.0");
        assert!(inner.get(&manifest).await.is_ok());
        assert!(inner.get(&blob).await.is_ok());
        let attempts = attempts.lock();
        assert_eq!(
            attempts.first(),
            Some(&crate::npm_layout::hosted_packument_cache_key(
                "npm-private",
                "pkg"
            )),
            "derived cache must be invalidated before authoritative state changes"
        );
        assert_eq!(attempts.get(1), Some(&completion));
        assert_eq!(attempts.get(2), Some(&tag));
        assert!(!attempts.contains(&manifest));
        assert!(!attempts.contains(&blob));
    }

    #[tokio::test]
    async fn empty_npm_package_cleanup_is_discoverable_and_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let package_key = "npm/repositories/npm-private/pkg/pkg.json";
        inner.put(package_key, br#"{"name":"pkg"}"#).await.unwrap();
        let failing = Storage::from_backend(Arc::new(
            crate::test_helpers::FaultInjectBackend::new(inner.clone()).fail_delete(package_key),
        ));
        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(0),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let first = run_retention(&failing, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(first.planned, 0);
        assert!(inner.get(package_key).await.is_ok());

        let second = run_retention(&inner, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(second.planned, 0);
        assert!(inner.get(package_key).await.is_err());
        assert_eq!(second.deleted_keys, 1);
    }

    #[tokio::test]
    async fn test_retention_npm_missing_listing_metadata_skips_age_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (manifest, tarball) =
            seed_npm_version(&inner, prefix, "pkg", "1.0.0", b"tarball").await;
        let storage = Storage::from_backend(Arc::new(
            crate::test_helpers::FaultInjectBackend::new(inner.clone()).stat_none(&manifest),
        ));
        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: None,
            older_than_days: Some(0),
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 0);
        assert!(inner.get(&manifest).await.is_ok());
        assert!(inner.get(&tarball).await.is_ok());
    }

    #[tokio::test]
    async fn test_retention_npm_tag_read_failure_skips_whole_package() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let prefix = "npm/repositories/npm-private/pkg";
        let (manifest, tarball) =
            seed_npm_version(&inner, prefix, "pkg", "1.0.0", b"tarball").await;
        let tag = format!("{prefix}/dist-tags/stable");
        inner.put(&tag, b"1.0.0").await.unwrap();
        let storage = Storage::from_backend(Arc::new(
            crate::test_helpers::FaultInjectBackend::new(inner.clone()).fail_get(&tag),
        ));
        let rules = vec![RetentionRule {
            registry: "npm".to_string(),
            name_glob: None,
            keep_last: Some(0),
            older_than_days: None,
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;

        assert_eq!(result.planned, 0);
        assert!(inner.get(&manifest).await.is_ok());
        assert!(inner.get(&tarball).await.is_ok());
        assert!(inner.get(&tag).await.is_ok());
    }

    /// The scheduler must run once at boot, not a full interval later — a
    /// process that restarts more often than the interval otherwise never
    /// runs retention at all.
    #[tokio::test]
    async fn test_scheduler_runs_at_boot() {
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
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_retention_scheduler(
            storage.clone(),
            test_publish_locks(),
            None,
            MavenConfig::default(),
            Arc::new(crate::repo_index::RepoIndex::new()),
            rules,
            86400, // the boot run must not wait for this
            false,
            None,
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );

        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while storage.get("maven/com/test/a/1.0/a.jar").await.is_ok() {
            assert!(Instant::now() < deadline, "boot run never fired");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(storage.get("maven/com/test/a/2.0/a.jar").await.is_ok());
        cancel.cancel();
        handle.await.unwrap();
    }

    /// The boot pass waits on the shared cleanup lock instead of the
    /// periodic skip-if-held — losing the boot race to GC must delay the
    /// first run, not forfeit it for a whole interval.
    #[tokio::test]
    async fn test_boot_run_waits_for_cleanup_lock() {
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
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_retention_scheduler(
            storage.clone(),
            test_publish_locks(),
            None,
            MavenConfig::default(),
            Arc::new(crate::repo_index::RepoIndex::new()),
            rules,
            86400,
            false,
            None,
            cleanup_lock,
            cancel.clone(),
        );

        // While the lock is held the boot pass must be parked, not skipped.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(storage.get("maven/com/test/a/1.0/a.jar").await.is_ok());

        drop(held);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while storage.get("maven/com/test/a/1.0/a.jar").await.is_ok() {
            assert!(
                Instant::now() < deadline,
                "boot run skipped instead of waiting for the lock"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        cancel.cancel();
        handle.await.unwrap();
    }

    /// A shutdown requested while the boot pass is parked on the cleanup lock
    /// must break promptly — not wait out the lock holder and then run a full
    /// pass after cancellation was already requested.
    #[tokio::test]
    async fn test_retention_boot_run_cancels_while_parked() {
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
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_retention_scheduler(
            storage.clone(),
            test_publish_locks(),
            None,
            MavenConfig::default(),
            Arc::new(crate::repo_index::RepoIndex::new()),
            rules,
            86400,
            false,
            None,
            cleanup_lock,
            cancel.clone(),
        );

        // Let the boot pass reach the parked lock().await, then ask to stop.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        cancel.cancel();

        // The scheduler must stop even though the lock is still held — the boot
        // acquire races cancellation, so it can't block behind the holder.
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("scheduler did not stop when cancelled while parked on the boot lock")
            .unwrap();

        // It never acquired the lock, so it never pruned the dominated version.
        assert!(storage.get("maven/com/test/a/1.0/a.jar").await.is_ok());
        drop(held);
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
            find_matching_rule(&rules, "rpm", "rpm:app-dev-x1/x86_64/pkg")
                .map(|r| r.older_than_days),
            Some(Some(7))
        );
        assert_eq!(
            find_matching_rule(&rules, "rpm", "rpm:app-stream-x/x86_64/pkg").map(|r| r.keep_last),
            Some(Some(25))
        );
        assert!(
            find_matching_rule(&rules, "rpm", "rpm:app-release/x86_64/pkg").is_none(),
            "no rule = keep forever"
        );
    }

    #[test]
    fn test_npm_name_glob_preserves_package_match_and_can_qualify_repository() {
        let package_rule = rule("npm", Some("@scope/*"), Some(5), None);
        assert!(find_matching_rule(
            std::slice::from_ref(&package_rule),
            "npm",
            "npm:npm-private:@scope/pkg"
        )
        .is_some());
        assert!(find_matching_rule(
            std::slice::from_ref(&package_rule),
            "npm",
            "npm:other-hosted:@scope/pkg"
        )
        .is_some());

        let repository_rule = rule("npm", Some("npm-private:@scope/*"), Some(1), None);
        assert!(find_matching_rule(
            std::slice::from_ref(&repository_rule),
            "npm",
            "npm:npm-private:@scope/pkg"
        )
        .is_some());
        assert!(find_matching_rule(
            std::slice::from_ref(&repository_rule),
            "npm",
            "npm:other-hosted:@scope/pkg"
        )
        .is_none());
    }

    fn build_rpm(name: &str, version: &str) -> Vec<u8> {
        build_rpm_arch(name, version, "x86_64")
    }

    fn build_rpm_arch(name: &str, version: &str, arch: &str) -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new(name, version, "MIT", arch, "t")
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

    /// `keep_last` counts per architecture: each `binary-{arch}/Packages` is
    /// an independent APT index, so two architectures of the same
    /// package/version/distribution must not share one `keep_last` budget —
    /// pooling them always evicts an arch once `keep_last < arch count`.
    #[tokio::test]
    async fn test_deb_keep_last_counts_per_architecture() {
        let ctx = create_test_context();
        for arch in ["amd64", "arm64"] {
            let deb = crate::registry::deb::test_fixtures::build_deb_arch("tree", "1.8", arch);
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/deb/myrepo/pool/tree_1.8_{arch}.deb?distribution=jammy"),
                deb,
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }

        let rules = vec![rule("deb", None, Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(
            result.planned, 0,
            "one version per arch — nothing exceeds keep_last"
        );

        for arch in ["amd64", "arm64"] {
            let packages = String::from_utf8(
                body_bytes(
                    send(
                        &ctx.app,
                        Method::GET,
                        &format!("/deb/myrepo/dists/jammy/main/binary-{arch}/Packages"),
                        "",
                    )
                    .await,
                )
                .await
                .to_vec(),
            )
            .unwrap();
            assert!(packages.contains("Package: tree\n"), "{arch}: {packages}");
        }
    }

    /// rpm mirror of the per-architecture scope: one repodata, but `keep_last`
    /// must still not collapse architectures into one budget.
    #[tokio::test]
    async fn test_rpm_keep_last_counts_per_architecture() {
        let ctx = create_test_context();
        for arch in ["x86_64", "aarch64"] {
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/rpm/prod/pkg-1.0.{arch}.rpm"),
                build_rpm_arch("pkg", "1.0", arch),
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
        assert_eq!(
            result.planned, 0,
            "one version per arch — nothing exceeds keep_last"
        );
        let keys = ctx.state.storage.list("rpm/prod/").await.unwrap();
        assert_eq!(keys.iter().filter(|k| k.ends_with(".rpm")).count(), 2);
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
