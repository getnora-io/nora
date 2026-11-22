//! Retention policies — keep_last, age-based, tag exclusion.
//!
//! Pure `plan_deletions` function determines what to delete.
//! CLI commands: `nora retention plan` (dry-run) and `nora retention apply`.
//!
//! Retention is per-registry and operates on "versions" (Maven versions,
//! Docker tags, npm tarballs, PyPI files, Cargo versions, Go modules).

use std::sync::LazyLock;
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
    /// The version's `modified` the plan was made from: a version whose writers hold a lock
    /// other than its keys' is deleted only if it still reads the same under that lock.
    pub modified: u64,
}

/// Plan which versions to delete based on retention rules.
///
/// This is a **pure function** — no I/O, no side effects. Easy to test.
///
/// Rules applied as AND:
/// - `keep_last`: keep the N most recent versions (by modified time)
/// - `older_than_days`: only delete versions older than X days
/// - `include_tags`: nonempty glob patterns restrict eligible version names
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
    let mut non_excluded_pos: usize = 0;

    for version in &versions {
        // An explicit scope protects unknown names, including future releases.
        // Nonmatching names do not consume the eligible keep_last budget.
        if !rule.include_tags.is_empty() && !is_excluded(&version.name, &rule.include_tags) {
            continue;
        }
        // Check exclusion patterns — excluded versions are invisible to keep_last (#926)
        if is_excluded(&version.name, &rule.exclude_tags) {
            continue;
        }

        let mut dominated = false;
        let mut reason_parts = Vec::new();

        // keep_last: versions beyond the Nth newest non-excluded are candidates
        if let Some(keep_last) = rule.keep_last {
            if non_excluded_pos >= keep_last as usize {
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
                modified: version.modified,
            });
        }
        non_excluded_pos += 1;
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
        // maven/{group...}/{artifact}/{version}/{file}, read the way the registry reads which
        // versions an artifact stores (#1291).
        let Some(file) = crate::registry::MavenVersionFile::parse(key) else {
            continue;
        };
        artifacts
            .entry(format!("{}/{}", file.group_path, file.artifact_id))
            .or_default()
            .entry(file.version.to_string())
            .or_default()
            .push(key.clone());
    }
    // Metadata documents are never a version's keys: the path alone does not tell a version-level
    // document (a SNAPSHOT's) from an artifact-level one (`g/a/maven-metadata.xml` reads as
    // artifact `g`, version `a`), and only its content does. Retention reconciles both after the
    // deletions: an artifact's document from its files, a retired SNAPSHOT's by removing it once
    // no file of the version is left (#1281).

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
/// (never the .rpm payloads). Group = `rpm:{repo}/{arch}/{package-name}`;
/// each version's keys are the package file and its sidecar. Deleting a
/// version therefore requires the post-delete index regeneration in
/// `run_retention`.
async fn collect_rpm_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "rpm", rpm_sidecar_version).await
}

fn rpm_sidecar_version(v: &serde_json::Value) -> SidecarVersion {
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
}

/// Collect deb package versions per repository — deb counterpart of
/// [`collect_rpm_versions`], same keys/regeneration contract. Structured
/// packages group per placement and architecture
/// (`deb:{repo}/{dist}/{component}/{arch}/{package}`), matching how
/// `regenerate_indexes` rebuilds one index per distribution × architecture;
/// flat-root packages group as `deb:{repo}/{arch}/{package}`.
async fn collect_deb_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    collect_sidecar_versions(storage, "deb", deb_sidecar_version).await
}

fn deb_sidecar_version(v: &serde_json::Value) -> SidecarVersion {
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
    parse: fn(&serde_json::Value) -> SidecarVersion,
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
        if let Some((group, entry)) = sidecar_version(storage, registry, key, parse).await {
            groups.entry(group).or_default().push(entry);
        }
    }
    groups.into_iter().collect()
}

/// The group and version a sidecar key (`{registry}/{repo}/.nora-meta/{path}.json`) stands for,
/// read the way retention plans from it; `None` for any other key, and for a sidecar that is
/// unreadable, unparsable or describes another file (the version is kept).
async fn sidecar_version(
    storage: &Storage,
    registry: &str,
    key: &str,
    parse: fn(&serde_json::Value) -> SidecarVersion,
) -> Option<(String, VersionEntry)> {
    let rest = key.strip_prefix(registry)?.strip_prefix('/')?;
    let (repo, meta_rest) = rest.split_once("/.nora-meta/")?;
    let pkg_path = meta_rest.strip_suffix(".json")?;
    let Ok(data) = storage.get(key).await else {
        tracing::warn!(key = %key, "retention: sidecar unreadable — version skipped (kept)");
        return None;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) else {
        tracing::warn!(key = %key, "retention: sidecar unparsable — version skipped (kept)");
        return None;
    };
    let sv = parse(&json);
    if sv.package.is_empty() || sv.href != pkg_path {
        // href/path divergence means the sidecar does not describe this
        // package file — leave it for `-/reindex` to reconcile.
        tracing::warn!(key = %key, "retention: sidecar/package mismatch — version skipped (kept)");
        return None;
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
    Some((
        group,
        VersionEntry {
            name: sv.version,
            keys: vec![package_key, key.to_string()],
            modified,
            size: sv.size,
        },
    ))
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

/// Collect Hugging Face cached files (#579): one group per repository (`hf:{repo}`), one
/// version per file the Hub named by its digest (`hf/models/{repo}/blobs/{digest}`), dated
/// by when it was cached. The format is pull-through only, so every file is a copy the next
/// download fetches again: `older_than_days` bounds how long one is kept, `keep_last` how
/// many files of a repository are.
async fn collect_hf_versions(storage: &Storage) -> Vec<(String, Vec<VersionEntry>)> {
    let keys = match storage.list_with_meta("hf/models/").await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to list hf/models/ keys: {}", e);
            return Vec::new();
        }
    };
    let mut groups: std::collections::HashMap<String, Vec<VersionEntry>> =
        std::collections::HashMap::new();
    for (key, meta) in &keys {
        let Some((repo, digest)) = key
            .strip_prefix("hf/models/")
            .and_then(|rest| rest.rsplit_once("/blobs/"))
        else {
            continue;
        };
        if repo.is_empty() || digest.is_empty() || digest.contains('/') {
            continue;
        }
        groups
            .entry(format!("hf:{repo}"))
            .or_default()
            .push(VersionEntry {
                name: digest.to_string(),
                keys: vec![key.clone()],
                modified: meta.modified,
                size: meta.size,
            });
    }
    groups.into_iter().collect()
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
                // Digest copies (sha256:…), stored beside the tag by put_manifest, must not
                // consume keep_last budget (#932); sidecars are not tags either.
                if let Some(tag) = crate::registry::docker::tag_from_manifest_file(tag_file) {
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
            // A version is its whole key set, not just the payload: the
            // `.sha256` sidecar and the per-version document describe the same
            // artifact, and leaving either behind makes the registry advertise
            // a version it can no longer serve (#961).
            let mut keys = vec![key.clone()];
            let hash_key = format!("{}.sha256", key);
            if storage.stat(&hash_key).await.is_some() {
                keys.push(hash_key);
            }
            // Provenance sidecar of a proxied tarball (#1055, under an internal prefix
            // that list() hides): part of the version too.
            let origin_key = crate::registry::npm::origin_key(key);
            if storage.stat(&origin_key).await.is_some() {
                keys.push(origin_key);
            }
            if let Some(version) = crate::curation::parse_npm_tarball_version(pkg, filename) {
                let version_key = format!("npm/{}/versions/{}.json", pkg, version);
                if storage.stat(&version_key).await.is_some() {
                    keys.push(version_key);
                }
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

    // Hash markers live outside `pypi/`, one directory per file:
    // `pypi-sha256/<project>/<filename>/<sha256>`. A retired file takes them with it.
    let marker_root = crate::registry::PYPI_HASH_MARKER_PREFIX;
    let marker_keys = storage.list(marker_root).await.unwrap_or_else(|e| {
        tracing::error!("Failed to list {} keys: {}", marker_root, e);
        Vec::new()
    });
    let mut markers: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();
    for marker in &marker_keys {
        if let Some((file, _)) = marker
            .strip_prefix(marker_root)
            .and_then(|rest| rest.rsplit_once('/'))
        {
            markers.entry(file).or_default().push(marker.clone());
        }
    }

    // Records that a file is NORA's own live outside `pypi/` too:
    // `pypi-own/<project>/files/<filename>`. A retired file takes its record with it, so a
    // file stored later under the same name is not taken for the project's own.
    let own_root = crate::registry::PYPI_OWN_PREFIX;
    let own_records: std::collections::HashSet<String> = storage
        .list(own_root)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to list {} keys: {}", own_root, e);
            Vec::new()
        })
        .into_iter()
        .collect();

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
            if let Some(file_markers) = markers.get(format!("{pkg}/{filename}").as_str()) {
                keys.extend(file_markers.iter().cloned());
            }
            let own = crate::registry::pypi_own_file_key(pkg, filename);
            if own_records.contains(&own) {
                keys.push(own);
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
        // A version is exactly cargo/{crate}/{version}/{crate}-{version}.crate. Every other cargo
        // key — the sparse index, its per-version entries and the records beside it, metadata.json —
        // is not a version of a crate, whatever its path looks like.
        if let Some(rest) = key.strip_prefix("cargo/") {
            if let [crate_name, version, file] = rest.split('/').collect::<Vec<_>>()[..] {
                if file == format!("{crate_name}-{version}.crate") {
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
    all_groups.extend(collect_hf_versions(storage).await);

    let mut all_plans: Vec<(String, Vec<DeletionPlan>)> = Vec::new();
    let mut total_planned = 0usize;
    let mut total_deleted_keys = 0usize;
    let mut total_bytes = 0u64;
    // rpm/deb repos whose packages were deleted — their indexes must be
    // rebuilt (and re-signed) afterwards or they keep advertising ghosts.
    // npm packages retention touched, with the versions it removed from each.
    let mut npm_regen: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    // Maven artifacts (`group/path/artifact`) retention touched, with the versions it removed.
    let mut maven_regen: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let mut regen: std::collections::BTreeSet<(&'static str, String)> =
        std::collections::BTreeSet::new();

    for (group_name, versions) in all_groups {
        // Find matching rule for this group
        let registry = group_name.split(':').next().unwrap_or("");
        let rule = match find_matching_rule(rules, registry, &group_name) {
            Some(r) => r,
            None => continue,
        };

        let mut plans = plan_deletions(versions, rule, now);
        if plans.is_empty() {
            continue;
        }

        if !dry_run {
            // Only the plans carried out are deleted versions: one whose version changed
            // since it was planned is kept, and reported nowhere as deleted.
            let mut deleted = Vec::with_capacity(plans.len());
            for plan in plans {
                let Some(keys) = delete_plan_keys(storage, publish_locks, &group_name, &plan).await
                else {
                    continue;
                };
                total_deleted_keys += keys;
                total_bytes += plan.size;
                info!(
                    group = %group_name,
                    version = %plan.version_name,
                    reason = %plan.reason,
                    "Retention: deleted"
                );
                deleted.push(plan);
            }
            plans = deleted;
            if plans.is_empty() {
                continue;
            }
            if let Some(artifact) = group_name.strip_prefix("maven:") {
                maven_regen
                    .entry(artifact.to_string())
                    .or_default()
                    .extend(plans.iter().map(|plan| plan.version_name.clone()));
            }
            if let Some(package) = group_name.strip_prefix("npm:") {
                npm_regen
                    .entry(package.to_string())
                    .or_default()
                    .extend(plans.iter().filter_map(|plan| {
                        crate::curation::parse_npm_tarball_version(package, &plan.version_name)
                    }));
            }
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

        total_planned += plans.len();
        all_plans.push((group_name, plans));
    }

    // Reconcile the packument of every npm package retention touched, for the
    // same reason the rpm/deb rebuild below exists: the index is derived, and
    // leaving it describing deleted artifacts makes the registry promise
    // versions it can no longer serve (#961). A published package is regenerated
    // from `versions/`; a dangling dist-tag pointer is dropped first, so the
    // regenerated `latest` is derived from what survives rather than pointing at
    // a retired version. A proxied package has no `versions/` keys: the retired
    // versions are removed from its cached upstream packument instead.
    //
    // Fail-open per package: a failed regeneration logs and the next publish or
    // read heals it (a read rebuilds a *missing* packument, #956); the
    // deletions themselves are already durable.
    for (package, retired) in &npm_regen {
        let lock_key = crate::registry::npm::published_packument_key(package);
        let lock = crate::acquire_publish_lock(publish_locks, &lock_key);
        let _guard = lock.lock().await;

        let dist_tags_prefix = format!("npm/{package}/dist-tags/");
        for tag_key in storage.list(&dist_tags_prefix).await.unwrap_or_default() {
            let Ok(data) = storage.get(&tag_key).await else {
                continue;
            };
            let Ok(version) = String::from_utf8(data.to_vec()) else {
                continue;
            };
            let version_key = format!("npm/{package}/versions/{}.json", version.trim());
            if storage.stat(&version_key).await.is_none() && storage.delete(&tag_key).await.is_ok()
            {
                info!(package = %package, tag = %tag_key, version = %version.trim(),
                    "retention: dropped dist-tag pointing at a retired version");
            }
        }

        match crate::registry::npm::reconcile_packument_after_retention(storage, package, retired)
            .await
        {
            Ok(()) => {
                info!(registry = "npm", package = %package, "retention: packument reconciled")
            }
            Err(e) => tracing::error!(registry = "npm", package = %package, error = %e,
                "retention: packument reconciliation failed — the next publish or read heals it"),
        }
    }

    reconcile_maven_metadata(storage, publish_locks, &maven_regen).await;

    // Rebuild + re-sign the indexes of every rpm/deb repo retention touched,
    // under the same per-repo publish lock the handlers use. Fail-open per
    // repo: a failed rebuild logs loudly and the next publish/reindex heals
    // it; the deletions themselves are already durable.
    for (fmt, repo) in &regen {
        let is_rpm = matches!(
            crate::registry_type::RegistryType::from_str_opt(fmt),
            Some(crate::registry_type::RegistryType::Rpm)
        );
        let lock_key = if is_rpm {
            crate::registry::rpm::repo_publish_lock_key(repo)
        } else {
            crate::registry::deb::repo_publish_lock_key(repo)
        };
        let lock = crate::acquire_publish_lock(publish_locks, &lock_key);
        let _guard = lock.lock().await;
        let result = if is_rpm {
            crate::registry::rpm::regenerate_repodata(storage, signer, repo).await
        } else {
            crate::registry::deb::regenerate_indexes(storage, signer, repo).await
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

/// How the writers of a group's versions are serialized, when it is not by the lock of each key:
/// the lock they hold while they write a version, and with it how the version is read again
/// under that lock. An rpm or deb upload stores the package and its sidecar under the
/// repository's lock (#1298), a Maven deploy stores a file and its checksums under the artifact's
/// metadata lock, a PyPI upload stores a file, its `.sha256`, its hash marker and the record that
/// it is the project's own under the lock of the file's key (the plan's first).
enum Writers {
    /// An rpm or deb repository, and how its sidecars read.
    Repository {
        lock: String,
        registry: crate::registry_type::RegistryType,
        parse: fn(&serde_json::Value) -> SidecarVersion,
    },
    /// A Maven artifact.
    MavenArtifact { lock: String },
    /// A PyPI file of `project`.
    PypiFile { lock: String, project: String },
}

impl Writers {
    /// The writers of the versions of `group_name` (`{registry}:{name}`), `plan` being one of
    /// them; `None` for a format whose versions are deleted under each key's lock alone.
    fn of(group_name: &str, plan: &DeletionPlan) -> Option<Self> {
        use crate::registry_type::RegistryType;
        let (registry, name) = group_name.split_once(':')?;
        let registry = RegistryType::from_str_opt(registry)?;
        match registry {
            RegistryType::Rpm => Some(Self::Repository {
                lock: crate::registry::rpm::repo_publish_lock_key(name.split('/').next()?),
                registry,
                parse: rpm_sidecar_version,
            }),
            RegistryType::Deb => Some(Self::Repository {
                lock: crate::registry::deb::repo_publish_lock_key(name.split('/').next()?),
                registry,
                parse: deb_sidecar_version,
            }),
            RegistryType::Maven => {
                let (group_path, artifact_id) = name.rsplit_once('/')?;
                Some(Self::MavenArtifact {
                    lock: crate::registry::maven_artifact_metadata_lock_key(
                        group_path,
                        artifact_id,
                    ),
                })
            }
            RegistryType::PyPI => Some(Self::PypiFile {
                lock: plan.keys.first()?.clone(),
                project: name.to_string(),
            }),
            RegistryType::Docker
            | RegistryType::Npm
            | RegistryType::Cargo
            | RegistryType::Go
            | RegistryType::Raw
            | RegistryType::Gems
            | RegistryType::Terraform
            | RegistryType::Ansible
            | RegistryType::Nuget
            | RegistryType::PubDart
            | RegistryType::Conan
            | RegistryType::Cpan
            | RegistryType::Composer
            | RegistryType::HuggingFace => None,
        }
    }

    /// The key of the lock the writers hold.
    fn lock_key(&self) -> &str {
        match self {
            Self::Repository { lock, .. }
            | Self::MavenArtifact { lock }
            | Self::PypiFile { lock, .. } => lock,
        }
    }
}

/// Whether a Maven version is still the files `plan` takes, as old as when it was planned. A
/// deploy that rewrote one of them changed the version's `modified`; one that added a file to
/// the version (a classifier's jar, the pom) changed its files, and deleting the planned ones
/// would leave the added file alone. A version whose files cannot be listed is not known to be
/// unchanged, and is kept.
async fn maven_version_unchanged(storage: &Storage, plan: &DeletionPlan) -> bool {
    let Some((dir, _)) = plan.keys.first().and_then(|key| key.rsplit_once('/')) else {
        return false;
    };
    let Ok(listed) = storage.list(&format!("{dir}/")).await else {
        return false;
    };
    // The version's own files: a deeper key is a file of another artifact's version.
    let mut stored: Vec<&str> = listed
        .iter()
        .map(String::as_str)
        .filter(|key| {
            key.rsplit_once('/').map(|(parent, _)| parent) == Some(dir)
                && crate::registry::MavenVersionFile::parse(key).is_some()
        })
        .collect();
    stored.sort_unstable();
    let mut planned: Vec<&str> = plan.keys.iter().map(String::as_str).collect();
    planned.sort_unstable();
    stored == planned && aggregate_meta(storage, &plan.keys).await.0 == plan.modified
}

/// Whether a PyPI file is still the keys `plan` takes, as old as when it was planned. An upload
/// that replaced the file changed its `modified` (a file is as old as the file itself, the plan's
/// first key); one that was still running when the plan was made has since stored the `.sha256`,
/// the hash marker and the record beside the file, and deleting the planned keys would leave
/// those alone. A file whose markers cannot be listed is not known to be unchanged, and is kept.
async fn pypi_file_unchanged(storage: &Storage, project: &str, plan: &DeletionPlan) -> bool {
    let Some(file_key) = plan.keys.first() else {
        return false;
    };
    let filename = file_key.rsplit('/').next().unwrap_or("");
    // The keys of the file, found the way `collect_pypi_versions` finds them.
    let mut stored = vec![file_key.clone()];
    let hash_key = format!("{file_key}.sha256");
    if storage.stat(&hash_key).await.is_some() {
        stored.push(hash_key);
    }
    let marker_root = crate::registry::PYPI_HASH_MARKER_PREFIX;
    let Ok(markers) = storage
        .list(&format!("{marker_root}{project}/{filename}/"))
        .await
    else {
        return false;
    };
    stored.extend(markers);
    let own = crate::registry::pypi_own_file_key(project, filename);
    if storage.stat(&own).await.is_some() {
        stored.push(own);
    }
    stored.sort_unstable();
    let mut planned = plan.keys.clone();
    planned.sort_unstable();
    stored == planned
        && aggregate_meta(storage, std::slice::from_ref(file_key))
            .await
            .0
            == plan.modified
}

/// Whether the version `plan` takes still reads as it did when it was planned, read under the
/// lock of its `writers` the way its collector read it: same group, name, keys and `modified`. A
/// writer that rewrote the version since (a re-upload of the same path) changed its `modified`;
/// a rewrite that leaves even that equal leaves every input of the plan equal, so the plan
/// stands.
async fn plan_still_current(
    storage: &Storage,
    writers: &Writers,
    group_name: &str,
    plan: &DeletionPlan,
) -> bool {
    match writers {
        Writers::Repository {
            registry, parse, ..
        } => {
            let Some(sidecar) = plan.keys.iter().find(|key| key.contains("/.nora-meta/")) else {
                return false;
            };
            sidecar_version(storage, registry.as_str(), sidecar, *parse)
                .await
                .is_some_and(|(group, entry)| {
                    group == group_name
                        && entry.name == plan.version_name
                        && entry.keys == plan.keys
                        && entry.modified == plan.modified
                })
        }
        Writers::MavenArtifact { .. } => maven_version_unchanged(storage, plan).await,
        Writers::PypiFile { project, .. } => pypi_file_unchanged(storage, project, plan).await,
    }
}

/// Delete the keys of one plan, so that no publish of them is interleaved: under the lock its
/// writers hold ([`Writers`]) when that is not each key's own — and then only if the version is
/// still the one planned — and each key under its own lock, as before. Returns the number of
/// keys deleted, or `None` when the version changed since it was planned and is kept.
async fn delete_plan_keys(
    storage: &Storage,
    publish_locks: &PublishLocks,
    group_name: &str,
    plan: &DeletionPlan,
) -> Option<usize> {
    // LOCK-SAFE: tokio mutexes. The writers' lock is taken before any key's, as the handlers
    // take a shorter path's lock first; no holder of a key's lock waits for the writers' lock.
    let writers = Writers::of(group_name, plan);
    let writer_lock = writers
        .as_ref()
        .map(|writers| crate::acquire_publish_lock(publish_locks, writers.lock_key()));
    let _writer_guard = match &writer_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    if let Some(writers) = &writers {
        if !plan_still_current(storage, writers, group_name, plan).await {
            info!(
                group = %group_name,
                version = %plan.version_name,
                "Retention: version changed since it was planned — kept"
            );
            return None;
        }
    }
    let writer_lock_key = writers.as_ref().map(Writers::lock_key);
    let mut deleted = 0;
    for key in &plan.keys {
        // Serialize with concurrent publish to prevent deleting
        // an artifact that is being referenced by a new publish. The writers' lock, when it is
        // a key's own (a PyPI file's), is held already.
        let lock = (writer_lock_key != Some(key.as_str()))
            .then(|| crate::acquire_publish_lock(publish_locks, key));
        let _guard = match &lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        if storage.delete(key).await.is_ok() {
            deleted += 1;
        }
    }
    Some(deleted)
}

/// Reconcile the Maven documents of the artifacts retention touched (#1281), `regen` mapping each
/// artifact (`group/path/artifact`) to the versions it lost. The document is derived too, and a
/// client resolving RELEASE, LATEST or a range from one that still lists a deleted version gets a
/// 404. Under the artifact's metadata lock, the lock its deploys take: a retired SNAPSHOT's
/// version-level document goes first (once no file of the version is left), then the artifact's
/// document drops the deleted versions; versions a hosted+proxy read merged in from an upstream
/// stay (#885). Fail-open per artifact: the deletions are already durable, a failure logs and
/// leaves the document as it was.
pub(crate) async fn reconcile_maven_metadata(
    storage: &Storage,
    publish_locks: &PublishLocks,
    regen: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
) {
    for (artifact, retired) in regen {
        let Some((group_path, artifact_id)) = artifact.rsplit_once('/') else {
            continue;
        };
        let lock_key = crate::registry::maven_artifact_metadata_lock_key(group_path, artifact_id);
        let lock = crate::acquire_publish_lock(publish_locks, &lock_key);
        let _guard = lock.lock().await;
        for version in retired {
            if let Err(e) = crate::registry::maven_reconcile_version_metadata_after_retention(
                storage,
                group_path,
                artifact_id,
                version,
            )
            .await
            {
                tracing::error!(registry = "maven", artifact = %artifact, version = %version, error = %e,
                    "retention: version-level maven-metadata.xml removal failed — it stays under the version");
            }
        }
        match crate::registry::maven_reconcile_metadata_after_retention(
            storage,
            group_path,
            artifact_id,
            retired,
        )
        .await
        {
            Ok(()) => {
                info!(registry = "maven", artifact = %artifact, "retention: maven-metadata.xml reconciled")
            }
            Err(e) => tracing::error!(registry = "maven", artifact = %artifact, error = %e,
                "retention: maven-metadata.xml reconciliation failed — it still lists the deleted versions"),
        }
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
        (r.registry == registry || (r.registry == "*" && wildcard_covers(registry)))
            && r.name_glob.as_deref().is_none_or(|g| glob_match(g, name))
    })
}

/// A `*` rule covers the registries `all` enables. An opt-in format (Hugging Face) is pruned
/// only by a rule that names it, so a wildcard written before the format existed does not
/// start deleting its cache on upgrade — `keep_last` counts files there, not versions.
fn wildcard_covers(registry: &str) -> bool {
    crate::registry_type::RegistryType::from_str_opt(registry).is_none_or(|rt| rt.in_all())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use std::sync::Arc;

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
            include_tags: Vec::new(),
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
    fn test_include_tags_scopes_retention_and_keep_budget() {
        let rule: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "docker",
            "include_tags": ["preview-*"],
            "keep_last": 1,
            "older_than_days": 14
        }))
        .unwrap();
        let versions = vec![
            make_version("future-release-format", NOW - DAY, 100),
            make_version("v1.0.0", NOW - 60 * DAY, 100),
            make_version("preview-new", NOW - 30 * DAY, 100),
            make_version("preview-old", NOW - 60 * DAY, 100),
        ];
        let plan = plan_deletions(versions, &rule, NOW);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].version_name, "preview-old");
    }

    #[test]
    fn test_include_tags_keeps_excluded_tags_and_nonmatching_names() {
        let rule: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "docker",
            "include_tags": ["preview-*", "test-*"],
            "exclude_tags": ["preview-protected"],
            "older_than_days": 14
        }))
        .unwrap();
        let versions = vec![
            make_version("preview-protected", NOW - 60 * DAY, 100),
            make_version("preview-old", NOW - 60 * DAY, 100),
            make_version("test-old", NOW - 60 * DAY, 100),
            make_version("preview-recent", NOW - DAY, 100),
            make_version("release-old", NOW - 60 * DAY, 100),
        ];
        let plan = plan_deletions(versions, &rule, NOW);
        assert_eq!(plan.len(), 2);
        assert!(plan
            .iter()
            .all(|entry| matches!(entry.version_name.as_str(), "preview-old" | "test-old")));
    }

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
    fn test_exclude_does_not_consume_keep_budget() {
        // Regression test for #926: excluded versions must not consume keep_last
        // budget. "latest" is newest and excluded; keep_last=2 should protect
        // the next 2 non-excluded versions, deleting only "1.0.0".
        let versions = vec![
            make_version("latest", NOW, 100),
            make_version("3.0.0", NOW - DAY, 200),
            make_version("2.0.0", NOW - 7 * DAY, 300),
            make_version("1.0.0", NOW - 30 * DAY, 400),
        ];
        let rule = make_rule(Some(2), None, vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "1.0.0");
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
        // Both release-* excluded, dev-build is the only non-excluded version.
        // keep_last=1 protects it — nothing to delete (#926: excluded versions
        // don't consume the keep budget).
        assert_eq!(plans.len(), 0);
    }

    // ── #926 AB matrix: exhaustive exclude_tags × keep_last interaction ──

    /// A: excluded version is newest — must not steal slot from non-excluded
    #[test]
    fn test_926_a_excluded_newest() {
        let versions = vec![
            make_version("latest", NOW, 100), // excluded, newest
            make_version("v3", NOW - DAY, 200),
            make_version("v2", NOW - 7 * DAY, 300),
            make_version("v1", NOW - 30 * DAY, 400),
        ];
        let rule = make_rule(Some(2), None, vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // keep 2 non-excluded: v3, v2 kept; v1 deleted
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    /// B: multiple excluded versions at top positions
    #[test]
    fn test_926_b_multiple_excluded_at_top() {
        let versions = vec![
            make_version("latest", NOW, 100),        // excluded
            make_version("nightly", NOW - DAY, 100), // excluded
            make_version("v3", NOW - 2 * DAY, 200),
            make_version("v2", NOW - 10 * DAY, 300),
            make_version("v1", NOW - 30 * DAY, 400),
        ];
        let rule = make_rule(Some(2), None, vec!["latest", "nightly"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // keep 2 non-excluded: v3, v2; delete v1
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    /// C: excluded version in the middle of the sorted list
    #[test]
    fn test_926_c_excluded_in_middle() {
        let versions = vec![
            make_version("v4", NOW, 100),
            make_version("stable", NOW - 5 * DAY, 200), // excluded, middle
            make_version("v3", NOW - 10 * DAY, 300),
            make_version("v2", NOW - 20 * DAY, 400),
        ];
        let rule = make_rule(Some(2), None, vec!["stable"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // keep 2 non-excluded: v4, v3; delete v2
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v2");
    }

    /// D: excluded version at bottom — no effect on keep budget
    #[test]
    fn test_926_d_excluded_at_bottom() {
        let versions = vec![
            make_version("v3", NOW, 100),
            make_version("v2", NOW - 5 * DAY, 200),
            make_version("v1", NOW - 10 * DAY, 300),
            make_version("pinned", NOW - 100 * DAY, 400), // excluded, oldest
        ];
        let rule = make_rule(Some(2), None, vec!["pinned"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // keep 2 non-excluded: v3, v2; delete v1; pinned excluded (protected)
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    /// E: all versions excluded — nothing to delete
    #[test]
    fn test_926_e_all_excluded() {
        let versions = vec![
            make_version("release-3", NOW, 100),
            make_version("release-2", NOW - 5 * DAY, 200),
            make_version("release-1", NOW - 10 * DAY, 300),
        ];
        let rule = make_rule(Some(1), None, vec!["release-*"]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert!(plans.is_empty());
    }

    /// F: no exclusions — baseline behavior unchanged
    #[test]
    fn test_926_f_no_exclusions_baseline() {
        let versions = vec![
            make_version("v3", NOW, 100),
            make_version("v2", NOW - 5 * DAY, 200),
            make_version("v1", NOW - 10 * DAY, 300),
        ];
        let rule = make_rule(Some(1), None, vec![]);
        let plans = plan_deletions(versions, &rule, NOW);
        assert_eq!(plans.len(), 2);
        let names: Vec<&str> = plans.iter().map(|p| p.version_name.as_str()).collect();
        assert!(names.contains(&"v2"));
        assert!(names.contains(&"v1"));
    }

    /// G: keep_last + older_than_days + exclusions (AND logic)
    #[test]
    fn test_926_g_keep_last_age_exclusion_and_logic() {
        let versions = vec![
            make_version("latest", NOW, 100),        // excluded
            make_version("v4", NOW - DAY, 200),      // newest non-excluded
            make_version("v3", NOW - 10 * DAY, 300), // within keep, recent
            make_version("v2", NOW - 60 * DAY, 400), // beyond keep, old → DELETE
            make_version("v1", NOW - 90 * DAY, 500), // beyond keep, old → DELETE
        ];
        let rule = make_rule(Some(2), Some(30), vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // v4 kept (pos 0), v3 kept (pos 1), v2 deleted (pos 2 + old), v1 deleted (pos 3 + old)
        assert_eq!(plans.len(), 2);
        let names: Vec<&str> = plans.iter().map(|p| p.version_name.as_str()).collect();
        assert!(names.contains(&"v2"));
        assert!(names.contains(&"v1"));
    }

    /// H: excluded version beyond keep_last + recent — still protected
    #[test]
    fn test_926_h_excluded_beyond_keep_still_protected() {
        let versions = vec![
            make_version("v3", NOW, 100),
            make_version("v2", NOW - 5 * DAY, 200),
            make_version("pinned", NOW - 50 * DAY, 300), // excluded, old, beyond keep
            make_version("v1", NOW - 60 * DAY, 400),
        ];
        let rule = make_rule(Some(2), Some(30), vec!["pinned"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // v3 kept, v2 kept, pinned excluded, v1 deleted (pos 2 + old)
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    /// I: keep_last=0 + exclusions — delete all non-excluded
    #[test]
    fn test_926_i_keep_zero_with_exclusions() {
        let versions = vec![
            make_version("latest", NOW, 100), // excluded
            make_version("v2", NOW - 5 * DAY, 200),
            make_version("v1", NOW - 10 * DAY, 300),
        ];
        let rule = make_rule(Some(0), None, vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // keep_last=0: all non-excluded deleted
        assert_eq!(plans.len(), 2);
        let names: Vec<&str> = plans.iter().map(|p| p.version_name.as_str()).collect();
        assert!(names.contains(&"v2"));
        assert!(names.contains(&"v1"));
    }

    /// J: single non-excluded version within budget — kept
    #[test]
    fn test_926_j_single_non_excluded_within_budget() {
        let versions = vec![
            make_version("latest", NOW, 100),        // excluded
            make_version("nightly", NOW - DAY, 100), // excluded
            make_version("v1", NOW - 30 * DAY, 200), // only non-excluded
        ];
        let rule = make_rule(Some(1), None, vec!["latest", "nightly"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // v1 is the only non-excluded, fits in keep_last=1
        assert!(plans.is_empty());
    }

    /// K: glob exclusion + keep_last — excluded by pattern at various positions
    #[test]
    fn test_926_k_glob_exclusion_scattered() {
        let versions = vec![
            make_version("rc-4", NOW, 100), // excluded by rc-*
            make_version("v3", NOW - 2 * DAY, 200),
            make_version("rc-3", NOW - 5 * DAY, 100), // excluded by rc-*
            make_version("v2", NOW - 10 * DAY, 300),
            make_version("rc-2", NOW - 15 * DAY, 100), // excluded by rc-*
            make_version("v1", NOW - 20 * DAY, 400),
        ];
        let rule = make_rule(Some(2), None, vec!["rc-*"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // non-excluded sorted: v3(pos 0), v2(pos 1), v1(pos 2)
        // keep 2: v3, v2 kept; v1 deleted
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    /// L: older_than_days ONLY (no keep_last) + exclusions — non_excluded_pos
    /// is irrelevant here, but verify exclusions still protect.
    #[test]
    fn test_926_l_age_only_with_exclusions() {
        let versions = vec![
            make_version("pinned", NOW - 90 * DAY, 100), // excluded, old
            make_version("v2", NOW - 60 * DAY, 200),     // old → DELETE
            make_version("v1", NOW - 5 * DAY, 300),      // recent → kept
        ];
        let rule = make_rule(None, Some(30), vec!["pinned"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // pinned excluded (protected), v2 old (deleted), v1 recent (kept)
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v2");
    }

    /// M: AND-logic protection — beyond keep_last but NOT old enough, with
    /// excluded version stealing old enumerate position. The AND gate must
    /// still protect the recent version.
    #[test]
    fn test_926_m_and_logic_recent_beyond_keep_with_exclusion() {
        let versions = vec![
            make_version("latest", NOW, 100),        // excluded
            make_version("v3", NOW - DAY, 200),      // pos 0, kept by keep
            make_version("v2", NOW - 5 * DAY, 300),  // pos 1, beyond keep BUT recent → AND protects
            make_version("v1", NOW - 60 * DAY, 400), // pos 2, beyond keep AND old → DELETE
        ];
        let rule = make_rule(Some(1), Some(30), vec!["latest"]);
        let plans = plan_deletions(versions, &rule, NOW);
        // v3: pos 0 < 1, kept
        // v2: pos 1 >= 1 (dominated by keep), but 5d < 30d (not old) → AND fails → kept
        // v1: pos 2 >= 1 (dominated by keep), 60d > 30d (old) → AND satisfied → deleted
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].version_name, "v1");
    }

    // =====================================================================
    // TRUE A/B: old (buggy) implementation vs new (fixed) implementation
    // Proves the bug exists in old code and is fixed in new code.
    // =====================================================================

    /// Clone of the pre-fix plan_deletions with the enumerate bug (#926).
    /// Used ONLY in tests to prove the before/after difference.
    fn plan_deletions_old(
        mut versions: Vec<VersionEntry>,
        rule: &RetentionRule,
        now_secs: u64,
    ) -> Vec<DeletionPlan> {
        if versions.is_empty() {
            return vec![];
        }
        versions.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| cmp_version_names(&b.name, &a.name))
        });
        let mut deletions = Vec::new();
        // BUG: enumerate index counts excluded versions
        for (i, version) in versions.iter().enumerate() {
            if is_excluded(&version.name, &rule.exclude_tags) {
                continue;
            }
            let mut dominated = false;
            let mut reason_parts = Vec::new();
            if let Some(keep_last) = rule.keep_last {
                if i >= keep_last as usize {
                    dominated = true;
                    reason_parts.push(format!("beyond keep_last={}", keep_last));
                }
            }
            if let Some(days) = rule.older_than_days {
                let threshold = now_secs.saturating_sub(days as u64 * 86400);
                if version.modified < threshold {
                    if rule.keep_last.is_none() {
                        dominated = true;
                    }
                    reason_parts.push(format!("older than {} days", days));
                } else if rule.keep_last.is_some() {
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
                    modified: version.modified,
                });
            }
        }
        deletions
    }

    /// Helper: names of deleted versions
    fn deleted_names(plans: &[DeletionPlan]) -> Vec<&str> {
        plans.iter().map(|p| p.version_name.as_str()).collect()
    }

    /// TRUE A/B: runs every scenario through BOTH implementations,
    /// prints the diff, and asserts the new code is correct.
    #[test]
    fn test_926_ab_old_vs_new() {
        struct Scenario {
            name: &'static str,
            versions: Vec<VersionEntry>,
            rule: RetentionRule,
            /// Expected deletions from the NEW (correct) implementation
            expect_new: Vec<&'static str>,
            /// Expected deletions from the OLD (buggy) implementation
            expect_old: Vec<&'static str>,
        }

        let scenarios = vec![
            Scenario {
                name: "A: excluded newest, keep_last=2",
                versions: vec![
                    make_version("latest", NOW, 100),
                    make_version("v3", NOW - DAY, 200),
                    make_version("v2", NOW - 7 * DAY, 300),
                    make_version("v1", NOW - 30 * DAY, 400),
                ],
                rule: make_rule(Some(2), None, vec!["latest"]),
                expect_new: vec!["v1"], // correct: latest invisible, v3+v2 kept, v1 deleted
                expect_old: vec!["v2", "v1"], // BUG: latest ate index 0, v2 pushed to index 2 >= 2
            },
            Scenario {
                name: "B: two excluded at top, keep_last=2",
                versions: vec![
                    make_version("latest", NOW, 100),
                    make_version("stable", NOW - DAY, 150),
                    make_version("v3", NOW - 2 * DAY, 200),
                    make_version("v2", NOW - 7 * DAY, 300),
                    make_version("v1", NOW - 30 * DAY, 400),
                ],
                rule: make_rule(Some(2), None, vec!["latest", "stable"]),
                expect_new: vec!["v1"], // correct: v3+v2 kept (budget=2)
                expect_old: vec!["v3", "v2", "v1"], // BUG: 2 excluded eat indices 0,1 → v3 at index 2 >= 2
            },
            Scenario {
                name: "C: excluded in middle, keep_last=2",
                versions: vec![
                    make_version("v3", NOW - DAY, 300),
                    make_version("latest", NOW - 2 * DAY, 100),
                    make_version("v2", NOW - 7 * DAY, 200),
                    make_version("v1", NOW - 30 * DAY, 400),
                ],
                rule: make_rule(Some(2), None, vec!["latest"]),
                expect_new: vec!["v1"], // correct: v3 (pos 0), v2 (pos 1), v1 (pos 2 → delete)
                expect_old: vec!["v2", "v1"], // BUG: latest at index 1 → v2 at index 2 >= 2
            },
            Scenario {
                name: "D: excluded at bottom (no difference)",
                versions: vec![
                    make_version("v3", NOW - DAY, 300),
                    make_version("v2", NOW - 7 * DAY, 200),
                    make_version("v1", NOW - 30 * DAY, 400),
                    make_version("latest", NOW - 60 * DAY, 100),
                ],
                rule: make_rule(Some(2), None, vec!["latest"]),
                expect_new: vec!["v1"],
                expect_old: vec!["v1"], // Same: excluded is beyond budget anyway
            },
            Scenario {
                name: "F: no exclusions baseline (no difference)",
                versions: vec![
                    make_version("v3", NOW - DAY, 300),
                    make_version("v2", NOW - 7 * DAY, 200),
                    make_version("v1", NOW - 30 * DAY, 400),
                ],
                rule: make_rule(Some(2), None, vec![]),
                expect_new: vec!["v1"],
                expect_old: vec!["v1"],
            },
            Scenario {
                name: "G: keep+age+exclusion AND logic",
                versions: vec![
                    make_version("latest", NOW, 100),
                    make_version("v3", NOW - DAY, 300),
                    make_version("v2", NOW - 5 * DAY, 200),
                    make_version("v1", NOW - 40 * DAY, 400),
                ],
                rule: make_rule(Some(1), Some(30), vec!["latest"]),
                expect_new: vec!["v1"], // correct: v3 pos 0 (kept), v2 pos 1 (beyond keep but recent→AND), v1 (old+beyond)
                expect_old: vec!["v1"], // AND-logic protects v2: 5d < 30d resets dominated even with buggy index
            },
            Scenario {
                name: "K: glob exclusion scattered",
                versions: vec![
                    make_version("release-3", NOW - DAY, 300),
                    make_version("dev-3", NOW - 2 * DAY, 200),
                    make_version("release-2", NOW - 7 * DAY, 150),
                    make_version("dev-2", NOW - 14 * DAY, 100),
                    make_version("release-1", NOW - 30 * DAY, 150),
                    make_version("dev-1", NOW - 60 * DAY, 50),
                ],
                rule: make_rule(Some(2), None, vec!["release-*"]),
                expect_new: vec!["dev-1"], // correct: dev-3 pos 0, dev-2 pos 1, dev-1 pos 2 → delete
                expect_old: vec!["dev-2", "dev-1"], // BUG: releases inflate indices
            },
        ];

        let mut any_diff = false;
        for s in &scenarios {
            let old_result = plan_deletions_old(s.versions.clone(), &s.rule, NOW);
            let new_result = plan_deletions(s.versions.clone(), &s.rule, NOW);
            let old_names = deleted_names(&old_result);
            let new_names = deleted_names(&new_result);

            let differs = old_names != new_names;
            if differs {
                any_diff = true;
            }

            eprintln!(
                "[{}] {} | OLD deletes: {:?} | NEW deletes: {:?} | {}",
                if differs { "DIFF" } else { "SAME" },
                s.name,
                old_names,
                new_names,
                if differs {
                    "<<< BUG PROVEN"
                } else {
                    "no change"
                }
            );

            // Assert old matches expected old behavior
            assert_eq!(
                old_names, s.expect_old,
                "Scenario '{}': old implementation mismatch",
                s.name
            );
            // Assert new matches expected new behavior
            assert_eq!(
                new_names, s.expect_new,
                "Scenario '{}': new implementation mismatch",
                s.name
            );
        }

        assert!(
            any_diff,
            "At least one scenario must show a difference between old and new"
        );
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

    // -- #932: Docker retention must count tags only, not digest references --

    /// collect_docker_versions must skip sha256:/sha512: digest files so that
    /// keep_last counts real OCI tags, not tag+digest pairs.
    #[tokio::test]
    async fn test_collect_docker_versions_skips_digests() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // 4 tags + 4 digest copies (as put_manifest stores them)
        for tag in ["v1", "v2", "v3", "v4"] {
            let manifest = serde_json::json!({"tag": tag});
            let body = serde_json::to_vec(&manifest).unwrap();
            let digest = format!(
                "sha256:{}",
                hex::encode(sha2::Digest::finalize(sha2::Sha256::new_with_prefix(&body)))
            );
            storage
                .put(&format!("docker/myapp/manifests/{}.json", tag), &body)
                .await
                .unwrap();
            storage
                .put(&format!("docker/myapp/manifests/{}.json", digest), &body)
                .await
                .unwrap();
        }

        let groups = super::collect_docker_versions(&storage).await;
        let myapp = groups
            .iter()
            .find(|(g, _)| g == "docker:myapp")
            .expect("group exists");
        assert_eq!(myapp.1.len(), 4, "exactly 4 tag entries, no digests");
        for entry in &myapp.1 {
            assert!(
                !entry.name.starts_with("sha256:"),
                "digest leaked: {}",
                entry.name
            );
        }
    }

    /// With digests filtered, keep_last=3 on 4 tags correctly deletes 1 tag.
    /// Before fix: 4 tags + 4 digests = 8 entries, keep_last=3 → 5 deleted
    /// (only ceil(3/2) = 2 tags survived).
    #[tokio::test]
    async fn test_docker_keep_last_correct_with_digests() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        for (i, tag) in ["v1", "v2", "v3", "v4"].iter().enumerate() {
            let manifest = serde_json::json!({"tag": tag, "i": i});
            let body = serde_json::to_vec(&manifest).unwrap();
            let digest = format!(
                "sha256:{}",
                hex::encode(sha2::Digest::finalize(sha2::Sha256::new_with_prefix(&body)))
            );
            storage
                .put(&format!("docker/img/manifests/{}.json", tag), &body)
                .await
                .unwrap();
            storage
                .put(&format!("docker/img/manifests/{}.json", digest), &body)
                .await
                .unwrap();
        }

        let rules = vec![RetentionRule {
            registry: "docker".to_string(),
            name_glob: None,
            keep_last: Some(3),
            older_than_days: None,
            include_tags: Vec::new(),
            exclude_tags: vec![],
        }];

        let result =
            super::run_retention(&storage, &test_publish_locks(), None, &rules, true).await;
        assert_eq!(
            result.planned, 1,
            "exactly 1 tag should be planned for deletion"
        );
    }

    /// #1114: a `.stats.json` pull-stats sidecar is not a tag — retention must
    /// not count it toward keep_last. With 4 tags and keep_last=3 exactly one tag
    /// is planned; if the sidecar were mistaken for a fifth tag, two would be.
    #[tokio::test]
    async fn retention_does_not_treat_the_stats_sidecar_as_a_tag() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        for (i, tag) in ["v1", "v2", "v3", "v4"].iter().enumerate() {
            let body = serde_json::to_vec(&serde_json::json!({"tag": tag, "i": i})).unwrap();
            storage
                .put(&format!("docker/img/manifests/{}.json", tag), &body)
                .await
                .unwrap();
        }
        // A pull-stats sidecar beside one tag — NOT a fifth tag.
        storage
            .put(
                "docker/img/manifests/v1.stats.json",
                b"{\"downloads\":3,\"last_pulled\":1}",
            )
            .await
            .unwrap();

        let rules = vec![RetentionRule {
            registry: "docker".to_string(),
            name_glob: None,
            keep_last: Some(3),
            older_than_days: None,
            include_tags: Vec::new(),
            exclude_tags: vec![],
        }];
        let result =
            super::run_retention(&storage, &test_publish_locks(), None, &rules, true).await;
        assert_eq!(
            result.planned, 1,
            "one real tag planned; the .stats.json sidecar is not a tag"
        );
    }

    /// 4 tags pointing at the same manifest (1 shared digest) — keep_last=3
    /// must still count 4 tags and delete 1, not be confused by the shared digest.
    #[tokio::test]
    async fn test_docker_tag_aliasing_keep_last() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        let body = b"{\"shared\": true}";
        let digest = format!(
            "sha256:{}",
            hex::encode(sha2::Digest::finalize(sha2::Sha256::new_with_prefix(body)))
        );
        // 4 tags all pointing at the same manifest
        for tag in ["latest", "stable", "v1.0", "v0.9"] {
            storage
                .put(&format!("docker/lib/manifests/{}.json", tag), body)
                .await
                .unwrap();
        }
        // 1 shared digest file
        storage
            .put(&format!("docker/lib/manifests/{}.json", digest), body)
            .await
            .unwrap();

        let groups = super::collect_docker_versions(&storage).await;
        let lib = groups
            .iter()
            .find(|(g, _)| g == "docker:lib")
            .expect("group exists");
        assert_eq!(lib.1.len(), 4, "4 tags, 0 digests");

        let rules = vec![RetentionRule {
            registry: "docker".to_string(),
            name_glob: None,
            keep_last: Some(3),
            older_than_days: None,
            include_tags: Vec::new(),
            exclude_tags: vec![],
        }];
        let result =
            super::run_retention(&storage, &test_publish_locks(), None, &rules, true).await;
        assert_eq!(result.planned, 1, "1 of 4 tags deleted with keep_last=3");
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
            include_tags: Vec::new(),
            exclude_tags: vec![],
        }];

        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        assert_eq!(result.planned, 2); // 1.0 and 2.0 deleted, 3.0 kept
        assert!(storage
            .get("maven/com/example/lib/3.0/lib-3.0.jar")
            .await
            .is_ok());
    }

    /// The cargo keys that are not crate files — per-version index entries, the sparse index and
    /// the records beside it — are not versions of a crate: no rule prunes them.
    #[tokio::test]
    async fn cargo_index_keys_are_not_crate_versions() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let service = [
            "cargo/index-entries/se/rd/serde/1.0.0.json",
            "cargo/index-entries/to/ki/tokio/1.0.0.json",
            "cargo/index-entries/3/a/abc/0.1.0.json",
            "cargo/index/se/rd/serde",
            "cargo/index/to/ki/tokio",
            "cargo/index-assembled/se/rd/serde",
            "cargo/index-assembled/to/ki/tokio",
            // One- and two-letter names: three segments, the shape of a crate file. Two of each
            // prefix, so a rule that took them for versions would prune one.
            "cargo/index/1/a",
            "cargo/index/2/ab",
            "cargo/index-assembled/1/a",
            "cargo/index-assembled/2/ab",
            "cargo/index-upstream/1/a",
            "cargo/index-upstream/2/ab",
            "cargo/index-entries/1/a/0.1.0.json",
        ];
        for key in service {
            storage.put(key, b"x").await.unwrap();
        }
        for key in [
            "cargo/serde/1.0.0/serde-1.0.0.crate",
            "cargo/tokio/1.0.0/tokio-1.0.0.crate",
            "cargo/abc/0.1.0/abc-0.1.0.crate",
            "cargo/a/0.1.0/a-0.1.0.crate",
            "cargo/ab/0.1.0/ab-0.1.0.crate",
        ] {
            storage.put(key, b"crate").await.unwrap();
        }
        let rules = vec![RetentionRule {
            registry: "cargo".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            include_tags: Vec::new(),
            exclude_tags: vec![],
        }];
        let result = run_retention(&storage, &test_publish_locks(), None, &rules, false).await;
        for key in service {
            assert!(storage.get(key).await.is_ok(), "{key} pruned");
        }
        assert_eq!(result.planned, 0, "one version per crate: nothing to prune");
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
            include_tags: Vec::new(),
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
            include_tags: Vec::new(),
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
            include_tags: Vec::new(),
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
            include_tags: Vec::new(),
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
    use sha1::Digest as _;

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
            include_tags: Vec::new(),
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
    async fn publish_npm(ctx: &crate::test_helpers::TestContext, package: &str, version: &str) {
        use base64::Engine;
        let payload = serde_json::json!({
            "name": package,
            "versions": { version: { "name": package, "version": version, "dist": {} } },
            "_attachments": {
                format!("{package}-{version}.tgz"): {
                    "data": base64::engine::general_purpose::STANDARD.encode(b"fake-tarball"),
                }
            }
        });
        let response = send(
            &ctx.app,
            Method::PUT,
            &format!("/npm/{package}"),
            axum::body::Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED, "publish {version}");
    }

    /// Versions present in the packument, from the registry's own answer.
    async fn packument_versions(
        ctx: &crate::test_helpers::TestContext,
        package: &str,
    ) -> Vec<String> {
        let response = send(&ctx.app, Method::GET, &format!("/npm/{package}"), "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        let mut versions: Vec<String> = json["versions"]
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        versions.sort();
        versions
    }

    /// Versions whose tarball still exists in storage.
    async fn stored_versions(storage: &Storage, package: &str) -> Vec<String> {
        let mut versions: Vec<String> = storage
            .list(&format!("npm/{package}/tarballs/"))
            .await
            .unwrap_or_default()
            .iter()
            .filter(|key| !key.ends_with(".sha256"))
            .filter_map(|key| {
                let filename = key.rsplit('/').next()?;
                crate::curation::parse_npm_tarball_version(package, filename)
            })
            .collect();
        versions.sort();
        versions
    }

    /// A retired PyPI file takes its hash markers with it; a surviving file keeps its own.
    #[tokio::test]
    async fn test_pypi_retention_deletes_hash_markers_with_files() {
        use sha2::Digest as _;

        let ctx = crate::test_helpers::create_test_context();
        let storage = &ctx.state.storage;
        let marker_root = crate::registry::PYPI_HASH_MARKER_PREFIX;
        let files: Vec<String> = (1..=4)
            .map(|i| format!("markpkg-1.0.{i}-py3-none-any.whl"))
            .collect();
        for file in &files {
            let content = format!("wheel {file}");
            let sha = hex::encode(sha2::Sha256::digest(content.as_bytes()));
            let key = format!("pypi/markpkg/{file}");
            storage.put(&key, content.as_bytes()).await.unwrap();
            storage
                .put(&format!("{key}.sha256"), sha.as_bytes())
                .await
                .unwrap();
            storage
                .put(&format!("{marker_root}markpkg/{file}/{sha}"), b"")
                .await
                .unwrap();
            storage
                .put(&crate::registry::pypi_own_file_key("markpkg", file), b"")
                .await
                .unwrap();
        }

        let rules = vec![rule("pypi", None, Some(2), None)];
        let result = run_retention(
            storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 2, "keep_last=2 of four files");

        let mut kept = Vec::new();
        for file in &files {
            if storage
                .stat(&format!("pypi/markpkg/{file}"))
                .await
                .is_some()
            {
                kept.push(file.as_str());
            }
        }
        assert_eq!(kept.len(), 2, "two files survive");
        let markers = storage
            .list(&format!("{marker_root}markpkg/"))
            .await
            .unwrap();
        assert_eq!(
            markers.len(),
            2,
            "one marker per surviving file: {markers:?}"
        );
        for file in &kept {
            assert!(
                markers.iter().any(|m| m.contains(&format!("/{file}/"))),
                "surviving {file} keeps its marker: {markers:?}"
            );
        }
        // So does the record that a file is NORA's own: a file stored later under a retired
        // name is not taken for one.
        let mut own = storage
            .list(&format!(
                "{}markpkg/files/",
                crate::registry::PYPI_OWN_PREFIX
            ))
            .await
            .unwrap();
        own.sort();
        let mut expected: Vec<String> = kept
            .iter()
            .map(|file| crate::registry::pypi_own_file_key("markpkg", file))
            .collect();
        expected.sort();
        assert_eq!(own, expected);
    }

    /// #961: retention deleted the tarball and left the packument advertising
    /// the version. The invariant is stated without naming which versions
    /// survive, because that depends on mtime ordering — what must hold is that
    /// the registry never promises an artifact it does not have.
    #[tokio::test]
    async fn test_npm_origin_sidecar_is_not_a_version() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        storage
            .put("npm/a/tarballs/a-1.0.0.tgz", b"tgz")
            .await
            .unwrap();
        storage
            .put(
                &crate::registry::npm::origin_key("npm/a/tarballs/a-1.0.0.tgz"),
                b"npm:https://r.example",
            )
            .await
            .unwrap();
        let groups = collect_npm_versions(&storage).await;
        let (_, versions) = groups
            .iter()
            .find(|(p, _)| p == "npm:a")
            .expect("package a");
        assert_eq!(versions.len(), 1, "the provenance sidecar is not a version");
        assert!(
            versions[0].keys.contains(&crate::registry::npm::origin_key(
                "npm/a/tarballs/a-1.0.0.tgz"
            )),
            "…but it is part of the version's key set (#961): {:?}",
            versions[0].keys
        );
    }

    #[tokio::test]
    async fn test_npm_retention_packument_matches_storage() {
        let ctx = create_test_context();
        for version in ["1.0.1", "1.0.2", "1.0.3", "1.0.4"] {
            publish_npm(&ctx, "rettest", version).await;
        }
        assert_eq!(packument_versions(&ctx, "rettest").await.len(), 4);

        let rules = vec![rule("npm", None, Some(2), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 2, "keep_last=2 of four versions");

        let advertised = packument_versions(&ctx, "rettest").await;
        let stored = stored_versions(&ctx.state.storage, "rettest").await;
        assert_eq!(
            advertised, stored,
            "the packument must advertise exactly what storage can serve"
        );
        assert_eq!(advertised.len(), 2);

        // The per-version documents go with their tarballs.
        for version in &advertised {
            assert!(
                ctx.state
                    .storage
                    .get(&format!("npm/rettest/versions/{version}.json"))
                    .await
                    .is_ok(),
                "surviving version {version} lost its document"
            );
        }
        let retired: Vec<String> = ["1.0.1", "1.0.2", "1.0.3", "1.0.4"]
            .iter()
            .map(|v| v.to_string())
            .filter(|v| !advertised.contains(v))
            .collect();
        for version in &retired {
            assert!(
                ctx.state
                    .storage
                    .get(&format!("npm/rettest/versions/{version}.json"))
                    .await
                    .is_err(),
                "retired version {version} kept its document"
            );
        }
    }

    /// A dist-tag must never point at a version that retention removed.
    #[tokio::test]
    async fn test_npm_retention_drops_dangling_dist_tag() {
        let ctx = create_test_context();
        for version in ["1.0.1", "1.0.2", "1.0.3"] {
            publish_npm(&ctx, "tagtest", version).await;
        }
        // Pin `latest` at the oldest version, which keep_last=1 will retire.
        ctx.state
            .storage
            .put("npm/tagtest/dist-tags/latest", b"1.0.1")
            .await
            .unwrap();

        let rules = vec![rule("npm", None, Some(1), None)];
        run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;

        let advertised = packument_versions(&ctx, "tagtest").await;

        // Compare the pointer against storage, not against the advertised list:
        // on a stale packument the advertised list still contains the retired
        // version, so that comparison would pass without the fix.
        let stored = stored_versions(&ctx.state.storage, "tagtest").await;
        if let Ok(pointer) = ctx.state.storage.get("npm/tagtest/dist-tags/latest").await {
            let pointer = String::from_utf8(pointer.to_vec()).unwrap_or_default();
            assert!(
                stored.iter().any(|v| *v == pointer.trim()),
                "dist-tags/latest points at {pointer:?}, whose artifact is gone; storage has {stored:?}"
            );
        }

        let response = send(&ctx.app, Method::GET, "/npm/tagtest", "").await;
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        let latest = json["dist-tags"]["latest"].as_str().unwrap_or_default();
        assert!(
            advertised.iter().any(|v| v == latest),
            "dist-tags.latest={latest} is not among the surviving versions {advertised:?}"
        );
    }

    /// A package retention did not touch keeps its packument exactly as it was.
    /// A guard against over-reach rather than a witness for the fix: it passes
    /// with or without the regeneration, and would fail if it regenerated too
    /// much.
    #[tokio::test]
    async fn test_npm_retention_leaves_untouched_package_alone() {
        let ctx = create_test_context();
        for version in ["1.0.1", "1.0.2", "1.0.3"] {
            publish_npm(&ctx, "busy", version).await;
        }
        publish_npm(&ctx, "quiet", "2.0.0").await;
        let before = ctx
            .state
            .storage
            .get("npm/quiet/metadata.json")
            .await
            .unwrap();

        let rules = vec![rule("npm", Some("busy"), Some(1), None)];
        run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;

        let after = ctx
            .state
            .storage
            .get("npm/quiet/metadata.json")
            .await
            .unwrap();
        assert_eq!(before, after, "an untouched package must not be rewritten");
        assert_eq!(packument_versions(&ctx, "quiet").await, vec!["2.0.0"]);
    }

    /// The per-version document of a cached upstream packument, as the proxy
    /// stores it (tarball URL already rewritten to this registry: the test
    /// context's public base URL, `http://127.0.0.1:0`).
    fn upstream_version_doc(package: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": package,
            "version": version,
            "dist": {
                "tarball": format!("http://127.0.0.1:0/npm/{package}/-/{package}-{version}.tgz"),
                "shasum": format!("sha1-of-{version}"),
                "integrity": format!("sha512-of-{version}"),
            }
        })
    }

    /// A proxied package as the cache leaves it: the upstream packument at
    /// `upstream/packument.json` (no `versions/` keys), and the tarballs a client happened to
    /// fetch, each with its hash sidecar and an explicit modification time in the
    /// past (`days_ago`), so `keep_last` ordering does not depend on the clock.
    async fn seed_proxied_npm(
        ctx: &crate::test_helpers::TestContext,
        package: &str,
        advertised: &[&str],
        dist_tags: serde_json::Value,
        cached: &[(&str, u64)],
    ) {
        use sha2::Digest as _;
        let versions: serde_json::Map<String, serde_json::Value> = advertised
            .iter()
            .map(|v| (v.to_string(), upstream_version_doc(package, v)))
            .collect();
        let packument = serde_json::json!({
            "name": package,
            "dist-tags": dist_tags,
            "versions": versions,
            "time": advertised.iter().map(|v| (v.to_string(), serde_json::json!("2020-01-01T00:00:00.000Z"))).collect::<serde_json::Map<_, _>>(),
        });
        let storage = &ctx.state.storage;
        storage
            .put(
                &format!("npm/{package}/upstream/packument.json"),
                &serde_json::to_vec(&packument).unwrap(),
            )
            .await
            .unwrap();
        let root = std::path::Path::new(&ctx.state.config.storage.path);
        for (version, days_ago) in cached {
            let key = format!("npm/{package}/tarballs/{package}-{version}.tgz");
            let body = format!("tarball {version}");
            storage.put(&key, body.as_bytes()).await.unwrap();
            let sha = hex::encode(sha2::Sha256::digest(body.as_bytes()));
            storage
                .put(&format!("{key}.sha256"), sha.as_bytes())
                .await
                .unwrap();
            let when = SystemTime::now() - std::time::Duration::from_secs(days_ago * 86_400);
            std::fs::File::options()
                .write(true)
                .open(root.join(&key))
                .unwrap()
                .set_modified(when)
                .unwrap();
        }
    }

    fn cached_packument_json(body: &[u8]) -> serde_json::Value {
        serde_json::from_slice(body).unwrap()
    }

    /// A proxied package keeps the versions retention left on disk in its
    /// packument, with their upstream documents unchanged. Regenerating it from
    /// `versions/` — where only published versions live — emptied it, and with
    /// the upstream unreachable `npm install` of the surviving version failed
    /// with ENOVERSIONS.
    /// A packument an older release cached at `metadata.json` is never written by retention:
    /// a rollback reads it as it was. Only 1.4.0's own cache is pruned.
    #[tokio::test]
    async fn test_npm_retention_leaves_an_older_releases_cache_alone() {
        let ctx = create_test_context();
        seed_proxied_npm(
            &ctx,
            "oldcache",
            &["6.0.0", "7.0.0"],
            serde_json::json!({ "latest": "7.0.0" }),
            &[("6.0.0", 20), ("7.0.0", 10)],
        )
        .await;
        let storage = &ctx.state.storage;
        let cached = storage
            .get("npm/oldcache/upstream/packument.json")
            .await
            .unwrap();
        storage
            .put("npm/oldcache/metadata.json", &cached)
            .await
            .unwrap();
        storage
            .delete("npm/oldcache/upstream/packument.json")
            .await
            .unwrap();

        let rules = vec![rule("npm", None, Some(1), None)];
        let result = run_retention(
            storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        assert_eq!(
            storage.get("npm/oldcache/metadata.json").await.unwrap(),
            cached
        );
        assert!(storage
            .get("npm/oldcache/upstream/packument.json")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_npm_retention_keeps_surviving_proxied_versions_in_packument() {
        let ctx = create_test_context();
        // 5.0.0 is advertised upstream but was never fetched through the proxy.
        seed_proxied_npm(
            &ctx,
            "isnum",
            &["5.0.0", "6.0.0", "7.0.0"],
            serde_json::json!({ "latest": "7.0.0", "legacy": "6.0.0" }),
            &[("6.0.0", 20), ("7.0.0", 10)],
        )
        .await;

        let rules = vec![rule("npm", None, Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1, "keep_last=1 of two cached tarballs");
        assert_eq!(
            stored_versions(&ctx.state.storage, "isnum").await,
            vec!["7.0.0"]
        );

        let response = send(&ctx.app, Method::GET, "/npm/isnum", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = cached_packument_json(&body_bytes(response).await);
        assert_eq!(
            json["versions"]["7.0.0"],
            upstream_version_doc("isnum", "7.0.0"),
            "the surviving version keeps its upstream document (dist, shasum, integrity): {json}"
        );
        assert!(
            json["versions"].get("6.0.0").is_none(),
            "the retired version is no longer advertised: {json}"
        );
        // Absence of a cached tarball is how a proxy cache normally looks; only
        // what retention removed leaves the packument (gc-respects-proxy-metadata).
        assert_eq!(
            json["versions"]["5.0.0"],
            upstream_version_doc("isnum", "5.0.0"),
            "a version retention did not remove stays as upstream advertised it: {json}"
        );
        assert_eq!(json["dist-tags"]["latest"], "7.0.0");
        assert!(
            json["dist-tags"].get("legacy").is_none(),
            "a dist-tag must not point at a removed version: {json}"
        );
    }

    /// `latest` pointing at a version retention removed is re-pointed at the
    /// highest version still advertised, as the registry does when a version is
    /// unpublished; it never names a version the packument no longer has.
    #[tokio::test]
    async fn test_npm_retention_repoints_latest_of_proxied_package() {
        let ctx = create_test_context();
        seed_proxied_npm(
            &ctx,
            "repoint",
            &["1.0.0", "1.1.0", "2.0.0"],
            serde_json::json!({ "latest": "1.1.0" }),
            &[("1.1.0", 30), ("2.0.0", 5)],
        )
        .await;

        let rules = vec![rule("npm", None, Some(1), None)];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            ctx.state.signer.as_deref(),
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 1);

        let response = send(&ctx.app, Method::GET, "/npm/repoint", "").await;
        let json = cached_packument_json(&body_bytes(response).await);
        let mut advertised: Vec<&String> = json["versions"].as_object().unwrap().keys().collect();
        advertised.sort();
        assert_eq!(advertised, ["1.0.0", "2.0.0"], "{json}");
        assert_eq!(json["dist-tags"]["latest"], "2.0.0", "{json}");
    }

    /// Retention rewrites the cached document, so the upstream validators stored
    /// for the old one must go: a conditional request answered 304 would
    /// otherwise re-serve the pruned copy as the fresh upstream packument.
    #[tokio::test]
    async fn test_npm_retention_clears_validators_of_pruned_packument() {
        let ctx = create_test_context();
        seed_proxied_npm(
            &ctx,
            "etagged",
            &["1.0.0", "2.0.0"],
            serde_json::json!({ "latest": "2.0.0" }),
            &[("1.0.0", 30), ("2.0.0", 5)],
        )
        .await;
        let storage = &ctx.state.storage;
        let meta_key = "npm/etagged/upstream/packument.json";
        crate::registry::write_validators(
            storage,
            meta_key,
            &crate::registry::Validators {
                etag: Some("\"upstream-etag\"".into()),
                last_modified: None,
                checked: None,
            },
        )
        .await;
        assert!(crate::registry::read_validators(storage, meta_key)
            .await
            .is_some());

        let rules = vec![rule("npm", None, Some(1), None)];
        run_retention(storage, &ctx.state.publish_locks, None, &rules, false).await;

        assert!(
            crate::registry::read_validators(storage, meta_key)
                .await
                .is_none(),
            "validators of the replaced document must be cleared"
        );
    }

    /// In a scope owned by a private upstream, a cached packument is served only
    /// while its provenance record matches its bytes. Retention's rewrite carries
    /// the owner's record over to the new bytes; a record that did not match the
    /// old bytes is not upgraded into one that matches.
    #[tokio::test]
    async fn test_npm_retention_carries_provenance_of_pruned_packument() {
        use sha2::Digest as _;
        let ctx = create_test_context();
        let storage = &ctx.state.storage;
        for (package, vouches) in [("trusted", true), ("foreign", false)] {
            seed_proxied_npm(
                &ctx,
                package,
                &["1.0.0", "2.0.0"],
                serde_json::json!({ "latest": "2.0.0" }),
                &[("1.0.0", 30), ("2.0.0", 5)],
            )
            .await;
            let key = format!("npm/{package}/upstream/packument.json");
            let old = storage.get(&key).await.unwrap();
            let digest = if vouches {
                hex::encode(sha2::Sha256::digest(&old))
            } else {
                "0".repeat(64)
            };
            storage
                .put(
                    &crate::registry::npm::origin_key(&key),
                    format!("npm:https://owner.example\n{digest}").as_bytes(),
                )
                .await
                .unwrap();
        }

        let rules = vec![rule("npm", None, Some(1), None)];
        run_retention(storage, &ctx.state.publish_locks, None, &rules, false).await;

        for (package, vouches) in [("trusted", true), ("foreign", false)] {
            let key = format!("npm/{package}/upstream/packument.json");
            let new = storage.get(&key).await.unwrap();
            assert!(
                cached_packument_json(&new)["versions"]
                    .get("1.0.0")
                    .is_none(),
                "{package}: pruned"
            );
            let record = storage
                .get(&crate::registry::npm::origin_key(&key))
                .await
                .unwrap();
            let record = String::from_utf8(record.to_vec()).unwrap();
            let (origin, digest) = record.split_once('\n').unwrap();
            assert_eq!(origin, "npm:https://owner.example", "{package}");
            assert_eq!(
                digest == hex::encode(sha2::Sha256::digest(&new)),
                vouches,
                "{package}: the record vouches for the new bytes only if it vouched for the old ones"
            );
        }
    }

    /// A retired version whose tarball is on disk again by the time the packument
    /// is reconciled — a client fetched it through the proxy in between — stays
    /// advertised: the packument never loses a version storage can serve.
    #[tokio::test]
    async fn test_npm_reconcile_keeps_retired_version_cached_again() {
        let ctx = create_test_context();
        seed_proxied_npm(
            &ctx,
            "refetched",
            &["1.0.0", "2.0.0", "3.0.0"],
            serde_json::json!({ "latest": "3.0.0" }),
            &[("1.0.0", 30), ("3.0.0", 5)],
        )
        .await;
        let retired: std::collections::BTreeSet<String> =
            ["1.0.0", "2.0.0"].iter().map(|v| v.to_string()).collect();
        crate::registry::npm::reconcile_packument_after_retention(
            &ctx.state.storage,
            "refetched",
            &retired,
        )
        .await
        .unwrap();

        let json = cached_packument_json(
            &ctx.state
                .storage
                .get("npm/refetched/upstream/packument.json")
                .await
                .unwrap(),
        );
        let mut advertised: Vec<&String> = json["versions"].as_object().unwrap().keys().collect();
        advertised.sort();
        assert_eq!(advertised, ["1.0.0", "3.0.0"], "{json}");
    }

    /// A package with published versions owns its packument (#975): it is
    /// assembled from `versions/`, and a tarball cached from the upstream for the
    /// same name counts toward `keep_last` but never enters it. Retention keeps
    /// that rule — it regenerates from `versions/`, whatever the cached document
    /// says.
    #[tokio::test]
    async fn test_npm_retention_mixed_package_follows_published_versions() {
        let ctx = create_test_context();
        let storage = &ctx.state.storage;
        for version in ["1.0.1", "1.0.2"] {
            publish_npm(&ctx, "mixed", version).await;
        }
        // A tarball of an upstream version cached through the proxy, oldest of all.
        let proxied = "npm/mixed/tarballs/mixed-0.9.0.tgz";
        storage.put(proxied, b"upstream tarball").await.unwrap();
        let root = std::path::Path::new(&ctx.state.config.storage.path);
        for (key, days_ago) in [
            (proxied.to_string(), 30u64),
            ("npm/mixed/tarballs/mixed-1.0.1.tgz".to_string(), 20),
            ("npm/mixed/tarballs/mixed-1.0.2.tgz".to_string(), 10),
        ] {
            std::fs::File::options()
                .write(true)
                .open(root.join(&key))
                .unwrap()
                .set_modified(SystemTime::now() - std::time::Duration::from_secs(days_ago * 86_400))
                .unwrap();
        }
        // The assembled document also names the upstream version, as a stale or
        // foreign copy would; regeneration from `versions/` must not keep it.
        let mut doc = cached_packument_json(&storage.get("npm/mixed/metadata.json").await.unwrap());
        doc["versions"]["0.8.0"] = upstream_version_doc("mixed", "0.8.0");
        storage
            .put(
                "npm/mixed/metadata.json",
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap();

        let rules = vec![rule("npm", None, Some(1), None)];
        let result = run_retention(storage, &ctx.state.publish_locks, None, &rules, false).await;
        assert_eq!(
            result.planned, 2,
            "the cached upstream tarball counts toward keep_last"
        );
        assert_eq!(stored_versions(storage, "mixed").await, vec!["1.0.2"]);
        assert_eq!(packument_versions(&ctx, "mixed").await, vec!["1.0.2"]);
    }

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

    /// Hugging Face: one group per repository, one version per cached file; only a rule
    /// that names hf applies.
    #[tokio::test]
    async fn test_hf_files_grouped_per_repository_and_pruned_by_name() {
        let ctx = create_test_context();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86400);
        for (key, aged) in [
            (
                "hf/models/org/model/blobs/1111111111111111111111111111111111111111",
                true,
            ),
            (
                "hf/models/org/model/blobs/2222222222222222222222222222222222222222",
                false,
            ),
            (
                "hf/models/gpt2/blobs/3333333333333333333333333333333333333333",
                true,
            ),
            (
                "hf/models/org/blobs/blobs/4444444444444444444444444444444444444444",
                true,
            ),
        ] {
            ctx.state.storage.put(key, b"data").await.unwrap();
            if aged {
                std::fs::File::options()
                    .write(true)
                    .open(std::path::Path::new(&ctx.state.config.storage.path).join(key))
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
        }
        let mut groups = collect_hf_versions(&ctx.state.storage).await;
        groups.sort_by(|a, b| a.0.cmp(&b.0));
        let names: Vec<(&str, usize)> = groups.iter().map(|(g, v)| (g.as_str(), v.len())).collect();
        assert_eq!(
            names,
            vec![("hf:gpt2", 1), ("hf:org/blobs", 1), ("hf:org/model", 2)]
        );

        // A wildcard rule written for the other formats leaves the opt-in cache alone.
        let wildcard = vec![rule("*", None, Some(1), Some(1))];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &wildcard,
            false,
        )
        .await;
        assert_eq!(result.planned, 0);
        assert_eq!(ctx.state.storage.list("hf/").await.unwrap().len(), 4);

        // A rule that names hf prunes what is older than its age, in the repositories it names.
        let rules = vec![rule("hf", Some("org/*"), None, Some(1))];
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &rules,
            false,
        )
        .await;
        assert_eq!(result.planned, 2);
        let mut left = ctx.state.storage.list("hf/").await.unwrap();
        left.sort();
        assert_eq!(
            left,
            vec![
                "hf/models/gpt2/blobs/3333333333333333333333333333333333333333".to_string(),
                "hf/models/org/model/blobs/2222222222222222222222222222222222222222".to_string(),
            ]
        );
    }

    #[test]
    fn a_wildcard_rule_covers_what_all_enables() {
        let rules = vec![rule("*", None, Some(1), None)];
        for registry in [
            "docker", "npm", "maven", "pypi", "cargo", "go", "rpm", "deb", "raw",
        ] {
            assert!(
                find_matching_rule(&rules, registry, &format!("{registry}:x")).is_some(),
                "{registry}"
            );
        }
        assert!(find_matching_rule(&rules, "hf", "hf:org/model").is_none());
        let named = vec![rule("hf", None, Some(1), None)];
        assert!(find_matching_rule(&named, "hf", "hf:org/model").is_some());
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

    /// The rule from #1097: Maven prerelease builds are selected by name with `include_tags`
    /// (`+` build metadata included, however the client encodes it); stable releases and a
    /// SNAPSHOT that no pattern names are kept. Local and object store.
    async fn maven_prerelease_rule_prunes_only_prereleases(ctx: crate::test_helpers::TestContext) {
        const PRERELEASES: [&str; 4] = [
            "0.14.0-dev.11+e47ab9f",
            "1.2.0-alpha.1",
            "1.2.0-beta.2",
            "1.2.0-rc.1",
        ];
        const KEPT: [&str; 3] = ["0.13.0", "1.2.0", "1.3.0-SNAPSHOT"];
        for v in KEPT.iter().chain(PRERELEASES.iter()) {
            // A client may send the build-metadata `+` percent-encoded; it is the same version.
            let path_v = v.replace('+', "%2B");
            let r = send(
                &ctx.app,
                Method::PUT,
                &format!("/maven2/com/example/app/{path_v}/app-{path_v}.jar"),
                format!("jar {v}"),
            )
            .await;
            assert_eq!(r.status(), StatusCode::CREATED, "upload {v}");
        }
        let jar_key = |v: &str| format!("maven/com/example/app/{v}/app-{v}.jar");
        for v in PRERELEASES {
            assert!(
                ctx.state.storage.stat(&jar_key(v)).await.is_some(),
                "{v} stored under its decoded name"
            );
        }

        let rule: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "maven",
            "include_tags": ["*-dev.*+*", "*-alpha*", "*-beta*", "*-rc*"],
            "keep_last": 0
        }))
        .unwrap();
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[rule],
            false,
        )
        .await;
        assert_eq!(result.planned, PRERELEASES.len(), "{:?}", result.plans);

        for v in KEPT {
            let jar = format!("/maven2/com/example/app/{v}/app-{v}.jar");
            let r = send(&ctx.app, Method::GET, &jar, "").await;
            assert_eq!(r.status(), StatusCode::OK, "{v} must survive");
        }
        for v in PRERELEASES {
            assert!(
                ctx.state.storage.stat(&jar_key(v)).await.is_none(),
                "{v} must be deleted"
            );
        }
    }

    #[tokio::test]
    async fn test_maven_prerelease_rule_local() {
        maven_prerelease_rule_prunes_only_prereleases(create_test_context()).await;
    }

    #[tokio::test]
    async fn test_maven_prerelease_rule_object_store() {
        let storage = Storage::from_backend(std::sync::Arc::new(
            crate::storage::ObjectStorage::in_memory(),
        ));
        maven_prerelease_rule_prunes_only_prereleases(
            crate::test_helpers::create_test_context_with_storage(storage),
        )
        .await;
    }

    // ── #1281: Maven metadata after retention ──────────────────────────────────────────

    fn maven_rule(include: &str) -> RetentionRule {
        serde_json::from_value(serde_json::json!({
            "registry": "maven", "include_tags": [include], "keep_last": 0
        }))
        .unwrap()
    }

    async fn maven_put(ctx: &crate::test_helpers::TestContext, path: &str, body: &str) {
        let r = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{path}"),
            body.to_string(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED, "upload {path}");
    }

    async fn maven_get(ctx: &crate::test_helpers::TestContext, path: &str) -> (StatusCode, String) {
        let r = send(&ctx.app, Method::GET, &format!("/maven2/{path}"), "").await;
        let status = r.status();
        (
            status,
            String::from_utf8_lossy(&body_bytes(r).await).into_owned(),
        )
    }

    fn xml_tag<'x>(xml: &'x str, tag: &str) -> &'x str {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open).map(|i| i + open.len()).unwrap_or(0);
        let end = xml[start..]
            .find(&close)
            .map(|i| start + i)
            .unwrap_or(start);
        &xml[start..end]
    }

    /// The artifact's `<latest>` and `<release>` jars answer 200, and the stored `.sha1` of
    /// the document matches the document.
    async fn assert_metadata_resolves(ctx: &crate::test_helpers::TestContext, artifact: &str) {
        let doc_path = format!("com/example/{artifact}/maven-metadata.xml");
        let (status, xml) = maven_get(ctx, &doc_path).await;
        assert_eq!(status, StatusCode::OK);
        for tag in ["latest", "release"] {
            let v = xml_tag(&xml, tag);
            assert!(!v.is_empty(), "<{tag}> empty:\n{xml}");
            let (status, _) = maven_get(
                ctx,
                &format!("com/example/{artifact}/{v}/{artifact}-{v}.jar"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "<{tag}>{v} does not resolve:\n{xml}"
            );
        }
        let (status, sha1) = maven_get(ctx, &format!("{doc_path}.sha1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sha1, hex::encode(sha1::Sha1::digest(xml.as_bytes())));
    }

    /// Retention that deletes Maven versions must stop advertising them: the artifact's
    /// `maven-metadata.xml` lists only versions still stored, `<latest>` and `<release>`
    /// never name a deleted one, and the next deploy does not bring a deleted one back.
    async fn maven_metadata_drops_retired_versions(ctx: crate::test_helpers::TestContext) {
        for v in ["1.0.0", "1.1.0-rc.1"] {
            maven_put(&ctx, &format!("com/example/meta/{v}/meta-{v}.jar"), v).await;
        }
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-rc*")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);

        let (_, xml) = maven_get(&ctx, "com/example/meta/maven-metadata.xml").await;
        assert!(xml.contains("<version>1.0.0</version>"), "{xml}");
        assert!(
            !xml.contains("1.1.0-rc.1"),
            "retired version still advertised:\n{xml}"
        );
        assert_metadata_resolves(&ctx, "meta").await;

        maven_put(&ctx, "com/example/meta/1.2.0/meta-1.2.0.jar", "1.2.0").await;
        let (_, xml) = maven_get(&ctx, "com/example/meta/maven-metadata.xml").await;
        assert!(
            !xml.contains("1.1.0-rc.1"),
            "next deploy brought it back:\n{xml}"
        );
        assert_metadata_resolves(&ctx, "meta").await;
    }

    #[tokio::test]
    async fn test_maven_metadata_drops_retired_versions_local() {
        maven_metadata_drops_retired_versions(create_test_context()).await;
    }

    #[tokio::test]
    async fn test_maven_metadata_drops_retired_versions_object_store() {
        let storage = Storage::from_backend(std::sync::Arc::new(
            crate::storage::ObjectStorage::in_memory(),
        ));
        maven_metadata_drops_retired_versions(
            crate::test_helpers::create_test_context_with_storage(storage),
        )
        .await;
    }

    /// A retired SNAPSHOT leaves nothing behind: its version-level `maven-metadata.xml` and
    /// checksums go with it, so the version directory is gone and nothing lists it again.
    async fn maven_retired_snapshot_leaves_no_version_metadata(
        ctx: crate::test_helpers::TestContext,
    ) {
        let base = "com/example/snap/1.0-SNAPSHOT";
        maven_put(
            &ctx,
            &format!("{base}/snap-1.0-20261117.120000-1.jar"),
            "jar",
        )
        .await;
        let version_meta = "<?xml version=\"1.0\"?><metadata modelVersion=\"1.1.0\"><groupId>com.example</groupId><artifactId>snap</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261117.120000</timestamp><buildNumber>1</buildNumber></snapshot><lastUpdated>20261117120000</lastUpdated></versioning></metadata>";
        maven_put(&ctx, &format!("{base}/maven-metadata.xml"), version_meta).await;
        maven_put(
            &ctx,
            &format!("{base}/maven-metadata.xml.sha1"),
            &hex::encode(sha1::Sha1::digest(version_meta.as_bytes())),
        )
        .await;
        maven_put(&ctx, "com/example/snap/1.1/snap-1.1.jar", "jar").await;

        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-SNAPSHOT")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        let left = ctx
            .state
            .storage
            .list("maven/com/example/snap/1.0-SNAPSHOT/")
            .await
            .unwrap();
        assert!(left.is_empty(), "retired SNAPSHOT left behind: {left:?}");

        maven_put(&ctx, "com/example/snap/1.2/snap-1.2.jar", "jar").await;
        let (_, xml) = maven_get(&ctx, "com/example/snap/maven-metadata.xml").await;
        assert!(!xml.contains("1.0-SNAPSHOT"), "{xml}");
        assert_metadata_resolves(&ctx, "snap").await;
    }

    #[tokio::test]
    async fn test_maven_retired_snapshot_leaves_no_version_metadata_local() {
        maven_retired_snapshot_leaves_no_version_metadata(create_test_context()).await;
    }

    #[tokio::test]
    async fn test_maven_retired_snapshot_leaves_no_version_metadata_object_store() {
        let storage = Storage::from_backend(std::sync::Arc::new(
            crate::storage::ObjectStorage::in_memory(),
        ));
        maven_retired_snapshot_leaves_no_version_metadata(
            crate::test_helpers::create_test_context_with_storage(storage),
        )
        .await;
    }

    /// A hosted+proxy document (#885) lists upstream versions this registry never stored.
    /// Retention removes the versions it deleted and nothing else: the upstream ones stay.
    #[tokio::test]
    async fn test_maven_retention_keeps_upstream_versions_of_merged_metadata() {
        use crate::config::MavenProxyEntry;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let upstream_metadata = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>mixed</artifactId>
  <versioning>
    <latest>0.9.0</latest>
    <release>0.9.0</release>
    <versions>
      <version>0.8.0</version>
      <version>0.9.0</version>
    </versions>
    <lastUpdated>20260728010000</lastUpdated>
  </versioning>
</metadata>
"#;
        Mock::given(method("GET"))
            .and(path("/com/example/mixed/maven-metadata.xml"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(upstream_metadata, "application/xml"),
            )
            .mount(&upstream)
            .await;
        let upstream_url = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_with_config(move |config| {
            config.maven.proxies = vec![MavenProxyEntry::Simple(upstream_url)];
            config.maven.metadata_ttl = 3600;
        });

        let (status, _) = maven_get(&ctx, "com/example/mixed/maven-metadata.xml").await;
        assert_eq!(status, StatusCode::OK);
        for v in ["1.0.0", "1.1.0-rc.1"] {
            maven_put(&ctx, &format!("com/example/mixed/{v}/mixed-{v}.jar"), v).await;
        }
        let (_, merged) = maven_get(&ctx, "com/example/mixed/maven-metadata.xml").await;
        for v in ["0.8.0", "0.9.0", "1.0.0", "1.1.0-rc.1"] {
            assert!(
                merged.contains(&format!("<version>{v}</version>")),
                "{merged}"
            );
        }

        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-rc*")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);

        let (_, xml) = maven_get(&ctx, "com/example/mixed/maven-metadata.xml").await;
        for v in ["0.8.0", "0.9.0", "1.0.0"] {
            assert!(
                xml.contains(&format!("<version>{v}</version>")),
                "version {v} dropped:\n{xml}"
            );
        }
        assert!(!xml.contains("1.1.0-rc.1"), "{xml}");
        assert_eq!(xml_tag(&xml, "latest"), "1.0.0", "{xml}");
        assert_eq!(xml_tag(&xml, "release"), "1.0.0", "{xml}");
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            1,
            "the document after retention must come from storage, not a fresh merge"
        );
    }

    /// Retention whose last version goes leaves no artifact-level document advertising it.
    #[tokio::test]
    async fn test_maven_retention_of_every_version_removes_the_document() {
        let ctx = create_test_context();
        maven_put(
            &ctx,
            "com/example/gone/1.0.0-rc.1/gone-1.0.0-rc.1.jar",
            "jar",
        )
        .await;
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-rc*")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        let left = ctx
            .state
            .storage
            .list("maven/com/example/gone/")
            .await
            .unwrap();
        assert!(left.is_empty(), "{left:?}");
    }

    /// An artifact's own `maven-metadata.xml` is never a version's key. Its path reads as
    /// artifact `com/example`, version `<artifactId>`, so two artifacts of one group would form
    /// a group of two "versions" a `keep_last` rule could prune, deleting one artifact's document.
    #[tokio::test]
    async fn test_maven_retention_never_takes_an_artifact_document_for_a_version() {
        let ctx = create_test_context();
        for artifact in ["left", "right"] {
            for v in ["1.0.0", "2.0.0"] {
                maven_put(
                    &ctx,
                    &format!("com/example/{artifact}/{v}/{artifact}-{v}.jar"),
                    v,
                )
                .await;
            }
        }
        let keep_one: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "maven", "keep_last": 1
        }))
        .unwrap();
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[keep_one],
            false,
        )
        .await;
        assert_eq!(result.planned, 2, "one version of each artifact");
        for artifact in ["left", "right"] {
            let (status, xml) =
                maven_get(&ctx, &format!("com/example/{artifact}/maven-metadata.xml")).await;
            assert_eq!(status, StatusCode::OK, "{artifact}: document deleted");
            assert_eq!(xml.matches("<version>").count(), 1, "{xml}");
            assert_metadata_resolves(&ctx, artifact).await;
        }
    }

    /// A SNAPSHOT version's `<version>` document, as maven-deploy writes it.
    fn snapshot_document(artifact: &str, timestamp: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><metadata modelVersion=\"1.1.0\"><groupId>com.example</groupId><artifactId>{artifact}</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>{timestamp}</timestamp><buildNumber>1</buildNumber></snapshot><lastUpdated>{timestamp}</lastUpdated></versioning></metadata>"
        )
    }

    /// `com.example:lib:tools` and `com.example.lib:tools:1.0` share the directory
    /// `com/example/lib/tools/`: the document of the second sits where a version `tools` of the
    /// first keeps its files. A rule for version `tools` must not take that document (#1281).
    #[tokio::test]
    async fn test_maven_retention_keeps_a_sibling_artifacts_document() {
        let ctx = create_test_context();
        maven_put(&ctx, "com/example/lib/tools/lib-tools.jar", "jar").await;
        maven_put(&ctx, "com/example/lib/tools/1.0/tools-1.0.jar", "jar").await;
        let rule: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "maven", "name_glob": "com/example/lib",
            "include_tags": ["tools"], "keep_last": 0
        }))
        .unwrap();
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[rule],
            false,
        )
        .await;
        assert_eq!(result.planned, 1, "version `tools` of com.example:lib");
        let (status, xml) = maven_get(&ctx, "com/example/lib/tools/maven-metadata.xml").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "sibling artifact's document deleted"
        );
        assert!(xml.contains("<artifactId>tools</artifactId>"), "{xml}");
    }

    /// A retired SNAPSHOT of `com.example:lib` shares its directory with the artifact-level
    /// document of `com.example.lib:1.0-SNAPSHOT`. Only the document whose `<version>` is the
    /// retired version belongs to that version; the sibling's must survive (#1281).
    #[tokio::test]
    async fn test_maven_retired_snapshot_keeps_a_sibling_artifacts_document() {
        let ctx = create_test_context();
        maven_put(
            &ctx,
            "com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
            "jar",
        )
        .await;
        maven_put(
            &ctx,
            "com/example/lib/1.0-SNAPSHOT/2.0/1.0-SNAPSHOT-2.0.jar",
            "jar",
        )
        .await;
        let rule: RetentionRule = serde_json::from_value(serde_json::json!({
            "registry": "maven", "name_glob": "com/example/lib",
            "include_tags": ["*-SNAPSHOT"], "keep_last": 0
        }))
        .unwrap();
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[rule],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        assert!(
            ctx.state
                .storage
                .stat("maven/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar")
                .await
                .is_none(),
            "retired SNAPSHOT jar kept"
        );
        let (status, xml) =
            maven_get(&ctx, "com/example/lib/1.0-SNAPSHOT/maven-metadata.xml").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "sibling artifact's document deleted"
        );
        assert!(
            xml.contains("<artifactId>1.0-SNAPSHOT</artifactId>"),
            "{xml}"
        );
    }

    /// `com.example:lib:1.0-SNAPSHOT` and `com.example.lib:1.0-SNAPSHOT:2.0` both stored: the files
    /// of the second sit under `com/example/lib/1.0-SNAPSHOT/2.0/`. Once retention removes the
    /// first's SNAPSHOT, the document of `com.example:lib` stops listing it: those files are a
    /// version of another artifact, not of `lib` (#1291).
    async fn maven_foreign_artifact_under_a_version_directory_is_not_that_version(
        ctx: crate::test_helpers::TestContext,
    ) {
        maven_put(&ctx, "com/example/lib/0.9/lib-0.9.jar", "jar").await;
        maven_put(
            &ctx,
            "com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
            "jar",
        )
        .await;
        maven_put(
            &ctx,
            "com/example/lib/1.0-SNAPSHOT/2.0/1.0-SNAPSHOT-2.0.jar",
            "jar",
        )
        .await;
        let (_, before) = maven_get(&ctx, "com/example/lib/maven-metadata.xml").await;
        assert!(
            before.contains("<version>1.0-SNAPSHOT</version>"),
            "{before}"
        );

        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-SNAPSHOT")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1, "only the SNAPSHOT of com.example:lib");

        let (status, xml) = maven_get(&ctx, "com/example/lib/maven-metadata.xml").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !xml.contains("1.0-SNAPSHOT"),
            "the retired SNAPSHOT is still listed:\n{xml}"
        );
        assert_metadata_resolves(&ctx, "lib").await;

        maven_put(&ctx, "com/example/lib/1.1/lib-1.1.jar", "jar").await;
        let (_, xml) = maven_get(&ctx, "com/example/lib/maven-metadata.xml").await;
        assert!(
            !xml.contains("1.0-SNAPSHOT"),
            "the next deploy listed the retired SNAPSHOT again:\n{xml}"
        );
        assert_metadata_resolves(&ctx, "lib").await;
        let (status, _) = maven_get(
            &ctx,
            "com/example/lib/1.0-SNAPSHOT/2.0/1.0-SNAPSHOT-2.0.jar",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the other artifact's file was deleted"
        );
    }

    #[tokio::test]
    async fn test_maven_foreign_artifact_under_a_version_directory_local() {
        maven_foreign_artifact_under_a_version_directory_is_not_that_version(create_test_context())
            .await;
    }

    #[tokio::test]
    async fn test_maven_foreign_artifact_under_a_version_directory_object_store() {
        let storage = Storage::from_backend(std::sync::Arc::new(
            crate::storage::ObjectStorage::in_memory(),
        ));
        maven_foreign_artifact_under_a_version_directory_is_not_that_version(
            crate::test_helpers::create_test_context_with_storage(storage),
        )
        .await;
    }

    /// A SNAPSHOT redeployed while retention runs keeps its new document. The plan takes the old
    /// files, a deploy writes new files and a new document under the same key, then the plan's
    /// remaining keys go: the new document must survive (#1281).
    #[tokio::test]
    async fn test_maven_snapshot_redeployed_during_retention_keeps_its_document() {
        let ctx = create_test_context();
        let storage = &ctx.state.storage;
        let base = "com/example/race/1.0-SNAPSHOT";
        maven_put(
            &ctx,
            &format!("{base}/race-1.0-20261101.000000-1.jar"),
            "old",
        )
        .await;
        maven_put(
            &ctx,
            &format!("{base}/maven-metadata.xml"),
            &snapshot_document("race", "20261101.000000"),
        )
        .await;
        maven_put(&ctx, "com/example/race/1.1/race-1.1.jar", "release").await;

        let groups = collect_maven_versions(storage).await;
        let versions = groups
            .into_iter()
            .find(|(name, _)| name == "maven:com/example/race")
            .expect("group")
            .1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let plans = plan_deletions(versions, &maven_rule("*-SNAPSHOT"), now);
        assert_eq!(plans.len(), 1);
        let (documents, files): (Vec<String>, Vec<String>) =
            plans[0].keys.iter().cloned().partition(|key| {
                key.rsplit('/')
                    .next()
                    .is_some_and(|name| name.starts_with("maven-metadata"))
            });
        for key in &files {
            storage.delete(key).await.unwrap();
        }
        maven_put(
            &ctx,
            &format!("{base}/race-1.0-20261117.120000-2.jar"),
            "new",
        )
        .await;
        maven_put(
            &ctx,
            &format!("{base}/maven-metadata.xml"),
            &snapshot_document("race", "20261117.120000"),
        )
        .await;
        for key in &documents {
            storage.delete(key).await.unwrap();
        }

        let regen = std::collections::BTreeMap::from([(
            "com/example/race".to_string(),
            std::collections::BTreeSet::from(["1.0-SNAPSHOT".to_string()]),
        )]);
        reconcile_maven_metadata(storage, &ctx.state.publish_locks, &regen).await;

        let doc = storage
            .get(&format!("maven/{base}/maven-metadata.xml"))
            .await;
        assert!(
            doc.is_ok(),
            "the new deploy's document was deleted by the plan"
        );
        let doc = String::from_utf8(doc.unwrap().to_vec()).unwrap();
        assert!(doc.contains("20261117.120000"), "{doc}");
        assert!(
            storage
                .stat(&format!("maven/{base}/race-1.0-20261117.120000-2.jar"))
                .await
                .is_some(),
            "the new deploy's jar is gone"
        );
    }

    /// The metadata lock of `com.example:lock`, the key a deploy of its documents and retention's
    /// reconciliation both take.
    const LOCK_KEY: &str = "maven/com/example/lock/maven-metadata.xml";

    /// A retired SNAPSHOT whose files are gone keeps only its document, until reconciliation
    /// removes it. Reconciliation waits for the artifact's metadata lock while another writer
    /// holds it (#1281).
    #[tokio::test]
    async fn test_maven_version_document_removal_waits_for_the_artifact_lock() {
        let ctx = create_test_context();
        let storage = ctx.state.storage.clone();
        let locks = ctx.state.publish_locks.clone();
        let doc = "maven/com/example/lock/1.0-SNAPSHOT/maven-metadata.xml";
        storage
            .put(doc, snapshot_document("lock", "20261117.120000").as_bytes())
            .await
            .unwrap();
        let regen = std::collections::BTreeMap::from([(
            "com/example/lock".to_string(),
            std::collections::BTreeSet::from(["1.0-SNAPSHOT".to_string()]),
        )]);

        let held_lock = crate::acquire_publish_lock(&locks, LOCK_KEY);
        let held = held_lock.lock().await;
        let task = tokio::spawn({
            let (storage, locks) = (storage.clone(), locks.clone());
            async move { reconcile_maven_metadata(&storage, &locks, &regen).await }
        });
        // Yield until the task ends or the bound is spent: a blocked task never ends, an unlocked
        // one ends well inside the bound (the HTTP path of a deploy takes ~18k turns).
        let mut turns = 0u32;
        while !task.is_finished() && turns < 50_000 {
            tokio::task::yield_now().await;
            turns += 1;
        }
        // Blocked on the lock, the task has not finished; without the lock it finishes in its
        // first polls, before any of the yields above end.
        assert!(
            !task.is_finished(),
            "reconciliation ran while the artifact lock was held"
        );
        assert!(
            storage.stat(doc).await.is_some(),
            "reconciliation removed the document while the artifact lock was held"
        );
        drop(held);
        task.await.unwrap();
        assert!(
            storage.stat(doc).await.is_none(),
            "retired version's document left behind"
        );
    }

    /// A deploy of a version-level document takes the artifact's metadata lock, the lock the
    /// reconciliation of that document takes: it waits while the lock is held (#1281).
    #[tokio::test]
    async fn test_maven_version_document_deploy_waits_for_the_artifact_lock() {
        let ctx = create_test_context();
        let storage = ctx.state.storage.clone();
        let held_lock = crate::acquire_publish_lock(&ctx.state.publish_locks, LOCK_KEY);
        let held = held_lock.lock().await;
        let app = ctx.app.clone();
        let body = snapshot_document("lock", "20261117.120000");
        let deploy = tokio::spawn(async move {
            crate::test_helpers::send(
                &app,
                Method::PUT,
                "/maven2/com/example/lock/1.0-SNAPSHOT/maven-metadata.xml",
                body,
            )
            .await
            .status()
        });
        // Yield until the request ends or the bound is spent: a blocked request never ends, an
        // unlocked one ends well inside the bound (a deploy's HTTP path takes ~18k turns).
        let mut turns = 0u32;
        while !deploy.is_finished() && turns < 50_000 {
            tokio::task::yield_now().await;
            turns += 1;
        }
        assert!(
            !deploy.is_finished(),
            "the document was deployed while the artifact lock was held"
        );
        assert!(
            storage
                .stat("maven/com/example/lock/1.0-SNAPSHOT/maven-metadata.xml")
                .await
                .is_none(),
            "the document was written while the artifact lock was held"
        );
        drop(held);
        assert_eq!(deploy.await.unwrap(), StatusCode::CREATED);
    }

    /// A file of another coordinate nested under a retired SNAPSHOT's directory does not keep the
    /// version's document: the version still goes once its own files are gone (#1281).
    #[tokio::test]
    async fn test_maven_nested_foreign_file_does_not_keep_a_retired_snapshot_document() {
        let ctx = create_test_context();
        let storage = &ctx.state.storage;
        let base = "com/example/nest/1.0-SNAPSHOT";
        maven_put(&ctx, &format!("{base}/nest-1.0-SNAPSHOT.jar"), "jar").await;
        maven_put(
            &ctx,
            &format!("{base}/maven-metadata.xml"),
            &snapshot_document("nest", "20261117.120000"),
        )
        .await;
        // Stored directly: a deploy of `nest:1.0-SNAPSHOT:9.0` would also write that artifact's
        // document at the very key the version's document has.
        storage
            .put(&format!("maven/{base}/9.0/nest-9.0.jar"), b"foreign")
            .await
            .unwrap();
        maven_put(&ctx, "com/example/nest/1.1/nest-1.1.jar", "release").await;

        let result = run_retention(
            storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-SNAPSHOT")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        assert!(
            storage
                .stat(&format!("maven/{base}/maven-metadata.xml"))
                .await
                .is_none(),
            "retired SNAPSHOT's document kept by a nested file of another coordinate"
        );
        assert!(
            storage
                .stat(&format!("maven/{base}/9.0/nest-9.0.jar"))
                .await
                .is_some(),
            "the nested foreign file was deleted"
        );
    }

    /// Only a SNAPSHOT has a version-level document: a retired release version's directory keeps
    /// its `maven-metadata.xml` whatever it declares (#1281).
    #[tokio::test]
    async fn test_maven_retired_release_keeps_its_directory_document() {
        let ctx = create_test_context();
        let storage = &ctx.state.storage;
        maven_put(&ctx, "com/example/rel/1.0/rel-1.0.jar", "jar").await;
        storage
            .put(
                "maven/com/example/rel/1.0/maven-metadata.xml",
                b"<?xml version=\"1.0\"?><metadata><groupId>com.example</groupId><artifactId>rel</artifactId><version>1.0</version></metadata>",
            )
            .await
            .unwrap();
        maven_put(&ctx, "com/example/rel/2.0/rel-2.0.jar", "jar").await;

        let result = run_retention(
            storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("1.0")],
            false,
        )
        .await;
        assert_eq!(result.planned, 1);
        assert!(storage
            .stat("maven/com/example/rel/1.0/rel-1.0.jar")
            .await
            .is_none());
        assert!(
            storage
                .stat("maven/com/example/rel/1.0/maven-metadata.xml")
                .await
                .is_some(),
            "a release version's directory document was removed"
        );
    }

    /// A dry run deletes nothing and rewrites nothing.
    #[tokio::test]
    async fn test_maven_retention_dry_run_leaves_metadata_untouched() {
        let ctx = create_test_context();
        for v in ["1.0.0", "1.1.0-rc.1"] {
            maven_put(&ctx, &format!("com/example/dry/{v}/dry-{v}.jar"), v).await;
        }
        let before = ctx
            .state
            .storage
            .list("maven/com/example/dry/")
            .await
            .unwrap();
        let mut snapshot = Vec::new();
        for key in &before {
            snapshot.push(ctx.state.storage.get(key).await.unwrap());
        }
        let result = run_retention(
            &ctx.state.storage,
            &ctx.state.publish_locks,
            None,
            &[maven_rule("*-rc*")],
            true,
        )
        .await;
        assert_eq!(result.planned, 1);
        let after = ctx
            .state
            .storage
            .list("maven/com/example/dry/")
            .await
            .unwrap();
        assert_eq!(before, after);
        for (key, data) in before.iter().zip(&snapshot) {
            assert_eq!(&ctx.state.storage.get(key).await.unwrap(), data, "{key}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod maven_proxy_document_and_retention {
    //! A proxy fetch caching a SNAPSHOT's version-level `maven-metadata.xml` while retention
    //! removes that document (#1291): the document and its checksums are written and removed
    //! under one lock, so no checksum is left without its document.
    use crate::storage::{FileMeta, LocalStorage, ObjectStorage, Result, StorageBackend};
    use crate::Storage;
    use axum::body::Bytes;
    use axum::http::{Method, StatusCode};
    use sha2::Digest as _;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

    const DIR: &str = "maven/com/example/lib/1.0-SNAPSHOT/";
    const DOCUMENT: &str = "maven/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml";
    const ARTIFACT_LOCK: &str = "maven/com/example/lib/maven-metadata.xml";

    /// Holds the first `put` of `key` until released: the proxy write has stored the document
    /// and not yet its checksums.
    struct HeldPut {
        inner: Arc<dyn StorageBackend>,
        key: String,
        armed: AtomicBool,
        reached: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl StorageBackend for HeldPut {
        async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
            if key == self.key && self.armed.swap(false, Ordering::SeqCst) {
                self.reached.notify_one();
                self.release.notified().await;
            }
            self.inner.put(key, data, sha256).await
        }
        async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)> {
            self.inner.get(key).await
        }
        async fn pin(&self, key: &str) -> Option<String> {
            self.inner.pin(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            self.inner.stat(key).await
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            0
        }
        fn backend_name(&self) -> &'static str {
            "held-put"
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> Result<()> {
            self.inner.put_from_path(key, src, sha256).await
        }
        async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(key).await
        }
    }

    /// A GET through the proxy stores the document of retired `com.example:lib:1.0-SNAPSHOT` (no
    /// file of the version is left) and is held before its checksums; retention's reconciliation
    /// of the artifact starts; the GET goes on once the reconciliation has finished or waits
    /// behind it. Every checksum left in the version directory has its document beside it and
    /// matches it.
    async fn no_checksum_outlives_its_document(inner: Arc<dyn StorageBackend>) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let document = "<?xml version=\"1.0\"?><metadata modelVersion=\"1.1.0\"><groupId>com.example</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261117.120000</timestamp><buildNumber>1</buildNumber></snapshot><lastUpdated>20261117120000</lastUpdated></versioning></metadata>";
        Mock::given(method("GET"))
            .and(path("/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(document, "application/xml"))
            .mount(&upstream)
            .await;

        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let storage = Storage::from_backend(Arc::new(HeldPut {
            inner,
            key: format!("{DOCUMENT}.md5"),
            armed: AtomicBool::new(true),
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let upstream_url = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            storage,
            move |config| {
                config.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(upstream_url)];
            },
        );

        let app = ctx.app.clone();
        let fetch = tokio::spawn(async move {
            crate::test_helpers::send(
                &app,
                Method::GET,
                "/maven2/com/example/lib/1.0-SNAPSHOT/maven-metadata.xml",
                "",
            )
            .await
            .status()
        });
        // Deadline, not a schedule: a proxy write that never reaches its checksums (a lock taken
        // twice) fails here instead of hanging the suite.
        let deadline = std::time::Duration::from_secs(60);
        tokio::time::timeout(deadline, reached.notified())
            .await
            .expect("the proxy write never reached its checksums");
        let storage = ctx.state.storage.clone();
        assert!(
            storage.stat(DOCUMENT).await.is_some(),
            "the proxy write is held after its document"
        );

        let locks = ctx.state.publish_locks.clone();
        let artifact_lock = crate::acquire_publish_lock(&locks, ARTIFACT_LOCK);
        let regen = BTreeMap::from([(
            "com/example/lib".to_string(),
            BTreeSet::from(["1.0-SNAPSHOT".to_string()]),
        )]);
        let retention = tokio::spawn({
            let (storage, locks) = (storage.clone(), locks.clone());
            async move { super::reconcile_maven_metadata(&storage, &locks, &regen).await }
        });
        // The reconciliation either finishes (it does not wait for the proxy write) or queues on
        // the artifact lock the proxy write holds: then four handles of that lock are out (the
        // lock map, this test, the proxy write, the reconciliation).
        let mut turns = 0u64;
        while !retention.is_finished() && Arc::strong_count(&artifact_lock) < 4 {
            tokio::task::yield_now().await;
            turns += 1;
            assert!(
                turns < 10_000_000,
                "the reconciliation neither finished nor queued on the artifact lock"
            );
        }
        release.notify_one();
        let status = tokio::time::timeout(deadline, fetch)
            .await
            .expect("the proxy GET never finished")
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        tokio::time::timeout(deadline, retention)
            .await
            .expect("the reconciliation never finished")
            .unwrap();

        let left = storage.list(DIR).await.unwrap();
        for key in &left {
            let Some((document, suffix)) = key
                .rsplit_once('.')
                .filter(|(_, suffix)| matches!(*suffix, "md5" | "sha1" | "sha256" | "sha512"))
            else {
                continue;
            };
            let data = match storage.get(document).await {
                Ok(data) => data,
                Err(e) => panic!("checksum {key} left without its document ({e}); left: {left:?}"),
            };
            let expected = match suffix {
                "md5" => hex::encode(md5::Md5::digest(&data)),
                "sha1" => hex::encode(sha1::Sha1::digest(&data)),
                "sha256" => hex::encode(sha2::Sha256::digest(&data)),
                _ => hex::encode(sha2::Sha512::digest(&data)),
            };
            let sum = storage.get(key).await.unwrap();
            assert_eq!(
                String::from_utf8_lossy(&sum),
                expected,
                "{key} does not match its document"
            );
        }
    }

    #[tokio::test]
    async fn test_maven_proxy_document_write_and_retention_local() {
        let dir = tempfile::tempdir().unwrap();
        no_checksum_outlives_its_document(Arc::new(LocalStorage::new(
            dir.path().to_str().unwrap(),
        )))
        .await;
    }

    #[tokio::test]
    async fn test_maven_proxy_document_write_and_retention_object_store() {
        no_checksum_outlives_its_document(Arc::new(ObjectStorage::in_memory())).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upload_racing_retention {
    //! An upload of a package path that retention is deleting (#1298). The upload holds the
    //! repository's lock while it stores the package, then its metadata sidecar; retention, which
    //! planned from what was stored before, must not delete the package in between. Either the
    //! upload's package survives (and the index lists it), or the deletion ran first and the
    //! upload stored the package again after it.
    use super::*;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage_and_config, local_outage_storage,
        outage_storage, send, StorageOutage, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use sha2::Digest as _;
    use std::time::Duration;

    fn rule(registry: &str, keep: Option<u32>, days: Option<u32>) -> RetentionRule {
        RetentionRule {
            registry: registry.into(),
            name_glob: None,
            keep_last: keep,
            older_than_days: days,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
        }
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

    /// A context over the in-memory object store, and its switch.
    fn in_memory() -> (TestContext, StorageOutage, Option<tempfile::TempDir>) {
        let (storage, outage) = outage_storage();
        (
            create_test_context_with_storage_and_config(storage, |_| {}),
            outage,
            None,
        )
    }

    /// A context over a local directory, and its switch.
    fn local() -> (TestContext, StorageOutage, Option<tempfile::TempDir>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let (storage, outage) = local_outage_storage(&path);
        let ctx = create_test_context_with_storage_and_config(storage, |c| {
            c.storage.path = path.clone();
        });
        (ctx, outage, Some(dir))
    }

    async fn text(ctx: &TestContext, uri: &str) -> String {
        let response = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        String::from_utf8(body_bytes(response).await.to_vec()).unwrap()
    }

    /// The rpm repository's primary.xml, read the way a client reads it: repomd.xml first.
    async fn rpm_primary(ctx: &TestContext, repo: &str) -> String {
        let repomd = text(ctx, &format!("/rpm/{repo}/repodata/repomd.xml")).await;
        let start = repomd.find("primary").unwrap();
        let href_at = repomd[start..].find("href=\"").unwrap() + start + 6;
        let end = repomd[href_at..].find('"').unwrap() + href_at;
        let gz = body_bytes(
            send(
                &ctx.app,
                Method::GET,
                &format!("/rpm/{repo}/{}", &repomd[href_at..end]),
                "",
            )
            .await,
        )
        .await;
        let mut primary = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut primary)
            .unwrap();
        primary
    }

    /// Re-upload `uri` while retention runs `rules`: the upload's write of its new `sidecar` is
    /// held at the store — the package is already stored and the repository's lock held — until
    /// retention has read what it plans from of the sidecar stored before (`planning_reads`
    /// reads, `get` and `stat` counted); then the write goes on. Without serialization the
    /// upload may also fail its index rebuild, the sidecars deleted under it — the same defect.
    /// Both must finish within the deadline.
    async fn reupload_racing_retention(
        ctx: &TestContext,
        outage: &StorageOutage,
        uri: &str,
        body: Vec<u8>,
        sidecar: &str,
        planning_reads: usize,
        rules: Vec<RetentionRule>,
    ) -> RetentionResult {
        // Every rpm and deb sidecar names the package's architecture.
        let held = outage.hold_write_of(sidecar, b"\"arch\"");
        let planned_from = outage.watch_reads_of(sidecar, planning_reads);
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        tokio::time::timeout(Duration::from_secs(30), async {
            // The package's key is the upload's path: `/rpm/{repo}/{path}` → `rpm/{repo}/{path}`.
            let package = uri.trim_start_matches('/').to_string();
            let app = ctx.app.clone();
            let uri = uri.to_string();
            let put = async move { send(&app, Method::PUT, &uri, body).await.status() };
            let upload = tokio::spawn(put);
            held.reached().await;
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Retention read the old sidecar: its plan takes the package, whatever runs next.
            planned_from.answered().await;
            // Unserialized, retention deletes the package within milliseconds; serialized, it
            // waits for the repository's lock, and this wait is spent.
            let started = std::time::Instant::now();
            while ctx.state.storage.stat(&package).await.is_some()
                && started.elapsed() < Duration::from_millis(200)
            {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            held.release();
            assert_eq!(upload.await.unwrap(), StatusCode::CREATED, "upload");
            retention.await.unwrap()
        })
        .await
        .expect("the upload and retention both finished")
    }

    /// A version retention planned from its old state and kept is not reported as deleted: not
    /// in the count the audit trail records, not in the keys or bytes.
    fn assert_nothing_reported_deleted(result: &RetentionResult) {
        assert_eq!(
            (result.planned, result.deleted_keys, result.bytes_freed),
            (0, 0, 0),
            "a kept version reported as deleted: {:?}",
            result.plans
        );
    }

    async fn rpm_reupload_keeps_its_package(ctx: TestContext, outage: StorageOutage) {
        let path = "pkg-1.0-1.x86_64.rpm";
        let uri = format!("/rpm/prod/{path}");
        let package = format!("rpm/prod/{path}");
        let sidecar = format!("rpm/prod/.nora-meta/{path}.json");
        let body = build_rpm("pkg", "1.0");
        let first = send(&ctx.app, Method::PUT, &uri, body.clone()).await;
        assert_eq!(first.status(), StatusCode::CREATED);
        // The stored version is 40 days old (the collector reads its sidecar's file_time), so a
        // 30-day rule plans its deletion; the re-upload is new and outside the rule.
        let mut sc: serde_json::Value =
            serde_json::from_slice(&ctx.state.storage.get(&sidecar).await.unwrap()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sc["file_time"] = serde_json::json!(now - 40 * 86400);
        ctx.state
            .storage
            .put(&sidecar, &serde_json::to_vec(&sc).unwrap())
            .await
            .unwrap();

        let result = reupload_racing_retention(
            &ctx,
            &outage,
            &uri,
            body.clone(),
            &sidecar,
            // The sidecar's content: file_time is the version's age.
            1,
            vec![rule("rpm", None, Some(30))],
        )
        .await;
        assert_nothing_reported_deleted(&result);

        let stored = ctx.state.storage.get(&package).await.ok();
        assert!(
            stored.as_deref() == Some(&body[..]),
            "the upload answered 201 and its package is gone (stored: {:?} bytes)",
            stored.map(|b| b.len())
        );
        assert!(
            ctx.state.storage.stat(&sidecar).await.is_some(),
            "the package's sidecar is gone"
        );
        let primary = rpm_primary(&ctx, "prod").await;
        assert!(
            primary.contains("packages=\"1\"") && primary.contains(path),
            "the repodata does not list the uploaded package: {primary}"
        );
    }

    #[tokio::test]
    async fn rpm_reupload_during_retention_keeps_its_package_local() {
        let (ctx, outage, _dir) = local();
        rpm_reupload_keeps_its_package(ctx, outage).await;
    }

    #[tokio::test]
    async fn rpm_reupload_during_retention_keeps_its_package_object_store() {
        let (ctx, outage, _dir) = in_memory();
        rpm_reupload_keeps_its_package(ctx, outage).await;
    }

    async fn deb_reupload_keeps_its_package(ctx: TestContext, outage: StorageOutage) {
        let uri = "/deb/prod/pool/pkg_1.0.deb";
        let package = "deb/prod/pool/pkg_1.0.deb";
        let sidecar = "deb/prod/.nora-meta/pool/pkg_1.0.deb.json";
        let body = crate::registry::deb::test_fixtures::build_deb("pkg", "1.0");
        // A deb version is as old as its sidecar's write time, in whole seconds: 1.0 is written
        // a second before 2.0, so keep_last=1 plans 1.0's deletion, and the re-upload a second
        // after 2.0 makes 1.0 the newest.
        let first = send(&ctx.app, Method::PUT, uri, body.clone()).await;
        assert_eq!(first.status(), StatusCode::CREATED);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let newer = send(
            &ctx.app,
            Method::PUT,
            "/deb/prod/pool/pkg_2.0.deb",
            crate::registry::deb::test_fixtures::build_deb("pkg", "2.0"),
        )
        .await;
        assert_eq!(newer.status(), StatusCode::CREATED);
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let result = reupload_racing_retention(
            &ctx,
            &outage,
            uri,
            body.clone(),
            sidecar,
            // The sidecar's content, then its write time: the version's age.
            2,
            vec![rule("deb", Some(1), None)],
        )
        .await;
        assert_nothing_reported_deleted(&result);

        let stored = ctx.state.storage.get(package).await.ok();
        assert!(
            stored.as_deref() == Some(&body[..]),
            "the upload answered 201 and its package is gone (stored: {:?} bytes)",
            stored.map(|b| b.len())
        );
        assert!(
            ctx.state.storage.stat(sidecar).await.is_some(),
            "the package's sidecar is gone"
        );
        let packages = text(&ctx, "/deb/prod/Packages").await;
        assert!(
            packages.contains("Version: 1.0"),
            "the Packages index does not list the uploaded package: {packages}"
        );
    }

    /// Maven: a deploy of a version's file holds its artifact's metadata lock while it stores the
    /// file, then the file's checksums. A SNAPSHOT deployed under its plain name rewrites the same
    /// path. Retention deleting the old version is paused after the jar, before its checksums
    /// (the test holds the lock of the `.md5` key, the one retention takes before deleting it),
    /// while the redeploy runs: the redeploy must not end up as a jar without its checksums.
    async fn maven_redeploy_keeps_its_file(ctx: TestContext) {
        let base = "com/example/race";
        let jar = format!("{base}/1.0-SNAPSHOT/race-1.0-SNAPSHOT.jar");
        let uri = format!("/maven2/{jar}");
        let package = format!("maven/{jar}");
        let body = b"snapshot-jar".to_vec();
        let first = send(&ctx.app, Method::PUT, &uri, body.clone()).await;
        assert_eq!(first.status(), StatusCode::CREATED);
        let newer = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{base}/1.1-SNAPSHOT/race-1.1-SNAPSHOT.jar"),
            b"newer".to_vec(),
        )
        .await;
        assert_eq!(newer.status(), StatusCode::CREATED);
        let mut snapshots = rule("maven", None, None);
        snapshots.include_tags = vec!["1.0-SNAPSHOT".to_string()];
        snapshots.keep_last = Some(0);

        let md5_lock =
            crate::acquire_publish_lock(&ctx.state.publish_locks, &format!("{package}.md5"));
        let md5_guard = md5_lock.lock().await;
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![snapshots];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Retention deletes the jar first, then waits for the `.md5` lock.
            while ctx.state.storage.stat(&package).await.is_some() && !retention.is_finished() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let app = ctx.app.clone();
            let (uri, redeployed) = (uri.clone(), body.clone());
            let put = async move { send(&app, Method::PUT, &uri, redeployed).await.status() };
            let deploy = tokio::spawn(put);
            // Unserialized, the deploy stores the jar and its checksums now; serialized with the
            // deletion, it waits for it. (A deploy's HTTP path takes milliseconds.)
            let started = std::time::Instant::now();
            while !deploy.is_finished() && started.elapsed() < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(md5_guard);
            assert_eq!(deploy.await.unwrap(), StatusCode::CREATED, "deploy");
            let result = retention.await.unwrap();
            // Planned from the version as stored, and carried out before the deploy.
            assert_eq!(result.planned, 1, "{:?}", result.plans);
        })
        .await
        .expect("the deploy and retention both finished");

        let stored = ctx.state.storage.get(&package).await.ok();
        assert!(
            stored.as_deref() == Some(&body[..]),
            "the deploy answered 201 and its file is gone (stored: {:?} bytes)",
            stored.map(|b| b.len())
        );
        for suffix in ["md5", "sha1", "sha256", "sha512"] {
            assert!(
                ctx.state
                    .storage
                    .stat(&format!("{package}.{suffix}"))
                    .await
                    .is_some(),
                "the deployed file's .{suffix} is gone"
            );
        }
    }

    /// Maven: retention planned 1.0-SNAPSHOT's deletion from its old files, then waits for the
    /// artifact's lock, which a deploy holds while it rewrites the version's jar and checksums
    /// (the test holds the lock and writes them as the deploy does). Under the lock the version
    /// no longer reads as planned, so it is kept, and reported nowhere as deleted.
    async fn maven_version_rewritten_after_planning_is_kept(
        ctx: TestContext,
        outage: StorageOutage,
    ) {
        let base = "com/example/race";
        let jar = format!("maven/{base}/1.0-SNAPSHOT/race-1.0-SNAPSHOT.jar");
        let first = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{base}/1.0-SNAPSHOT/race-1.0-SNAPSHOT.jar"),
            b"old".to_vec(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        // Ages in whole seconds: 1.0-SNAPSHOT older than 1.1-SNAPSHOT, then rewritten newest.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let newer = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{base}/1.1-SNAPSHOT/race-1.1-SNAPSHOT.jar"),
            b"newer".to_vec(),
        )
        .await;
        assert_eq!(newer.status(), StatusCode::CREATED);
        let mut snapshots = rule("maven", Some(1), None);
        snapshots.include_tags = vec!["*-SNAPSHOT".to_string()];

        let artifact_lock = crate::acquire_publish_lock(
            &ctx.state.publish_locks,
            &crate::registry::maven_artifact_metadata_lock_key("com/example", "race"),
        );
        let deploy_guard = artifact_lock.lock().await;
        // The jar and its four checksums: the version's age is the newest of them.
        let planned_from = outage.watch_reads_of(".jar.sha512", 2);
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![snapshots];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Both versions' files were read (stat of each `.sha512`): the plan is made.
            planned_from.answered().await;
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let body = b"redeployed".to_vec();
            ctx.state.storage.put(&jar, &body).await.unwrap();
            for suffix in ["md5", "sha1", "sha256", "sha512"] {
                let sum = match suffix {
                    "md5" => hex::encode(md5::Md5::digest(&body)),
                    "sha1" => hex::encode(sha1::Sha1::digest(&body)),
                    "sha256" => hex::encode(sha2::Sha256::digest(&body)),
                    _ => hex::encode(sha2::Sha512::digest(&body)),
                };
                ctx.state
                    .storage
                    .put(&format!("{jar}.{suffix}"), sum.as_bytes())
                    .await
                    .unwrap();
            }
            drop(deploy_guard);
            retention.await.unwrap()
        })
        .await
        .expect("retention finished");

        assert_eq!(
            ctx.state.storage.get(&jar).await.ok().as_deref(),
            Some(&b"redeployed"[..]),
            "the rewritten version was deleted by a plan made before it"
        );
        for suffix in ["md5", "sha1", "sha256", "sha512"] {
            assert!(
                ctx.state
                    .storage
                    .stat(&format!("{jar}.{suffix}"))
                    .await
                    .is_some(),
                ".{suffix} gone"
            );
        }
        assert_eq!(
            result.planned, 0,
            "a kept version reported as deleted: {:?}",
            result.plans
        );
    }

    #[tokio::test]
    async fn maven_version_rewritten_after_planning_is_kept_local() {
        let (ctx, outage, _dir) = local();
        maven_version_rewritten_after_planning_is_kept(ctx, outage).await;
    }

    #[tokio::test]
    async fn maven_version_rewritten_after_planning_is_kept_object_store() {
        let (ctx, outage, _dir) = in_memory();
        maven_version_rewritten_after_planning_is_kept(ctx, outage).await;
    }

    /// Maven: retention planned 1.0-SNAPSHOT's deletion from the files it had, then waits for the
    /// artifact's lock, which a deploy holds while it adds a file to the version (a `-sources.jar`
    /// beside the jar; the test holds the lock and writes as the deploy does). The files planned
    /// are untouched, but the version is no longer the one planned: it is kept whole, not left as
    /// the added file alone.
    async fn maven_version_given_a_file_after_planning_is_kept(
        ctx: TestContext,
        outage: StorageOutage,
    ) {
        let base = "com/example/race";
        let dir = format!("maven/{base}/1.0-SNAPSHOT");
        let jar = format!("{dir}/race-1.0-SNAPSHOT.jar");
        let first = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{base}/1.0-SNAPSHOT/race-1.0-SNAPSHOT.jar"),
            b"old".to_vec(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        // Ages in whole seconds: 1.0-SNAPSHOT older than 1.1-SNAPSHOT.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let newer = send(
            &ctx.app,
            Method::PUT,
            &format!("/maven2/{base}/1.1-SNAPSHOT/race-1.1-SNAPSHOT.jar"),
            b"newer".to_vec(),
        )
        .await;
        assert_eq!(newer.status(), StatusCode::CREATED);
        let mut snapshots = rule("maven", Some(1), None);
        snapshots.include_tags = vec!["*-SNAPSHOT".to_string()];

        let artifact_lock = crate::acquire_publish_lock(
            &ctx.state.publish_locks,
            &crate::registry::maven_artifact_metadata_lock_key("com/example", "race"),
        );
        let deploy_guard = artifact_lock.lock().await;
        // The jar and its four checksums: the version's age is the newest of them.
        let planned_from = outage.watch_reads_of(".jar.sha512", 2);
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![snapshots];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Both versions' files were read (stat of each `.sha512`): the plan is made.
            planned_from.answered().await;
            // The added file makes 1.0-SNAPSHOT the newest version, a second after 1.1-SNAPSHOT.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let sources = format!("{dir}/race-1.0-SNAPSHOT-sources.jar");
            let body = b"sources".to_vec();
            ctx.state.storage.put(&sources, &body).await.unwrap();
            let sum = hex::encode(sha2::Sha256::digest(&body));
            ctx.state
                .storage
                .put(&format!("{sources}.sha256"), sum.as_bytes())
                .await
                .unwrap();
            drop(deploy_guard);
            retention.await.unwrap()
        })
        .await
        .expect("retention finished");

        assert_eq!(
            ctx.state.storage.get(&jar).await.ok().as_deref(),
            Some(&b"old"[..]),
            "a version that was given a file was deleted around it by a plan made before"
        );
        for suffix in ["md5", "sha1", "sha256", "sha512"] {
            assert!(
                ctx.state
                    .storage
                    .stat(&format!("{jar}.{suffix}"))
                    .await
                    .is_some(),
                ".{suffix} gone"
            );
        }
        assert_eq!(
            result.planned, 0,
            "a kept version reported as deleted: {:?}",
            result.plans
        );
    }

    #[tokio::test]
    async fn maven_version_given_a_file_after_planning_is_kept_local() {
        let (ctx, outage, _dir) = local();
        maven_version_given_a_file_after_planning_is_kept(ctx, outage).await;
    }

    #[tokio::test]
    async fn maven_version_given_a_file_after_planning_is_kept_object_store() {
        let (ctx, outage, _dir) = in_memory();
        maven_version_given_a_file_after_planning_is_kept(ctx, outage).await;
    }

    /// Maven: a client uploads a file's checksum while retention deletes the file's version.
    /// Retention is paused after the jar, before its checksums (the test holds the lock of the
    /// `.md5` key, the one retention takes before deleting it), while the `.sha256` is uploaded:
    /// the upload must not answer 201 for a checksum the deletion then takes.
    async fn maven_checksum_upload_keeps_its_checksum(ctx: TestContext) {
        let base = "com/example/race";
        let jar = format!("{base}/1.0-SNAPSHOT/race-1.0-SNAPSHOT.jar");
        let uri = format!("/maven2/{jar}");
        let package = format!("maven/{jar}");
        let body = b"snapshot-jar".to_vec();
        let first = send(&ctx.app, Method::PUT, &uri, body.clone()).await;
        assert_eq!(first.status(), StatusCode::CREATED);
        let mut snapshots = rule("maven", None, None);
        snapshots.include_tags = vec!["1.0-SNAPSHOT".to_string()];
        snapshots.keep_last = Some(0);

        let md5_lock =
            crate::acquire_publish_lock(&ctx.state.publish_locks, &format!("{package}.md5"));
        let md5_guard = md5_lock.lock().await;
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![snapshots];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Retention deletes the jar first, then waits for the `.md5` lock.
            while ctx.state.storage.stat(&package).await.is_some() && !retention.is_finished() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let app = ctx.app.clone();
            let sum_uri = format!("{uri}.sha256");
            let sum = hex::encode(sha2::Sha256::digest(&body));
            let put = async move { send(&app, Method::PUT, &sum_uri, sum).await.status() };
            let upload = tokio::spawn(put);
            // Unserialized, the upload stores the checksum now; serialized with the deletion,
            // it waits for it. (An upload's HTTP path takes milliseconds.)
            let started = std::time::Instant::now();
            while !upload.is_finished() && started.elapsed() < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(md5_guard);
            assert_eq!(
                upload.await.unwrap(),
                StatusCode::CREATED,
                "checksum upload"
            );
            let result = retention.await.unwrap();
            // Planned from the version as stored, and carried out before the upload.
            assert_eq!(result.planned, 1, "{:?}", result.plans);
        })
        .await
        .expect("the upload and retention both finished");

        assert!(
            ctx.state
                .storage
                .stat(&format!("{package}.sha256"))
                .await
                .is_some(),
            "the upload answered 201 and its checksum is gone"
        );
    }

    #[tokio::test]
    async fn maven_checksum_upload_during_retention_keeps_its_checksum_local() {
        let (ctx, _outage, _dir) = local();
        maven_checksum_upload_keeps_its_checksum(ctx).await;
    }

    #[tokio::test]
    async fn maven_checksum_upload_during_retention_keeps_its_checksum_object_store() {
        let (ctx, _outage, _dir) = in_memory();
        maven_checksum_upload_keeps_its_checksum(ctx).await;
    }

    #[tokio::test]
    async fn maven_redeploy_during_retention_keeps_its_file_local() {
        let (ctx, _outage, _dir) = local();
        maven_redeploy_keeps_its_file(ctx).await;
    }

    #[tokio::test]
    async fn maven_redeploy_during_retention_keeps_its_file_object_store() {
        let (ctx, _outage, _dir) = in_memory();
        maven_redeploy_keeps_its_file(ctx).await;
    }

    #[tokio::test]
    async fn deb_reupload_during_retention_keeps_its_package_local() {
        let (ctx, outage, _dir) = local();
        deb_reupload_keeps_its_package(ctx, outage).await;
    }

    #[tokio::test]
    async fn deb_reupload_during_retention_keeps_its_package_object_store() {
        let (ctx, outage, _dir) = in_memory();
        deb_reupload_keeps_its_package(ctx, outage).await;
    }

    /// Retention still deletes what its rule selects, on both stores, and the index stops listing
    /// it: the repository's lock it now takes does not keep it from its work.
    async fn rpm_and_deb_retention_still_delete(ctx: TestContext) {
        for v in ["1.0", "2.0"] {
            let rpm = send(
                &ctx.app,
                Method::PUT,
                &format!("/rpm/prod/pkg-{v}-1.x86_64.rpm"),
                build_rpm("pkg", v),
            )
            .await;
            assert_eq!(rpm.status(), StatusCode::CREATED);
            let deb = send(
                &ctx.app,
                Method::PUT,
                &format!("/deb/prod/pool/pkg_{v}.deb"),
                crate::registry::deb::test_fixtures::build_deb("pkg", v),
            )
            .await;
            assert_eq!(deb.status(), StatusCode::CREATED);
        }
        // CANCEL-SAFETY: a watchdog: a retention pass that waits forever on a lock fails the
        // test instead of stalling the run.
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            run_retention(
                &ctx.state.storage,
                &ctx.state.publish_locks,
                ctx.state.signer.as_deref(),
                &[rule("rpm", Some(1), None), rule("deb", Some(1), None)],
                false,
            ),
        )
        .await
        .expect("retention finished");
        assert_eq!(result.planned, 2, "{:?}", result.plans);
        assert_eq!(result.deleted_keys, 4, "package and sidecar of each");
        for gone in [
            "rpm/prod/pkg-1.0-1.x86_64.rpm",
            "rpm/prod/.nora-meta/pkg-1.0-1.x86_64.rpm.json",
            "deb/prod/pool/pkg_1.0.deb",
            "deb/prod/.nora-meta/pool/pkg_1.0.deb.json",
        ] {
            assert!(ctx.state.storage.stat(gone).await.is_none(), "{gone} kept");
        }
        let primary = rpm_primary(&ctx, "prod").await;
        assert!(
            primary.contains("packages=\"1\"") && primary.contains("pkg-2.0-1.x86_64.rpm"),
            "{primary}"
        );
        let packages = text(&ctx, "/deb/prod/Packages").await;
        assert!(
            packages.contains("Version: 2.0") && !packages.contains("Version: 1.0"),
            "{packages}"
        );
    }

    #[tokio::test]
    async fn rpm_and_deb_retention_still_delete_local() {
        let (ctx, _outage, _dir) = local();
        rpm_and_deb_retention_still_delete(ctx).await;
    }

    #[tokio::test]
    async fn rpm_and_deb_retention_still_delete_object_store() {
        let (ctx, _outage, _dir) = in_memory();
        rpm_and_deb_retention_still_delete(ctx).await;
    }

    /// The multipart form `twine` posts to upload `filename` of `name` 1.0.0 with `content`.
    fn pypi_upload_form(name: &str, filename: &str, content: &str) -> (String, Vec<u8>) {
        let b = "NORA-RETENTION-RACE-BOUNDARY";
        let form = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\":action\"\r\n\r\nfile_upload\r\n\
--{b}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{name}\r\n\
--{b}\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n1.0.0\r\n\
--{b}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
Content-Type: application/octet-stream\r\n\r\n{content}\r\n--{b}--\r\n"
        );
        (
            format!("multipart/form-data; boundary={b}"),
            form.into_bytes(),
        )
    }

    async fn pypi_upload(ctx: &TestContext, filename: &str, content: &str) -> StatusCode {
        let (ctype, body) = pypi_upload_form("racepkg", filename, content);
        crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", ctype.as_str())],
            body,
        )
        .await
        .status()
    }

    /// PyPI: an upload stores the file, its `.sha256`, its hash marker and, last, the record that
    /// the file is the project's own, all under the lock of the file's key; a hosted project lists
    /// a file only once it is recorded. Retention deleting the file is paused before the record
    /// (the test holds the record key's lock, the one retention takes before deleting it) while an
    /// upload of the same name runs: the upload must not end up unrecorded and unlisted.
    async fn pypi_reupload_keeps_its_record(ctx: TestContext) {
        let filename = "racepkg-1.0.0.tar.gz";
        let file_key = format!("pypi/racepkg/{filename}");
        let record_key = crate::registry::pypi_own_file_key("racepkg", filename);
        assert_eq!(pypi_upload(&ctx, filename, "first").await, StatusCode::OK);
        let rules = vec![rule("pypi", Some(0), None)];

        let record_lock = crate::acquire_publish_lock(&ctx.state.publish_locks, &record_key);
        let record_guard = record_lock.lock().await;
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // Retention deletes the file first, then waits for the record's lock.
            while ctx.state.storage.stat(&file_key).await.is_some() && !retention.is_finished() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let upload = tokio::spawn({
                let app = ctx.app.clone();
                async move {
                    let (ctype, body) = pypi_upload_form("racepkg", filename, "second");
                    let headers = vec![("content-type", ctype.as_str())];
                    crate::test_helpers::send_with_headers(
                        &app,
                        Method::POST,
                        "/simple/",
                        headers,
                        body,
                    )
                    .await
                    .status()
                }
            });
            // Unserialized, the upload stores everything now; serialized with the deletion, it
            // waits for it. (An upload's HTTP path takes milliseconds.)
            let started = std::time::Instant::now();
            while !upload.is_finished() && started.elapsed() < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            drop(record_guard);
            assert_eq!(upload.await.unwrap(), StatusCode::OK, "upload");
            let result = retention.await.unwrap();
            assert_eq!(result.planned, 1, "{:?}", result.plans);
        })
        .await
        .expect("the upload and retention both finished");

        assert!(
            ctx.state.storage.stat(&file_key).await.is_some(),
            "the upload answered 200 and its file is gone"
        );
        assert!(
            ctx.state
                .storage
                .stat(&format!("{file_key}.sha256"))
                .await
                .is_some(),
            "the uploaded file's .sha256 is gone"
        );
        assert!(
            ctx.state.storage.stat(&record_key).await.is_some(),
            "the uploaded file's own-file record is gone"
        );
        let index = text(&ctx, "/simple/racepkg/").await;
        assert!(
            index.contains(filename),
            "the index does not list the upload: {index}"
        );
    }

    #[tokio::test]
    async fn pypi_reupload_during_retention_keeps_its_record_local() {
        let (ctx, _outage, _dir) = local();
        pypi_reupload_keeps_its_record(ctx).await;
    }

    #[tokio::test]
    async fn pypi_reupload_during_retention_keeps_its_record_object_store() {
        let (ctx, _outage, _dir) = in_memory();
        pypi_reupload_keeps_its_record(ctx).await;
    }

    /// PyPI: retention planned a file's deletion from its stored state, then waits for the file's
    /// lock, which an upload replacing the file holds while it rewrites it (the test holds the lock
    /// and writes as the upload does). Under the lock the file no longer reads as planned, so it is
    /// kept, and reported nowhere as deleted.
    async fn pypi_file_rewritten_after_planning_is_kept(ctx: TestContext, outage: StorageOutage) {
        let filename = "racepkg-1.0.0.tar.gz";
        let file_key = format!("pypi/racepkg/{filename}");
        assert_eq!(pypi_upload(&ctx, filename, "first").await, StatusCode::OK);
        // Ages in whole seconds: the rewrite is a second younger than the planned file.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let file_lock = crate::acquire_publish_lock(&ctx.state.publish_locks, &file_key);
        let upload_guard = file_lock.lock().await;
        let planned_from = outage.watch_reads_of(&file_key, 1);
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![rule("pypi", Some(0), None)];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            // The file's age was read (its stat): the plan is made.
            planned_from.answered().await;
            ctx.state.storage.put(&file_key, b"second").await.unwrap();
            let sha = hex::encode(sha2::Sha256::digest(b"second"));
            ctx.state
                .storage
                .put(&format!("{file_key}.sha256"), sha.as_bytes())
                .await
                .unwrap();
            drop(upload_guard);
            retention.await.unwrap()
        })
        .await
        .expect("retention finished");

        assert_eq!(
            ctx.state.storage.get(&file_key).await.ok().as_deref(),
            Some(&b"second"[..]),
            "the rewritten file was deleted by a plan made before it"
        );
        assert_eq!(
            result.planned, 0,
            "a kept file reported as deleted: {:?}",
            result.plans
        );
    }

    #[tokio::test]
    async fn pypi_file_rewritten_after_planning_is_kept_local() {
        let (ctx, outage, _dir) = local();
        pypi_file_rewritten_after_planning_is_kept(ctx, outage).await;
    }

    #[tokio::test]
    async fn pypi_file_rewritten_after_planning_is_kept_object_store() {
        let (ctx, outage, _dir) = in_memory();
        pypi_file_rewritten_after_planning_is_kept(ctx, outage).await;
    }

    /// PyPI: retention plans from a file whose first upload is still running — the file is
    /// stored, its `.sha256`, hash marker and record are not yet — and waits for the file's lock,
    /// which the upload holds. The plan takes the file alone; what the upload leaves is the file
    /// and what it wrote beside it, so the file is kept, not deleted from under them.
    async fn pypi_file_planned_during_its_upload_is_kept(ctx: TestContext, outage: StorageOutage) {
        let filename = "racepkg-1.0.0.tar.gz";
        let file_key = format!("pypi/racepkg/{filename}");
        let hash_key = format!("{file_key}.sha256");
        let digest = hex::encode(sha2::Sha256::digest(b"first"));
        let held = outage.hold_write_of(&hash_key, digest.as_bytes());
        // CANCEL-SAFETY: a watchdog over the scenario: a deadlock fails the test instead of
        // stalling the run; nothing is ordered by it.
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let upload = tokio::spawn({
                let app = ctx.app.clone();
                async move {
                    let (ctype, body) = pypi_upload_form("racepkg", filename, "first");
                    let headers = vec![("content-type", ctype.as_str())];
                    crate::test_helpers::send_with_headers(
                        &app,
                        Method::POST,
                        "/simple/",
                        headers,
                        body,
                    )
                    .await
                    .status()
                }
            });
            held.reached().await;
            // Retention looks for the file's `.sha256` after it read the file's age: once that
            // is answered, the plan is made from the file alone.
            let planned_from = outage.watch_reads_of(&hash_key, 1);
            let (storage, locks, signer) = (
                ctx.state.storage.clone(),
                ctx.state.publish_locks.clone(),
                ctx.state.signer.clone(),
            );
            let rules = vec![rule("pypi", Some(0), None)];
            let retention = tokio::spawn(async move {
                run_retention(&storage, &locks, signer.as_deref(), &rules, false).await
            });
            planned_from.answered().await;
            held.release();
            assert_eq!(upload.await.unwrap(), StatusCode::OK, "upload");
            retention.await.unwrap()
        })
        .await
        .expect("the upload and retention both finished");

        assert!(
            ctx.state.storage.stat(&file_key).await.is_some(),
            "the upload answered 200 and its file is gone"
        );
        assert!(
            ctx.state.storage.stat(&hash_key).await.is_some(),
            "the uploaded file's .sha256 is gone"
        );
        let index = text(&ctx, "/simple/racepkg/").await;
        assert!(
            index.contains(filename),
            "the index does not list the upload: {index}"
        );
        assert_eq!(
            result.planned, 0,
            "a kept file reported as deleted: {:?}",
            result.plans
        );
    }

    #[tokio::test]
    async fn pypi_file_planned_during_its_upload_is_kept_local() {
        let (ctx, outage, _dir) = local();
        pypi_file_planned_during_its_upload_is_kept(ctx, outage).await;
    }

    #[tokio::test]
    async fn pypi_file_planned_during_its_upload_is_kept_object_store() {
        let (ctx, outage, _dir) = in_memory();
        pypi_file_planned_during_its_upload_is_kept(ctx, outage).await;
    }
}
