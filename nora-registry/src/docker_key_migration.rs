// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Docker storage key migration — consolidate legacy flat keys into namespaced format.
//!
//! After introducing namespaced storage keys (`docker/{namespace}/{name}/...`),
//! existing installations may have legacy keys (`docker/{name}/...`) alongside
//! new namespaced keys for the same images. This module provides a CLI migration
//! to consolidate them, eliminating double-counting in GC/retention and storage
//! reporting.
//!
//! Algorithm:
//! 1. List all keys under `docker/`
//! 2. Classify each key as namespaced or legacy (plain image name). A key is namespaced when its
//!    first segment is the storage namespace of a configured Docker upstream — the one the proxy
//!    writes its copies under, dotless or not — or holds a dot, as it always did (#1271)
//! 3. For legacy keys:
//!    - If a namespaced equivalent already exists → delete legacy (dedup)
//!    - If no namespaced equivalent → copy data to namespaced key, verify, delete legacy (migrate)
//! 4. Already-namespaced keys are skipped
//! 5. A repository with a tag pushed here (its bare `.meta.json` records the push) is hosted, not
//!    a flat proxy cache: none of its keys are moved or deleted

use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, warn};

use crate::config::DockerConfig;
use crate::storage::Storage;

/// The storage namespace of every Docker upstream, as the proxy computes it
/// ([`crate::config::DockerUpstream::resolved_namespace`]: explicit, or derived from its url).
/// The first is where legacy keys move, as before; with no upstream it is `docker.io`.
pub fn upstream_namespaces(docker: &DockerConfig) -> Vec<String> {
    if docker.upstreams.is_empty() {
        return vec!["docker.io".to_string()];
    }
    docker
        .upstreams
        .iter()
        .map(|upstream| upstream.resolved_namespace())
        .collect()
}

/// Whether the repository of a key under `docker/` already carries a storage namespace: its
/// leading segments are a namespace some upstream was given (`harbor/team/app` for `harbor`), or
/// its first segment holds a dot, as it always did — that keeps the copies of a host no upstream
/// here is configured for. A bare name is never namespaced, nor a name with nothing after the
/// namespace (#1271).
fn is_namespaced(repo: &str, namespaces: &[String]) -> bool {
    let dotted = repo
        .split_once('/')
        .is_some_and(|(first, rest)| first.contains('.') && !rest.is_empty());
    dotted
        || namespaces.iter().any(|ns| {
            !ns.is_empty()
                && repo
                    .strip_prefix(ns.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|rest| !rest.is_empty())
        })
}

/// Migration options
#[derive(Default)]
pub struct MigrateDockerKeysOptions {
    /// If true, show what would be done without modifying storage
    pub dry_run: bool,
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrateDockerKeysStats {
    /// Total docker keys scanned
    pub total_keys: usize,
    /// Legacy keys copied to namespaced format and deleted
    pub migrated: usize,
    /// Legacy keys deleted because namespaced equivalent exists
    pub deduped: usize,
    /// Already-namespaced keys (no action needed)
    pub skipped: usize,
    /// Keys that failed to migrate
    pub failed: usize,
    /// Bytes freed by removing legacy duplicates
    pub bytes_freed: u64,
}

/// Migrate legacy Docker storage keys to namespaced format.
///
/// `namespaces` is the storage namespace of every Docker upstream ([`upstream_namespaces`]); a key
/// already under one of them is kept. Legacy keys move under the first, the target.
pub async fn migrate_docker_keys(
    storage: &Storage,
    namespaces: &[String],
    options: MigrateDockerKeysOptions,
) -> Result<MigrateDockerKeysStats, String> {
    let Some(namespace) = namespaces.first() else {
        return Err("no Docker upstream namespace to migrate legacy keys under".to_string());
    };
    println!("Docker key migration: legacy → namespaced (namespace: {namespace})");

    if options.dry_run {
        println!("DRY RUN — no data will be modified");
    }

    println!("Scanning docker storage keys...");
    let all_keys = storage
        .list("docker/")
        .await
        .map_err(|e| format!("Failed to list docker keys: {}", e))?;

    if all_keys.is_empty() {
        println!("No docker keys found in storage.");
        return Ok(MigrateDockerKeysStats::default());
    }

    println!("Found {} docker keys to analyze", all_keys.len());

    let pb = ProgressBar::new(all_keys.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress bar template")
            .progress_chars("#>-"),
    );

    let mut stats = MigrateDockerKeysStats {
        total_keys: all_keys.len(),
        ..Default::default()
    };

    let pushed = pushed_repositories(storage, &all_keys, namespaces)
        .await
        .map_err(|e| format!("Failed to read a push record: {e}"))?;

    for key in &all_keys {
        let Some(rest) = key.strip_prefix("docker/") else {
            stats.skipped += 1;
            pb.inc(1);
            continue;
        };

        let Some(repo_name) = repository_of(rest) else {
            // Not a manifest or blob key — skip (e.g., metadata or unknown)
            stats.skipped += 1;
            pb.inc(1);
            continue;
        };

        // Already under an upstream's namespace (or a dotted host): no action needed
        if is_namespaced(repo_name, namespaces) {
            // Already namespaced — no action needed
            stats.skipped += 1;
            pb.inc(1);
            continue;
        }

        // A repository pushed here keeps its bare keys: they are the pushed images. So does
        // everything under the root of pushes made under a registry host or prefix.
        let qualified_push = repo_name
            .strip_prefix(crate::config::QUALIFIED_PUSH_ROOT)
            .is_some_and(|rest| rest.starts_with('/'));
        if qualified_push || pushed.contains(repo_name) {
            stats.skipped += 1;
            pb.inc(1);
            continue;
        }

        // This is a legacy key (no namespace prefix).
        // Build the target namespaced key by inserting {namespace}/ after "docker/".
        let namespaced_key = format!("docker/{namespace}/{rest}");

        // Check if the namespaced equivalent already exists
        let ns_exists = storage.stat(&namespaced_key).await.is_some();

        if ns_exists {
            // Namespaced key exists — just remove the legacy duplicate
            let freed = storage.stat(key).await.map_or(0, |m| m.size);

            if options.dry_run {
                info!(
                    legacy_key = %key,
                    namespaced_key = %namespaced_key,
                    bytes = freed,
                    action = "dedup",
                    "would delete legacy duplicate"
                );
                stats.deduped += 1;
                stats.bytes_freed += freed;
            } else {
                match storage.delete(key).await {
                    Ok(()) => {
                        info!(
                            legacy_key = %key,
                            namespaced_key = %namespaced_key,
                            bytes = freed,
                            action = "dedup",
                            "deleted legacy duplicate"
                        );
                        stats.deduped += 1;
                        stats.bytes_freed += freed;
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "failed to delete legacy key");
                        stats.failed += 1;
                    }
                }
            }
        } else {
            // No namespaced equivalent — copy data then delete legacy
            if options.dry_run {
                let size = storage.stat(key).await.map_or(0, |m| m.size);
                info!(
                    legacy_key = %key,
                    namespaced_key = %namespaced_key,
                    bytes = size,
                    action = "migrate",
                    "would copy to namespaced key and delete legacy"
                );
                stats.migrated += 1;
            } else {
                match storage.get(key).await {
                    Ok(data) => {
                        let data_len = data.len() as u64;

                        // Write to namespaced location
                        if let Err(e) = storage.put(&namespaced_key, &data).await {
                            warn!(
                                key = %namespaced_key,
                                error = %e,
                                "failed to write namespaced key"
                            );
                            stats.failed += 1;
                            pb.inc(1);
                            continue;
                        }

                        // Verify write: check size matches
                        let written_size =
                            storage.stat(&namespaced_key).await.map_or(0, |m| m.size);
                        if written_size != data_len {
                            warn!(
                                key = %namespaced_key,
                                expected = data_len,
                                actual = written_size,
                                "size mismatch after write — skipping delete"
                            );
                            stats.failed += 1;
                            pb.inc(1);
                            continue;
                        }

                        // Delete legacy key
                        match storage.delete(key).await {
                            Ok(()) => {
                                info!(
                                    legacy_key = %key,
                                    namespaced_key = %namespaced_key,
                                    bytes = data_len,
                                    action = "migrate",
                                    "migrated to namespaced key"
                                );
                                stats.migrated += 1;
                                stats.bytes_freed += data_len;
                            }
                            Err(e) => {
                                warn!(
                                    key = %key,
                                    error = %e,
                                    "copied to namespaced but failed to delete legacy"
                                );
                                // Still counts as partial success — data is not lost
                                stats.migrated += 1;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "failed to read legacy key");
                        stats.failed += 1;
                    }
                }
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Migration complete");

    println!();
    println!("Docker key migration summary:");
    println!("  Total keys scanned:  {}", stats.total_keys);
    println!("  Migrated (copy+del): {}", stats.migrated);
    println!("  Deduped (del legacy): {}", stats.deduped);
    println!("  Skipped (already ns): {}", stats.skipped);
    println!("  Failed:              {}", stats.failed);
    println!("  Bytes freed:         {} KB", stats.bytes_freed / 1024);

    if stats.failed > 0 {
        warn!("{} keys failed to migrate", stats.failed);
    }

    if options.dry_run {
        info!("Dry run complete. Re-run without --dry-run to perform actual migration.");
    }

    Ok(stats)
}

/// The repository a key under `docker/` belongs to: everything before its last `/manifests/` or
/// `/blobs/`, read from the right as a request path is, so `a/manifests/b` is one repository and
/// both loops of the migration see the same name. None for any other key.
fn repository_of(rest: &str) -> Option<&str> {
    let at = [rest.rfind("/manifests/"), rest.rfind("/blobs/")]
        .into_iter()
        .flatten()
        .max()?;
    Some(&rest[..at]).filter(|repo| !repo.is_empty())
}

/// The bare repositories with at least one tag whose `.meta.json` records a push. A record that
/// cannot be read fails the migration: guessing would move or delete a pushed image.
async fn pushed_repositories(
    storage: &Storage,
    keys: &[String],
    namespaces: &[String],
) -> crate::storage::Result<std::collections::HashSet<String>> {
    let mut pushed = std::collections::HashSet::new();
    for key in keys {
        let Some(rest) = key.strip_prefix("docker/") else {
            continue;
        };
        let Some(repo) = repository_of(rest) else {
            continue;
        };
        let file = &rest[repo.len()..];
        if !file.starts_with("/manifests/")
            || !file.ends_with(".meta.json")
            || is_namespaced(repo, namespaces)
        {
            continue;
        }
        let meta = storage.get(key).await.inspect_err(|e| {
            warn!(key = %key, error = %e, "push record unreadable");
        })?;
        // The resolver's own test of a push record: one predicate decides what is a push.
        if crate::registry::docker::push_record(&meta).is_some() {
            pushed.insert(repo.to_string());
        }
    }
    Ok(pushed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The storage namespaces of the upstreams a test configures; the first one is the target.
    fn names(namespaces: &[&str]) -> Vec<String> {
        namespaces.iter().map(|ns| ns.to_string()).collect()
    }

    /// A tag pushed here records the push in its bare `.meta.json`: its repository is hosted and
    /// keeps every bare key — with or without a proxied copy of the same tag. A repository without
    /// a record is migrated as before.
    #[tokio::test]
    async fn a_pushed_repository_keeps_its_bare_keys() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let pushed = [
            ("docker/corp/app/manifests/1.0.json", &b"pushed"[..]),
            (
                "docker/corp/app/manifests/1.0.meta.json",
                &br#"{"push_timestamp":1,"last_pulled":0,"downloads":0,"size_bytes":0,"os":"","arch":"","layers":[],"pushed_digest":"sha256:00"}"#[..],
            ),
            ("docker/corp/app/manifests/sha256:00.json", &b"pushed"[..]),
            ("docker/corp/app/blobs/sha256:11", &b"layer"[..]),
        ];
        for (key, data) in pushed {
            storage.put(key, data).await.unwrap();
        }
        storage
            .put("docker/docker.io/corp/app/manifests/1.0.json", b"proxied")
            .await
            .unwrap();
        storage
            .put("docker/library/nginx/manifests/latest.json", b"flat cache")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        for (key, data) in pushed {
            assert_eq!(&*storage.get(key).await.unwrap(), data, "{key}");
        }
        assert!(storage
            .get("docker/docker.io/library/nginx/manifests/latest.json")
            .await
            .is_ok());
        assert_eq!(stats.migrated, 1);
        assert_eq!(stats.deduped, 0);
    }

    /// A push under a registry host or prefix (`_/…`) is never moved under an upstream's
    /// namespace, with or without its push record (a blob uploaded before its manifest).
    #[tokio::test]
    async fn a_push_under_a_host_keeps_its_keys() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let keys = [
            "docker/_/quay.io/org/img/manifests/v1.json",
            "docker/_/quay.io/org/img/blobs/sha256:11",
            "docker/_/hub/acme/tool/blobs/sha256:22",
        ];
        for key in keys {
            storage.put(key, b"x").await.unwrap();
        }
        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        for key in keys {
            assert!(storage.get(key).await.is_ok(), "{key}");
        }
        assert_eq!(stats.migrated, 0);
    }

    #[test]
    fn a_repository_is_read_from_the_right() {
        for (key, repo) in [
            ("corp/app/manifests/1.0.json", Some("corp/app")),
            ("corp/app/blobs/sha256:11", Some("corp/app")),
            (
                "corp/manifests/app/manifests/1.0.json",
                Some("corp/manifests/app"),
            ),
            (
                "corp/manifests/app/blobs/sha256:11",
                Some("corp/manifests/app"),
            ),
            ("x/blobs/y/manifests/1.0.meta.json", Some("x/blobs/y")),
            ("app/manifests/1.0.json", Some("app")),
            ("/manifests/1.0.json", None),
            ("corp/app/1.0.json", None),
        ] {
            assert_eq!(repository_of(key), repo, "{key}");
        }
    }

    /// Every pushed repository keeps its keys — several of them, and one whose name has a
    /// `manifests` component (a repository name is read from the right, as a request is).
    #[tokio::test]
    async fn every_pushed_repository_keeps_its_keys() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let record = br#"{"push_timestamp":1,"last_pulled":0,"downloads":0,"size_bytes":0,"os":"","arch":"","layers":[],"pushed_digest":"sha256:00"}"#;
        let mut kept = Vec::new();
        for repo in ["corp/a", "corp/b", "corp/manifests/app"] {
            for (file, data) in [
                ("manifests/1.0.json", &b"pushed"[..]),
                ("manifests/1.0.meta.json", &record[..]),
                ("blobs/sha256:11", &b"layer"[..]),
            ] {
                let key = format!("docker/{repo}/{file}");
                storage.put(&key, data).await.unwrap();
                kept.push((key, data));
            }
        }
        migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        for (key, data) in kept {
            assert_eq!(&*storage.get(&key).await.unwrap(), data, "{key}");
        }
    }

    /// A metadata file whose `pushed_digest` names no digest is not a push record — for the migration
    /// as for the resolver (one predicate): its flat repository is moved like any proxied cache.
    #[tokio::test]
    async fn a_record_naming_no_digest_is_not_a_push() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let not_a_record = br#"{"push_timestamp":1,"last_pulled":0,"downloads":0,"size_bytes":0,"os":"","arch":"","layers":[],"pushed_digest":"md5:00"}"#;
        storage
            .put("docker/corp/app/manifests/1.0.meta.json", not_a_record)
            .await
            .unwrap();
        storage
            .put("docker/corp/app/manifests/1.0.json", b"flat cache")
            .await
            .unwrap();
        migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        assert!(storage
            .stat("docker/corp/app/manifests/1.0.json")
            .await
            .is_none());
        assert_eq!(
            &*storage
                .get("docker/docker.io/corp/app/manifests/1.0.json")
                .await
                .unwrap(),
            b"flat cache"
        );
    }

    /// A push record that cannot be read stops the migration before anything moves: guessing
    /// "not pushed" would move or delete a pushed image.
    #[tokio::test]
    async fn an_unreadable_push_record_stops_the_migration() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        storage
            .put(
                "docker/corp/app/manifests/1.0.meta.json",
                br#"{"push_timestamp":1,"last_pulled":0,"downloads":0,"size_bytes":0,"os":"","arch":"","layers":[],"pushed_digest":"sha256:00"}"#,
            )
            .await
            .unwrap();
        storage
            .put("docker/corp/app/manifests/1.0.json", b"pushed")
            .await
            .unwrap();
        storage
            .put("docker/library/nginx/manifests/latest.json", b"flat cache")
            .await
            .unwrap();
        // The record's bytes change under its stored digest: the read fails closed.
        std::fs::write(
            dir.path().join("docker/corp/app/manifests/1.0.meta.json"),
            b"{}",
        )
        .unwrap();
        assert!(storage
            .get("docker/corp/app/manifests/1.0.meta.json")
            .await
            .is_err());

        let result = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await;
        assert!(result.is_err());
        assert!(storage
            .get("docker/corp/app/manifests/1.0.json")
            .await
            .is_ok());
        assert!(storage
            .get("docker/library/nginx/manifests/latest.json")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_migrate_legacy_to_namespaced() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Legacy key (no namespace)
        storage
            .put(
                "docker/library/nginx/manifests/latest.json",
                b"manifest-data",
            )
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(stats.migrated, 1);
        assert_eq!(stats.deduped, 0);
        assert_eq!(stats.failed, 0);

        // Legacy key should be gone
        assert!(storage
            .get("docker/library/nginx/manifests/latest.json")
            .await
            .is_err());
        // Namespaced key should exist with same data
        let data = storage
            .get("docker/docker.io/library/nginx/manifests/latest.json")
            .await
            .unwrap();
        assert_eq!(&*data, b"manifest-data");
    }

    #[tokio::test]
    async fn test_dedup_when_both_exist() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Both formats exist
        storage
            .put("docker/library/nginx/manifests/latest.json", b"old-data")
            .await
            .unwrap();
        storage
            .put(
                "docker/docker.io/library/nginx/manifests/latest.json",
                b"new-data",
            )
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(stats.deduped, 1, "legacy duplicate should be deduped");
        assert_eq!(stats.skipped, 1, "namespaced key should be skipped");
        assert_eq!(stats.migrated, 0);

        // Legacy gone, namespaced preserved with its own data
        assert!(storage
            .get("docker/library/nginx/manifests/latest.json")
            .await
            .is_err());
        let data = storage
            .get("docker/docker.io/library/nginx/manifests/latest.json")
            .await
            .unwrap();
        assert_eq!(&*data, b"new-data");
    }

    #[tokio::test]
    async fn test_skip_already_namespaced() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Only namespaced key
        storage
            .put(
                "docker/docker.io/library/nginx/manifests/latest.json",
                b"data",
            )
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.migrated, 0);
        assert_eq!(stats.deduped, 0);
    }

    #[tokio::test]
    async fn test_dry_run_does_not_modify() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        storage
            .put("docker/library/nginx/manifests/latest.json", b"data")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: true },
        )
        .await
        .unwrap();

        assert_eq!(stats.migrated, 1);

        // Original key should still exist (dry run)
        assert!(storage
            .get("docker/library/nginx/manifests/latest.json")
            .await
            .is_ok());
        // Namespaced key should NOT exist
        assert!(storage
            .get("docker/docker.io/library/nginx/manifests/latest.json")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_empty_storage() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.migrated, 0);
    }

    #[tokio::test]
    async fn test_migrate_blobs() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Legacy blob key
        storage
            .put("docker/library/nginx/blobs/sha256:abc123", b"blob-data")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(stats.migrated, 1);

        // Should be at namespaced location
        let data = storage
            .get("docker/docker.io/library/nginx/blobs/sha256:abc123")
            .await
            .unwrap();
        assert_eq!(&*data, b"blob-data");
    }

    #[tokio::test]
    async fn test_idempotent() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        storage
            .put("docker/library/nginx/manifests/latest.json", b"data")
            .await
            .unwrap();

        // First run: migrates
        let stats1 = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        assert_eq!(stats1.migrated, 1);

        // Second run: nothing to do
        let stats2 = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        assert_eq!(stats2.migrated, 0);
        assert_eq!(stats2.skipped, 1);
    }

    /// A copy a pull through an upstream whose namespace has no dot leaves under that namespace
    /// (`http://harbor:5000` → `harbor`, `localhost:5000` → `localhost`) is already namespaced,
    /// flat or deep: it stays where it is and is not written a second time under itself (#1271).
    #[tokio::test]
    async fn a_copy_under_a_one_word_namespace_is_not_moved() {
        let cases: [(&str, &[&str]); 2] = [
            (
                "harbor",
                &[
                    "docker/harbor/team/app/manifests/1.0.json",
                    "docker/harbor/team/app/blobs/sha256:11",
                    "docker/harbor/team/sub/app/manifests/1.0.json",
                ],
            ),
            ("localhost", &["docker/localhost/app/manifests/latest.json"]),
        ];
        for (namespace, keys) in cases {
            let dir = TempDir::new().unwrap();
            let storage = Storage::new_local(dir.path().to_str().unwrap());
            for key in keys {
                storage.put(key, b"proxied").await.unwrap();
            }

            let stats = migrate_docker_keys(
                &storage,
                &names(&[namespace]),
                MigrateDockerKeysOptions { dry_run: false },
            )
            .await
            .unwrap();

            for key in keys {
                assert!(
                    storage.get(key).await.is_ok(),
                    "{key} moved under {namespace}"
                );
            }
            assert!(storage
                .get(&format!(
                    "docker/{namespace}/{namespace}/team/app/manifests/1.0.json"
                ))
                .await
                .is_err());
            assert_eq!(stats.migrated, 0, "{namespace}");
            assert_eq!(stats.skipped, keys.len(), "{namespace}");
        }
    }

    /// A bare key whose first segment is an upstream's namespace, with no push record, stays where
    /// it is: the layout cannot tell it from a copy under that namespace, and moving a pushed image
    /// is the mistake this migration must not make. Where the namespace and a bare name meet, the
    /// namespace wins (#1271).
    #[tokio::test]
    async fn a_bare_key_under_an_upstream_namespace_stays_without_a_push_record() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        storage
            .put("docker/harbor/app/manifests/1.0.json", b"unrecorded")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["harbor"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert!(storage
            .get("docker/harbor/app/manifests/1.0.json")
            .await
            .is_ok());
        assert_eq!(stats.migrated, 0);
    }

    /// The same first segment with a push record: the repository is hosted and keeps every key,
    /// as before the fix (#1271 — the pushed set is unchanged).
    #[tokio::test]
    async fn a_pushed_repository_under_an_upstream_namespace_keeps_its_keys() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        for (key, data) in [
            ("docker/harbor/app/manifests/1.0.json", &b"pushed"[..]),
            (
                "docker/harbor/app/manifests/1.0.meta.json",
                &br#"{"push_timestamp":1,"last_pulled":0,"downloads":0,"size_bytes":0,"os":"","arch":"","layers":[],"pushed_digest":"sha256:00"}"#[..],
            ),
            ("docker/harbor/app/blobs/sha256:11", &b"layer"[..]),
        ] {
            storage.put(key, data).await.unwrap();
        }

        let stats = migrate_docker_keys(
            &storage,
            &names(&["harbor"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert!(storage
            .get("docker/harbor/app/manifests/1.0.json")
            .await
            .is_ok());
        assert!(storage
            .get("docker/harbor/app/blobs/sha256:11")
            .await
            .is_ok());
        assert!(storage
            .get("docker/harbor/harbor/app/manifests/1.0.json")
            .await
            .is_err());
        assert_eq!(stats.migrated, 0);
    }

    /// The namespace of each upstream is the one the proxy writes its copies under: explicit, or
    /// derived from its url (`http://harbor:5000` → `harbor`). The first is the migration's target.
    #[test]
    fn upstream_namespaces_are_the_proxy_s_own() {
        use crate::config::DockerUpstream;
        let upstream = |url: &str, namespace: Option<&str>| DockerUpstream {
            url: url.to_string(),
            auth: None,
            namespace: namespace.map(str::to_string),
            prefix: None,
            namespaces: Vec::new(),
            metadata_ttl: None,
        };
        let mut docker = DockerConfig::default();
        docker.upstreams = vec![
            upstream("http://harbor:5000", None),
            upstream("https://registry-1.docker.io", None),
            upstream("http://localhost:5000", None),
            upstream("https://mirror.example", Some("team")),
        ];
        assert_eq!(
            upstream_namespaces(&docker),
            names(&["harbor", "docker.io", "localhost", "team"])
        );
        docker.upstreams.clear();
        assert_eq!(upstream_namespaces(&docker), names(&["docker.io"]));
    }

    /// A name whose first segment holds a dot is classified as before: namespaced, so kept — the
    /// dot rule stays for hosts no upstream here is configured for (#1271: dotted names unchanged).
    #[tokio::test]
    async fn a_dotted_host_key_is_kept_as_before() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        storage
            .put("docker/ghcr.io/org/img/manifests/1.0.json", b"copy")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert!(storage
            .get("docker/ghcr.io/org/img/manifests/1.0.json")
            .await
            .is_ok());
        assert_eq!(stats.migrated, 0);
    }

    /// The dry run takes the same decision for every key as the real run and leaves the storage as
    /// it found it (#1271: dry-run prints the decision the real run makes).
    #[tokio::test]
    async fn a_dry_run_decides_what_the_real_run_does() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let keys = [
            "docker/library/nginx/manifests/latest.json",
            "docker/app/manifests/1.0.json",
            "docker/harbor/app/manifests/1.0.json",
            "docker/harbor/team/app/manifests/1.0.json",
            "docker/_/quay.io/org/img/manifests/v1.json",
        ];
        for key in keys {
            storage.put(key, b"x").await.unwrap();
        }

        let dry = migrate_docker_keys(
            &storage,
            &names(&["harbor"]),
            MigrateDockerKeysOptions { dry_run: true },
        )
        .await
        .unwrap();
        for key in keys {
            assert!(storage.get(key).await.is_ok(), "dry run touched {key}");
        }

        let real = migrate_docker_keys(
            &storage,
            &names(&["harbor"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert_eq!(
            (dry.migrated, dry.deduped, dry.skipped, dry.failed),
            (real.migrated, real.deduped, real.skipped, real.failed)
        );
        assert_eq!(
            (real.migrated, real.deduped, real.skipped),
            (1, 1, 3),
            "only the library copy and the flat duplicate move; the harbor copies and the host push stay"
        );
        assert!(storage
            .get("docker/harbor/app/manifests/1.0.json")
            .await
            .is_ok());
        assert!(storage
            .get("docker/harbor/team/app/manifests/1.0.json")
            .await
            .is_ok());
    }

    /// Every Docker upstream's namespace keeps its copies, not only the first one's; a legacy key
    /// still moves under the first, the target, as before (#1271).
    #[tokio::test]
    async fn every_upstream_namespace_keeps_its_copies() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        for key in [
            "docker/harbor/team/app/manifests/1.0.json",
            "docker/localhost/app/blobs/sha256:11",
            "docker/docker.io/library/nginx/manifests/latest.json",
            "docker/app/manifests/1.0.json",
        ] {
            storage.put(key, b"x").await.unwrap();
        }

        let stats = migrate_docker_keys(
            &storage,
            &names(&["docker.io", "harbor", "localhost"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert!(storage
            .get("docker/harbor/team/app/manifests/1.0.json")
            .await
            .is_ok());
        assert!(storage
            .get("docker/localhost/app/blobs/sha256:11")
            .await
            .is_ok());
        assert!(storage
            .get("docker/docker.io/app/manifests/1.0.json")
            .await
            .is_ok());
        assert!(storage.get("docker/app/manifests/1.0.json").await.is_err());
        assert_eq!((stats.migrated, stats.skipped), (1, 3));
    }

    /// A namespace is matched by whole segment: `harborx/app` is a bare name, not a copy under
    /// `harbor`, and it moves as any legacy key does (#1271).
    #[tokio::test]
    async fn a_namespace_is_matched_by_segment_not_by_prefix() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        storage
            .put("docker/harborx/app/manifests/1.0.json", b"legacy")
            .await
            .unwrap();

        let stats = migrate_docker_keys(
            &storage,
            &names(&["harbor"]),
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();

        assert!(storage
            .get("docker/harborx/app/manifests/1.0.json")
            .await
            .is_err());
        assert!(storage
            .get("docker/harbor/harborx/app/manifests/1.0.json")
            .await
            .is_ok());
        assert_eq!(stats.migrated, 1);
    }
}
