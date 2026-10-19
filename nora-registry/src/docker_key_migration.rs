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
//! 2. Classify each key as namespaced (first segment after `docker/` contains a dot)
//!    or legacy (no dot — plain image name)
//! 3. For legacy keys:
//!    - If a namespaced equivalent already exists → delete legacy (dedup)
//!    - If no namespaced equivalent → copy data to namespaced key, verify, delete legacy (migrate)
//! 4. Already-namespaced keys are skipped
//! 5. A repository with a tag pushed here (its bare `.meta.json` records the push) is hosted, not
//!    a flat proxy cache: none of its keys are moved or deleted

use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, warn};

use crate::registry::docker::strip_docker_namespace;
use crate::storage::Storage;

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
/// `namespace` is the target namespace prefix (e.g., `"docker.io"`), typically
/// derived from `DockerUpstream::resolved_namespace()`.
pub async fn migrate_docker_keys(
    storage: &Storage,
    namespace: &str,
    options: MigrateDockerKeysOptions,
) -> Result<MigrateDockerKeysStats, String> {
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

    let pushed = pushed_repositories(storage, &all_keys)
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

        // Classify: if strip_docker_namespace changes the name, it's already namespaced
        let canonical = strip_docker_namespace(repo_name);
        if canonical != repo_name {
            // Already namespaced — no action needed
            stats.skipped += 1;
            pb.inc(1);
            continue;
        }

        // A repository pushed here keeps its bare keys: they are the pushed images.
        if pushed.contains(repo_name) {
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
            || strip_docker_namespace(repo) != repo
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
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
            "docker.io",
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        assert_eq!(stats1.migrated, 1);

        // Second run: nothing to do
        let stats2 = migrate_docker_keys(
            &storage,
            "docker.io",
            MigrateDockerKeysOptions { dry_run: false },
        )
        .await
        .unwrap();
        assert_eq!(stats2.migrated, 0);
        assert_eq!(stats2.skipped, 1);
    }
}
