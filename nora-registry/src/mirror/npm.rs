// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! npm lockfile parser + mirror logic.

use super::{create_progress_bar, MirrorResult, MirrorTarget};
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::sync::Semaphore;

/// Entry point for npm mirroring
pub async fn run_npm_mirror(
    client: &reqwest::Client,
    registry: &str,
    lockfile: Option<PathBuf>,
    packages: Option<Vec<String>>,
    all_versions: bool,
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let targets = if let Some(path) = lockfile {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        parse_npm_lockfile(&content)?
    } else if let Some(names) = packages {
        resolve_npm_packages(client, registry, &names, all_versions).await?
    } else {
        return Err("Specify --lockfile or --packages".to_string());
    };

    if targets.is_empty() {
        println!("No npm packages to mirror");
        return Ok(MirrorResult {
            total: 0,
            fetched: 0,
            failed: 0,
            bytes: 0,
        });
    }

    println!(
        "Mirroring {} npm packages via {}...",
        targets.len(),
        registry
    );
    mirror_npm_packages(client, registry, &targets, concurrency).await
}

/// Parse package-lock.json (v1, v2, v3)
fn parse_npm_lockfile(content: &str) -> Result<Vec<MirrorTarget>, String> {
    let json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let version = json
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    if version >= 2 {
        // v2/v3: use "packages" object
        if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
            for (key, pkg) in packages {
                if key.is_empty() {
                    continue; // root package
                }
                if let Some(name) = extract_package_name(key) {
                    if let Some(ver) = pkg.get("version").and_then(|v| v.as_str()) {
                        let pair = (name.to_string(), ver.to_string());
                        if seen.insert(pair.clone()) {
                            targets.push(MirrorTarget {
                                name: pair.0,
                                version: pair.1,
                            });
                        }
                    }
                }
            }
        }
    }

    if version == 1 || targets.is_empty() {
        // v1 fallback: recursive "dependencies"
        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            parse_v1_deps(deps, &mut targets, &mut seen);
        }
    }

    Ok(targets)
}

/// Extract package name from lockfile key like "node_modules/@babel/core"
fn extract_package_name(key: &str) -> Option<&str> {
    // Handle nested: "node_modules/foo/node_modules/@scope/bar" → "@scope/bar"
    let last_nm = key.rfind("node_modules/")?;
    let after = &key[last_nm + "node_modules/".len()..];
    let name = after.trim_end_matches('/');
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Recursively parse v1 lockfile "dependencies"
fn parse_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    targets: &mut Vec<MirrorTarget>,
    seen: &mut HashSet<(String, String)>,
) {
    for (name, pkg) in deps {
        if let Some(ver) = pkg.get("version").and_then(|v| v.as_str()) {
            let pair = (name.clone(), ver.to_string());
            if seen.insert(pair.clone()) {
                targets.push(MirrorTarget {
                    name: pair.0,
                    version: pair.1,
                });
            }
        }
        // Recurse into nested dependencies
        if let Some(nested) = pkg.get("dependencies").and_then(|d| d.as_object()) {
            parse_v1_deps(nested, targets, seen);
        }
    }
}

/// Resolve --packages list by fetching metadata from NORA
async fn resolve_npm_packages(
    client: &reqwest::Client,
    registry: &str,
    names: &[String],
    all_versions: bool,
) -> Result<Vec<MirrorTarget>, String> {
    let base = registry.trim_end_matches('/');
    let mut targets = Vec::new();

    for name in names {
        let url = format!("{}/npm/{}", base, name);
        let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            eprintln!("Warning: {} not found (HTTP {})", name, resp.status());
            continue;
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

        if all_versions {
            if let Some(versions) = json.get("versions").and_then(|v| v.as_object()) {
                for ver in versions.keys() {
                    targets.push(MirrorTarget {
                        name: name.clone(),
                        version: ver.clone(),
                    });
                }
            }
        } else {
            // Just latest
            let latest = json
                .get("dist-tags")
                .and_then(|d| d.get("latest"))
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            targets.push(MirrorTarget {
                name: name.clone(),
                version: latest.to_string(),
            });
        }
    }

    Ok(targets)
}

/// Fetch packages through NORA (triggers proxy cache)
async fn mirror_npm_packages(
    client: &reqwest::Client,
    registry: &str,
    targets: &[MirrorTarget],
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let base = registry.trim_end_matches('/');
    let pb = create_progress_bar(targets.len() as u64);
    let sem = std::sync::Arc::new(Semaphore::new(concurrency));

    // Deduplicate metadata fetches (one per package name)
    let unique_names: HashSet<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    pb.set_message("fetching metadata...");
    for name in &unique_names {
        let url = format!("{}/npm/{}", base, name);
        let _ = client.get(&url).send().await; // trigger metadata cache
    }

    // Fetch tarballs concurrently
    let fetched = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut handles = Vec::new();

    for target in targets {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed unexpectedly");
        let client = client.clone();
        let pb = pb.clone();
        let fetched = fetched.clone();
        let failed = failed.clone();
        let bytes = bytes.clone();

        let short_name = target.name.split('/').next_back().unwrap_or(&target.name);
        let tarball_url = format!(
            "{}/npm/{}/-/{}-{}.tgz",
            base, target.name, short_name, target.version
        );
        let label = format!("{}@{}", target.name, target.version);

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match client.get(&tarball_url).send().await {
                Ok(r) if r.status().is_success() => {
                    if let Ok(body) = r.bytes().await {
                        bytes.fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {
                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            pb.set_message(label);
            pb.inc(1);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    pb.finish_with_message("done");

    Ok(MirrorResult {
        total: targets.len(),
        fetched: fetched.load(std::sync::atomic::Ordering::Relaxed),
        failed: failed.load(std::sync::atomic::Ordering::Relaxed),
        bytes: bytes.load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name() {
        assert_eq!(extract_package_name("node_modules/lodash"), Some("lodash"));
        assert_eq!(
            extract_package_name("node_modules/@babel/core"),
            Some("@babel/core")
        );
        assert_eq!(
            extract_package_name("node_modules/foo/node_modules/bar"),
            Some("bar")
        );
        assert_eq!(
            extract_package_name("node_modules/foo/node_modules/@types/node"),
            Some("@types/node")
        );
        assert_eq!(extract_package_name(""), None);
    }

    #[test]
    fn test_parse_lockfile_v3() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "test" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@babel/core": { "version": "7.26.0" },
                "node_modules/@babel/core/node_modules/semver": { "version": "6.3.1" }
            }
        }"#;
        let targets = parse_npm_lockfile(content).unwrap();
        assert_eq!(targets.len(), 3);
        let names: HashSet<&str> = targets.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains("lodash"));
        assert!(names.contains("@babel/core"));
        assert!(names.contains("semver"));
    }

    #[test]
    fn test_parse_lockfile_v1() {
        let content = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": { "version": "1.3.8" }
                    }
                }
            }
        }"#;
        let targets = parse_npm_lockfile(content).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "express");
        assert_eq!(targets[1].name, "accepts");
    }

    #[test]
    fn test_deduplication() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/debug": { "version": "4.3.4" },
                "node_modules/express/node_modules/debug": { "version": "4.3.4" }
            }
        }"#;
        let targets = parse_npm_lockfile(content).unwrap();
        assert_eq!(targets.len(), 1); // deduplicated
        assert_eq!(targets[0].name, "debug");
    }
}
