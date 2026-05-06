// Copyright (c) 2026 The NORA Authors
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
pub async fn mirror_npm_packages(
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
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed — stop scheduling
        };
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

/// Parse yarn.lock v1 format
/// Format: "package@version:\n  version \"X.Y.Z\"\n  resolved \"url\""
pub fn parse_yarn_lock(content: &str) -> Vec<MirrorTarget> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // Package header: "lodash@^4.17.21:" or "@babel/core@^7.0.0, @babel/core@^7.26.0:"
        if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':');
            // Take first entry before comma (all resolve to same version)
            let first = header.split(',').next().unwrap_or(header).trim();
            // Remove quotes if present
            let first = first.trim_matches('"');
            // Extract package name: everything before last @
            if let Some(name) = extract_yarn_package_name(first) {
                current_name = Some(name.to_string());
            } else {
                current_name = None;
            }
            continue;
        }

        // Version line: "  version "4.17.21""
        if let Some(ref name) = current_name {
            if trimmed.starts_with("version ") {
                let ver = trimmed.trim_start_matches("version ").trim_matches('"');
                let pair = (name.clone(), ver.to_string());
                if seen.insert(pair.clone()) {
                    targets.push(MirrorTarget {
                        name: pair.0,
                        version: pair.1,
                    });
                }
                current_name = None;
            }
        }
    }

    targets
}

/// Extract package name from yarn.lock entry like "@babel/core@^7.0.0"
fn extract_yarn_package_name(entry: &str) -> Option<&str> {
    if let Some(rest) = entry.strip_prefix('@') {
        // Scoped: @babel/core@^7.0.0 → find second @
        let after_scope = rest.find('@')?;
        Some(&entry[..after_scope + 1])
    } else {
        // Regular: lodash@^4.17.21 → find first @
        let at = entry.find('@')?;
        if at == 0 {
            None
        } else {
            Some(&entry[..at])
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn test_extract_package_name_simple() {
        assert_eq!(extract_package_name("node_modules/lodash"), Some("lodash"));
    }

    #[test]
    fn test_extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("node_modules/@babel/core"),
            Some("@babel/core")
        );
    }

    #[test]
    fn test_extract_package_name_nested() {
        assert_eq!(
            extract_package_name("node_modules/foo/node_modules/@scope/bar"),
            Some("@scope/bar")
        );
    }

    #[test]
    fn test_extract_package_name_no_node_modules() {
        assert_eq!(extract_package_name("just/a/path"), None);
    }

    #[test]
    fn test_extract_package_name_empty_after() {
        assert_eq!(extract_package_name("node_modules/"), None);
    }

    #[test]
    fn test_parse_lockfile_v2() {
        let lockfile = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "root"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/@types/node": {"version": "20.11.0"}
            }
        });
        let targets = parse_npm_lockfile(&lockfile.to_string()).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_parse_lockfile_empty_packages() {
        let lockfile = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {}
        });
        let targets = parse_npm_lockfile(&lockfile.to_string()).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_lockfile_invalid_json() {
        let result = parse_npm_lockfile("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lockfile_v1_nested() {
        let lockfile = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": {"version": "1.3.8"}
                    }
                }
            }
        });
        let targets = parse_npm_lockfile(&lockfile.to_string()).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_parse_lockfile_v2_falls_back_to_v1() {
        // v2 with empty packages should fall back to v1 dependencies
        let lockfile = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {},
            "dependencies": {
                "lodash": {"version": "4.17.21"}
            }
        });
        let targets = parse_npm_lockfile(&lockfile.to_string()).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "lodash");
    }

    #[test]
    fn test_parse_lockfile_no_version_field() {
        let lockfile = serde_json::json!({
            "packages": {
                "node_modules/something": {"resolved": "https://example.com"}
            }
        });
        let targets = parse_npm_lockfile(&lockfile.to_string()).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_yarn_lock_basic() {
        let content = r#"# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
"#;
        let targets = parse_yarn_lock(content);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "lodash");
        assert_eq!(targets[0].version, "4.17.21");
        assert_eq!(targets[1].name, "express");
        assert_eq!(targets[1].version, "4.18.2");
    }

    #[test]
    fn test_parse_yarn_lock_scoped() {
        let content = r#"
"@babel/core@^7.26.0":
  version "7.26.0"
  resolved "https://registry.npmjs.org/@babel/core/-/core-7.26.0.tgz"
"#;
        let targets = parse_yarn_lock(content);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "@babel/core");
        assert_eq!(targets[0].version, "7.26.0");
    }

    #[test]
    fn test_parse_yarn_lock_multiple_ranges() {
        let content = r#"
debug@2.6.9, debug@^2.2.0:
  version "2.6.9"
  resolved "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"

debug@^4.1.0, debug@^4.3.4:
  version "4.3.7"
  resolved "https://registry.npmjs.org/debug/-/debug-4.3.7.tgz"
"#;
        let targets = parse_yarn_lock(content);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "debug");
        assert_eq!(targets[0].version, "2.6.9");
        assert_eq!(targets[1].name, "debug");
        assert_eq!(targets[1].version, "4.3.7");
    }

    #[test]
    fn test_parse_yarn_lock_dedup() {
        let content = r#"
lodash@^4.0.0:
  version "4.17.21"

lodash@^4.17.0:
  version "4.17.21"
"#;
        let targets = parse_yarn_lock(content);
        assert_eq!(targets.len(), 1); // same name+version deduped
    }

    #[test]
    fn test_parse_yarn_lock_empty() {
        let targets = parse_yarn_lock(
            "# yarn lockfile v1

",
        );
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_yarn_lock_comments_only() {
        let content = "# yarn lockfile v1
# comment
";
        let targets = parse_yarn_lock(content);
        assert!(targets.is_empty());
    }

    #[test]
    fn test_extract_yarn_package_name_simple() {
        assert_eq!(extract_yarn_package_name("lodash@^4.17.21"), Some("lodash"));
    }

    #[test]
    fn test_extract_yarn_package_name_scoped() {
        assert_eq!(
            extract_yarn_package_name("@babel/core@^7.0.0"),
            Some("@babel/core")
        );
    }

    #[test]
    fn test_extract_yarn_package_name_no_at() {
        assert_eq!(extract_yarn_package_name("lodash"), None);
    }

    #[test]
    fn test_parse_yarn_lock_quoted_headers() {
        let content = r#"
"@types/node@^20.0.0":
  version "20.11.5"
  resolved "https://registry.npmjs.org/@types/node/-/node-20.11.5.tgz"
"#;
        let targets = parse_yarn_lock(content);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "@types/node");
        assert_eq!(targets[0].version, "20.11.5");
    }
}
