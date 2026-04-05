// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! `nora mirror` — pre-fetch dependencies through NORA proxy cache.

mod npm;

use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum MirrorFormat {
    /// Mirror npm packages
    Npm {
        /// Path to package-lock.json (v1/v2/v3)
        #[arg(long, conflicts_with = "packages")]
        lockfile: Option<PathBuf>,
        /// Comma-separated package names
        #[arg(long, conflicts_with = "lockfile", value_delimiter = ',')]
        packages: Option<Vec<String>>,
        /// Fetch all versions (only with --packages)
        #[arg(long)]
        all_versions: bool,
    },
    /// Mirror npm packages from yarn.lock
    Yarn {
        /// Path to yarn.lock
        #[arg(long)]
        lockfile: PathBuf,
    },
    /// Mirror Python packages
    Pip {
        /// Path to requirements.txt
        #[arg(long)]
        lockfile: PathBuf,
    },
    /// Mirror Cargo crates
    Cargo {
        /// Path to Cargo.lock
        #[arg(long)]
        lockfile: PathBuf,
    },
    /// Mirror Maven artifacts
    Maven {
        /// Path to dependency list (mvn dependency:list output)
        #[arg(long)]
        lockfile: PathBuf,
    },
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct MirrorTarget {
    pub name: String,
    pub version: String,
}

#[derive(serde::Serialize)]
pub struct MirrorResult {
    pub total: usize,
    pub fetched: usize,
    pub failed: usize,
    pub bytes: u64,
}

pub fn create_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
            )
            .expect("static progress bar template is valid")
            .progress_chars("=>-"),
    );
    pb
}

pub async fn run_mirror(
    format: MirrorFormat,
    registry: &str,
    concurrency: usize,
    json_output: bool,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Health check
    let health_url = format!("{}/health", registry.trim_end_matches('/'));
    match client.get(&health_url).send().await {
        Ok(r) if r.status().is_success() => {}
        _ => {
            return Err(format!(
                "Cannot connect to NORA at {}. Is `nora serve` running?",
                registry
            ))
        }
    }

    let start = Instant::now();

    let result = match format {
        MirrorFormat::Npm {
            lockfile,
            packages,
            all_versions,
        } => {
            npm::run_npm_mirror(
                &client,
                registry,
                lockfile,
                packages,
                all_versions,
                concurrency,
            )
            .await?
        }
        MirrorFormat::Yarn { lockfile } => {
            let content = std::fs::read_to_string(&lockfile)
                .map_err(|e| format!("Cannot read {}: {}", lockfile.display(), e))?;
            let targets = npm::parse_yarn_lock(&content);
            if targets.is_empty() {
                println!("No packages found in {}", lockfile.display());
                MirrorResult {
                    total: 0,
                    fetched: 0,
                    failed: 0,
                    bytes: 0,
                }
            } else {
                println!(
                    "Mirroring {} npm packages from yarn.lock via {}...",
                    targets.len(),
                    registry
                );
                npm::mirror_npm_packages(&client, registry, &targets, concurrency).await?
            }
        }
        MirrorFormat::Pip { lockfile } => {
            mirror_lockfile(&client, registry, "pip", &lockfile).await?
        }
        MirrorFormat::Cargo { lockfile } => {
            mirror_lockfile(&client, registry, "cargo", &lockfile).await?
        }
        MirrorFormat::Maven { lockfile } => {
            mirror_lockfile(&client, registry, "maven", &lockfile).await?
        }
    };

    let elapsed = start.elapsed();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        println!("\nMirror complete:");
        println!("  Total:    {}", result.total);
        println!("  Fetched:  {}", result.fetched);
        println!("  Failed:   {}", result.failed);
        println!("  Size:     {:.1} MB", result.bytes as f64 / 1_048_576.0);
        println!("  Time:     {:.1}s", elapsed.as_secs_f64());
    }

    if result.failed > 0 {
        Err(format!("{} packages failed to mirror", result.failed))
    } else {
        Ok(())
    }
}

async fn mirror_lockfile(
    client: &reqwest::Client,
    registry: &str,
    format: &str,
    lockfile: &PathBuf,
) -> Result<MirrorResult, String> {
    let content = std::fs::read_to_string(lockfile)
        .map_err(|e| format!("Cannot read {}: {}", lockfile.display(), e))?;

    let targets = match format {
        "pip" => parse_requirements_txt(&content),
        "cargo" => parse_cargo_lock(&content)?,
        "maven" => parse_maven_deps(&content),
        _ => vec![],
    };

    if targets.is_empty() {
        println!("No packages found in {}", lockfile.display());
        return Ok(MirrorResult {
            total: 0,
            fetched: 0,
            failed: 0,
            bytes: 0,
        });
    }

    let pb = create_progress_bar(targets.len() as u64);
    let base = registry.trim_end_matches('/');
    let mut fetched = 0;
    let mut failed = 0;
    let mut bytes = 0u64;

    for target in &targets {
        let url = match format {
            "pip" => format!("{}/simple/{}/", base, target.name),
            "cargo" => format!(
                "{}/cargo/api/v1/crates/{}/{}/download",
                base, target.name, target.version
            ),
            "maven" => {
                let parts: Vec<&str> = target.name.split(':').collect();
                if parts.len() == 2 {
                    let group_path = parts[0].replace('.', "/");
                    format!(
                        "{}/maven2/{}/{}/{}/{}-{}.jar",
                        base, group_path, parts[1], target.version, parts[1], target.version
                    )
                } else {
                    pb.inc(1);
                    failed += 1;
                    continue;
                }
            }
            _ => continue,
        };

        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.bytes().await {
                    bytes += body.len() as u64;
                }
                fetched += 1;
            }
            _ => failed += 1,
        }

        pb.set_message(format!("{}@{}", target.name, target.version));
        pb.inc(1);
    }

    pb.finish_with_message("done");
    Ok(MirrorResult {
        total: targets.len(),
        fetched,
        failed,
        bytes,
    })
}

fn parse_requirements_txt(content: &str) -> Vec<MirrorTarget> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or(line).trim();
            if let Some((name, version)) = line.split_once("==") {
                Some(MirrorTarget {
                    name: name.trim().to_string(),
                    version: version.trim().to_string(),
                })
            } else {
                let name = line.split(['>', '<', '=', '!', '~', ';']).next()?.trim();
                if name.is_empty() {
                    None
                } else {
                    Some(MirrorTarget {
                        name: name.to_string(),
                        version: "latest".to_string(),
                    })
                }
            }
        })
        .collect()
}

fn parse_cargo_lock(content: &str) -> Result<Vec<MirrorTarget>, String> {
    let lock: toml::Value =
        toml::from_str(content).map_err(|e| format!("Invalid Cargo.lock: {}", e))?;
    let packages = lock
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(packages
        .iter()
        .filter(|p| {
            p.get("source")
                .and_then(|s| s.as_str())
                .map(|s| s.starts_with("registry+"))
                .unwrap_or(false)
        })
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let version = p.get("version")?.as_str()?.to_string();
            Some(MirrorTarget { name, version })
        })
        .collect())
}

fn parse_maven_deps(content: &str) -> Vec<MirrorTarget> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches("[INFO]").trim();
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let name = format!("{}:{}", parts[0], parts[1]);
                let version = parts[3].to_string();
                Some(MirrorTarget { name, version })
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_requirements_txt() {
        let content = "flask==2.3.0\nrequests>=2.28.0\n# comment\nnumpy==1.24.3\n";
        let targets = parse_requirements_txt(content);
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].name, "flask");
        assert_eq!(targets[0].version, "2.3.0");
        assert_eq!(targets[1].name, "requests");
        assert_eq!(targets[1].version, "latest");
    }

    #[test]
    fn test_parse_cargo_lock() {
        let content = "\
[[package]]
name = \"serde\"
version = \"1.0.197\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"

[[package]]
name = \"my-local-crate\"
version = \"0.1.0\"
";
        let targets = parse_cargo_lock(content).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "serde");
    }

    #[test]
    fn test_parse_maven_deps() {
        let content = "[INFO]    org.apache.commons:commons-lang3:jar:3.12.0:compile\n";
        let targets = parse_maven_deps(content);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(targets[0].version, "3.12.0");
    }

    #[test]
    fn test_parse_requirements_txt_empty() {
        let targets = parse_requirements_txt("");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_comments_only() {
        let content = "# This is a comment\n# Another comment\n\n";
        let targets = parse_requirements_txt(content);
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_flags() {
        let content = "-r other-requirements.txt\n-i https://pypi.org/simple\nflask==2.0\n";
        let targets = parse_requirements_txt(content);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "flask");
    }

    #[test]
    fn test_parse_requirements_txt_version_specifiers() {
        let content =
            "pkg1>=1.0\npkg2<2.0\npkg3!=1.5\npkg4~=1.0\npkg5==1.0 ; python_version>='3.8'\n";
        let targets = parse_requirements_txt(content);
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0].name, "pkg1");
        assert_eq!(targets[0].version, "latest");
        assert_eq!(targets[4].name, "pkg5");
        assert_eq!(targets[4].version, "1.0 ; python_version>='3.8'");
    }

    #[test]
    fn test_parse_requirements_txt_inline_comments() {
        let content = "flask==2.0  # web framework\n";
        let targets = parse_requirements_txt(content);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "flask");
        assert_eq!(targets[0].version, "2.0");
    }

    #[test]
    fn test_parse_cargo_lock_empty() {
        let content = "";
        let result = parse_cargo_lock(content);
        let targets = result.unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_cargo_lock_no_packages() {
        let content = "[metadata]\nsome = \"value\"\n";
        let targets = parse_cargo_lock(content).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_cargo_lock_git_source() {
        let content = r#"
[[package]]
name = "my-dep"
version = "0.1.0"
source = "git+https://github.com/user/repo#abc123"
"#;
        let targets = parse_cargo_lock(content).unwrap();
        assert!(targets.is_empty()); // git sources filtered out
    }

    #[test]
    fn test_parse_cargo_lock_multiple() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.36.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-crate"
version = "0.1.0"
"#;
        let targets = parse_cargo_lock(content).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_parse_maven_deps_empty() {
        let targets = parse_maven_deps("");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_maven_deps_short_line() {
        let targets = parse_maven_deps("foo:bar\n");
        assert!(targets.is_empty());
    }

    #[test]
    fn test_parse_maven_deps_multiple() {
        let content = "[INFO]    org.slf4j:slf4j-api:jar:2.0.9:compile\n[INFO]    com.google.guava:guava:jar:33.0.0-jre:compile\n";
        let targets = parse_maven_deps(content);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "org.slf4j:slf4j-api");
        assert_eq!(targets[1].version, "33.0.0-jre");
    }

    #[test]
    fn test_create_progress_bar() {
        let pb = create_progress_bar(100);
        assert_eq!(pb.length(), Some(100));
    }

    #[test]
    fn test_mirror_result_json_serialization() {
        let result = MirrorResult {
            total: 10,
            fetched: 8,
            failed: 2,
            bytes: 1048576,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["total"], 10);
        assert_eq!(parsed["fetched"], 8);
        assert_eq!(parsed["failed"], 2);
        assert_eq!(parsed["bytes"], 1048576);
    }

    #[test]
    fn test_mirror_result_json_zero_values() {
        let result = MirrorResult {
            total: 0,
            fetched: 0,
            failed: 0,
            bytes: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"total\":0"));
    }
}
