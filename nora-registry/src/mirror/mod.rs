// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror` — pre-fetch dependencies through NORA proxy cache.

mod cargo;
mod deb;
mod docker;
mod go;
mod npm;
mod pip;
mod rpm;

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
    /// Mirror Python packages: every file of each pinned requirement's version
    Pip {
        /// Path to requirements.txt, every requirement pinned (`name==version`, as written by
        /// `pip freeze` or `pip-compile`)
        #[arg(long)]
        lockfile: PathBuf,
    },
    /// Mirror Cargo crates: each locked crate's sparse index entry and `.crate`
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
    /// Warm a pull-through RPM repo for offline use (fetch every package through NORA)
    Rpm {
        /// Proxied repo name (an entry in `[rpm.proxies]`)
        #[arg(long)]
        repo: String,
        /// Only these arches (e.g. x86_64,noarch); default: all
        #[arg(long, value_delimiter = ',')]
        arch: Option<Vec<String>>,
    },
    /// Warm a pull-through DEB repo for offline use (fetch every package through NORA)
    Deb {
        /// Proxied repo name (an entry in `[deb.proxies]`)
        #[arg(long)]
        repo: String,
        /// Distribution under dists/ (omit for a flat repo)
        #[arg(long)]
        dist: Option<String>,
        /// Components to mirror (default: all listed in the Release file)
        #[arg(long, value_delimiter = ',')]
        component: Option<Vec<String>>,
        /// Architectures to mirror (default: all listed in the Release file)
        #[arg(long, value_delimiter = ',')]
        arch: Option<Vec<String>>,
    },
    /// Mirror Docker images from upstream registries
    Docker {
        /// Comma-separated image references (e.g., alpine:3.20,postgres:15)
        #[arg(long, conflicts_with = "images_file", value_delimiter = ',')]
        images: Option<Vec<String>>,
        /// Path to file with image references (one per line)
        #[arg(long, conflicts_with = "images")]
        images_file: Option<PathBuf>,
    },
    /// Mirror Go modules: what `go mod download` reads offline, from go.mod and go.sum
    Go {
        /// Path to go.mod: each required module (after `replace`) is fetched in full
        #[arg(long)]
        modfile: PathBuf,
        /// Path to go.sum (default: the go.sum beside go.mod, if any): each version it lists is
        /// fetched in full, or only its go.mod for a `/go.mod` line
        #[arg(long)]
        sumfile: Option<PathBuf>,
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
    client: &reqwest::Client,
) -> Result<(), String> {
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
            if let Some(ref lf) = lockfile {
                let content = std::fs::read_to_string(lf)
                    .map_err(|e| format!("Cannot read {}: {}", lf.display(), e))?;
                if content.contains("# yarn lockfile v1")
                    || content.starts_with("# THIS IS AN AUTOGENERATED FILE")
                {
                    return Err("This looks like a yarn.lock file. Use `nora mirror yarn --lockfile` instead.".to_string());
                }
            }
            npm::run_npm_mirror(
                client,
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
                npm::mirror_npm_packages(client, registry, &targets, concurrency).await?
            }
        }
        MirrorFormat::Pip { lockfile } => {
            mirror_lockfile(client, registry, "pip", &lockfile, concurrency).await?
        }
        MirrorFormat::Cargo { lockfile } => {
            mirror_lockfile(client, registry, "cargo", &lockfile, concurrency).await?
        }
        MirrorFormat::Maven { lockfile } => {
            mirror_lockfile(client, registry, "maven", &lockfile, concurrency).await?
        }
        MirrorFormat::Rpm { repo, arch } => {
            rpm::run_rpm_mirror(client, registry, &repo, arch.as_deref(), concurrency).await?
        }
        MirrorFormat::Deb {
            repo,
            dist,
            component,
            arch,
        } => {
            deb::run_deb_mirror(
                client,
                registry,
                &repo,
                dist.as_deref(),
                component.as_deref(),
                arch.as_deref(),
                concurrency,
            )
            .await?
        }
        MirrorFormat::Docker {
            images,
            images_file,
        } => {
            let image_refs = if let Some(file) = images_file {
                let content = std::fs::read_to_string(&file)
                    .map_err(|e| format!("Cannot read {}: {}", file.display(), e))?;
                docker::parse_images_file(&content)
            } else if let Some(imgs) = images {
                imgs.iter().map(|s| docker::parse_image_ref(s)).collect()
            } else {
                return Err("Either --images or --images-file is required".to_string());
            };
            if image_refs.is_empty() {
                return Err("No images specified".to_string());
            }
            println!(
                "Mirroring {} Docker images via {}...",
                image_refs.len(),
                registry
            );
            docker::run_docker_mirror(client, registry, &image_refs, concurrency).await?
        }
        MirrorFormat::Go { modfile, sumfile } => {
            // The command's error is the message `nora mirror` prints: the typed error ends here.
            match go::run_go_mirror(client, registry, &modfile, sumfile, concurrency).await {
                Ok(result) => result,
                Err(e) => return Err(e.to_string()),
            }
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
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let content = std::fs::read_to_string(lockfile)
        .map_err(|e| format!("Cannot read {}: {}", lockfile.display(), e))?;

    let targets = match format {
        "pip" => pip::parse_requirements_txt(&content),
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

    let base = registry.trim_end_matches('/');
    match format {
        "pip" => return Ok(pip::mirror_requirements(client, base, &targets, concurrency).await),
        "cargo" => return Ok(cargo::mirror_crates(client, base, &targets, concurrency).await),
        _ => {}
    }

    let pb = create_progress_bar(targets.len() as u64);
    let mut fetched = 0;
    let mut failed = 0;
    let mut bytes = 0u64;

    for target in &targets {
        let url = match format {
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
            Ok(r) => {
                eprintln!(
                    "  WARN: {} {} -> HTTP {}",
                    target.name,
                    target.version,
                    r.status()
                );
                failed += 1;
            }
            Err(e) => {
                eprintln!("  WARN: {} {} -> {}", target.name, target.version, e);
                failed += 1;
            }
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

/// GET each repo-relative path through the NORA pull-through repo so the
/// proxy cache is warmed for offline use. A path NORA already has (HEAD 200,
/// local-only check) is skipped and counted as fetched with 0 new bytes.
async fn warm_repo_paths(
    client: &reqwest::Client,
    base: &str,
    format: &str,
    repo: &str,
    paths: &[String],
    concurrency: usize,
) -> MirrorResult {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let pb = create_progress_bar(paths.len() as u64);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let fetched = std::sync::Arc::new(AtomicUsize::new(0));
    let failed = std::sync::Arc::new(AtomicUsize::new(0));
    let bytes = std::sync::Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for path in paths {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let client = client.clone();
        let pb = pb.clone();
        let fetched = fetched.clone();
        let failed = failed.clone();
        let bytes = bytes.clone();
        let url = format!("{base}/{format}/{repo}/{path}");
        let label = path.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let cached = matches!(client.head(&url).send().await, Ok(r) if r.status().is_success());
            if cached {
                fetched.fetch_add(1, Ordering::Relaxed);
            } else {
                match client.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(body) = r.bytes().await {
                            bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
                        }
                        fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    r => {
                        let status = match r {
                            Ok(resp) => format!("HTTP {}", resp.status()),
                            Err(e) => e.to_string(),
                        };
                        eprintln!("  WARN: {label} -> {status}");
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
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

    MirrorResult {
        total: paths.len(),
        fetched: fetched.load(std::sync::atomic::Ordering::Relaxed),
        failed: failed.load(std::sync::atomic::Ordering::Relaxed),
        bytes: bytes.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// Fetch a repo-relative path through the NORA proxy, returning the body.
async fn fetch_repo_file(
    client: &reqwest::Client,
    base: &str,
    format: &str,
    repo: &str,
    path: &str,
) -> Result<Vec<u8>, String> {
    let url = format!("{base}/{format}/{repo}/{path}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("{url}: {e}"))
}

/// Why a GET through NORA brought nothing usable.
#[derive(Debug, thiserror::Error)]
pub(super) enum FetchError {
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    #[error("HTTP {0}")]
    Status(reqwest::StatusCode),
    #[error("unreadable answer: {0}")]
    Json(#[from] serde_json::Error),
}

/// GET `url` (with `accept`, if given) and keep the response only when it is a success.
pub(super) async fn fetch_ok(
    client: &reqwest::Client,
    url: &str,
    accept: Option<&str>,
) -> Result<reqwest::Response, FetchError> {
    let mut req = client.get(url);
    if let Some(accept) = accept {
        req = req.header(reqwest::header::ACCEPT, accept);
    }
    let resp = req.send().await?;
    if resp.status().is_success() {
        Ok(resp)
    } else {
        Err(FetchError::Status(resp.status()))
    }
}

/// Read a response body to its end, counting its bytes without holding them: a wheel can be
/// gigabytes, and NORA stores what it serves.
pub(super) async fn drain(mut resp: reqwest::Response) -> Result<u64, FetchError> {
    let mut n = 0u64;
    while let Some(chunk) = resp.chunk().await? {
        n += chunk.len() as u64;
    }
    Ok(n)
}

/// Decompress an index file by its extension (`.gz`/`.xz`/plain) to text.
/// Repo indexes are operator-chosen upstream data read on the client side —
/// no decompression cap needed (unlike the server's control.tar bomb cap).
fn decompress_index(path: &str, raw: Vec<u8>) -> Result<String, String> {
    use std::io::Read;
    if path.ends_with(".gz") {
        let mut s = String::new();
        flate2::read::GzDecoder::new(&raw[..])
            .read_to_string(&mut s)
            .map_err(|e| format!("{path}: {e}"))?;
        Ok(s)
    } else if path.ends_with(".xz") {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut &raw[..], &mut out).map_err(|e| format!("{path}: {e:?}"))?;
        String::from_utf8(out).map_err(|e| format!("{path}: {e}"))
    } else if path.ends_with(".zst") {
        let mut s = String::new();
        ruzstd::decoding::StreamingDecoder::new(&raw[..])
            .map_err(|e| format!("{path}: {e}"))?
            .read_to_string(&mut s)
            .map_err(|e| format!("{path}: {e}"))?;
        Ok(s)
    } else {
        String::from_utf8(raw).map_err(|e| format!("{path}: {e}"))
    }
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

/// #1183: what `nora mirror pip` and `nora mirror cargo` leave in the store must serve an offline
/// client. Each test seeds a NORA (in memory, served over a socket as the CLI reaches it) through
/// `run_mirror` from a fake upstream, takes the upstream away, and then asks NORA what the
/// client asks: pip the project page and the files on it, cargo the sparse index entry and the
/// `.crate`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod offline_seed_tests {
    use super::pip::parse_requirements_txt;
    use super::{run_mirror, MirrorFormat};
    use crate::test_helpers::{
        body_bytes, create_test_context_in_memory, create_test_context_with_storage_and_config,
        send_with_headers, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// NORA over a socket, as the mirror (an HTTP client of a running NORA) reaches it. The
    /// server stops when this drops.
    struct Served {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(ctx: &TestContext) -> Served {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = ctx.app.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Served {
            url: format!("http://{addr}"),
            task,
        }
    }

    /// NORA restarted on the same store without an upstream: what an offline client gets is only
    /// what the store holds. (Dropping a wiremock server does not close its port — servers are
    /// pooled — so the offline NORA is a second one. With an unreachable upstream instead, NORA
    /// serves the same stored copies, but only after asking the upstream once more a second later,
    /// ~2 s a request; the black-box scenario covers that path with real clients.)
    fn offline(ctx: &TestContext) -> TestContext {
        create_test_context_with_storage_and_config(ctx.state.storage.clone(), |cfg| {
            cfg.pypi.proxy = None;
            cfg.pypi.proxies.clear();
            cfg.cargo.proxy = None;
        })
    }

    /// Ask `uri` until it answers 200, up to a deadline: what the mirror fetched is written by
    /// NORA's cache task after NORA answers (on a store in memory, at its first yield).
    async fn get_ok(ctx: &TestContext, uri: &str, accept: &str) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let (status, body) = get(ctx, uri, accept).await;
            if status == StatusCode::OK {
                return body;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{uri} offline: {status}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn lockfile(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    async fn get(ctx: &TestContext, uri: &str, accept: &str) -> (StatusCode, Vec<u8>) {
        let resp =
            send_with_headers(&ctx.app, Method::GET, uri, vec![("accept", accept)], "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    /// The files NORA lists on a project page (PEP 691 JSON), sorted.
    async fn listed_files(ctx: &TestContext, project: &str) -> Vec<String> {
        let (status, body) = get(
            ctx,
            &format!("/simple/{project}/"),
            "application/vnd.pypi.simple.v1+json",
        )
        .await;
        if status != StatusCode::OK {
            return Vec::new();
        }
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut files: Vec<String> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["filename"].as_str().unwrap().to_string())
            .collect();
        files.sort();
        files
    }

    /// A fake PyPI: the project page of `project` lists `files` (name, bytes) with their sha256,
    /// each served from the same server.
    async fn fake_pypi(project: &str, files: &[(&str, &[u8])]) -> MockServer {
        fake_pypi_with(project, files, &[]).await
    }

    /// [`fake_pypi`] where the files named in `broken` are listed but answer 500.
    async fn fake_pypi_with(project: &str, files: &[(&str, &[u8])], broken: &[&str]) -> MockServer {
        let upstream = MockServer::start().await;
        let mut html = String::from("<html><body>\n");
        for (name, bytes) in files {
            let sha = hex::encode(sha2::Sha256::digest(bytes));
            html.push_str(&format!(
                "<a href=\"{}/files/{name}#sha256={sha}\">{name}</a><br>\n",
                upstream.uri()
            ));
            let answer = if broken.contains(name) {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_bytes(bytes.to_vec())
            };
            Mock::given(method("GET"))
                .and(path(format!("/files/{name}")))
                .respond_with(answer)
                .mount(&upstream)
                .await;
        }
        html.push_str("</body></html>");
        Mock::given(method("GET"))
            .and(path(format!("/{project}/")))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&upstream)
            .await;
        upstream
    }

    const DEMO_FILES: [(&str, &[u8]); 4] = [
        ("demo-1.0-py3-none-any.whl", b"wheel 1.0"),
        ("demo-1.0.tar.gz", b"sdist 1.0"),
        ("demo-2.0-py3-none-any.whl", b"wheel 2.0"),
        ("demo-2.0.tar.gz", b"sdist 2.0"),
    ];

    /// The issue as reported: after `nora mirror pip`, an offline pip finds the pinned version's
    /// files on the project page and downloads them from NORA. Only the pinned version is stored.
    #[tokio::test]
    async fn pip_mirror_leaves_the_files_an_offline_client_installs() {
        let upstream = fake_pypi("demo", &DEMO_FILES).await;
        let uri = upstream.uri();
        let ctx = create_test_context_in_memory(move |cfg| cfg.pypi.proxy = Some(uri));
        let nora = serve(&ctx).await;
        let dir = tempfile::tempdir().unwrap();
        let lockfile = lockfile(&dir, "requirements.txt", "demo==1.0\n");

        let mirrored = run_mirror(
            MirrorFormat::Pip { lockfile },
            &nora.url,
            4,
            false,
            &reqwest::Client::new(),
        )
        .await;
        assert!(mirrored.is_ok(), "mirror failed: {mirrored:?}");

        let offline = offline(&ctx);
        for (name, bytes) in &DEMO_FILES[..2] {
            let body = get_ok(&offline, &format!("/simple/demo/{name}"), "*/*").await;
            assert_eq!(&body, bytes, "{name} offline");
        }
        assert_eq!(
            listed_files(&offline, "demo").await,
            vec!["demo-1.0-py3-none-any.whl", "demo-1.0.tar.gz"],
            "offline, the project page lists the pinned version's files and nothing else"
        );
        drop(upstream);
    }

    /// A requirement names the project in any spelling and the version in any PEP 440 form of it:
    /// `Demo.Pkg==1.0.0` is the files of `demo-pkg` 1.0.
    #[tokio::test]
    async fn pip_mirror_matches_the_project_and_version_as_pep_503_and_440_do() {
        let files: [(&str, &[u8]); 3] = [
            ("demo_pkg-1.0-py3-none-any.whl", b"wheel"),
            ("demo_pkg-1.0.tar.gz", b"sdist"),
            ("demo_pkg-1.0.1.tar.gz", b"other"),
        ];
        let upstream = fake_pypi("demo-pkg", &files).await;
        let uri = upstream.uri();
        let ctx = create_test_context_in_memory(move |cfg| cfg.pypi.proxy = Some(uri));
        let nora = serve(&ctx).await;
        let dir = tempfile::tempdir().unwrap();
        let lockfile = lockfile(&dir, "requirements.txt", "Demo.Pkg==1.0.0\n");

        let mirrored = run_mirror(
            MirrorFormat::Pip { lockfile },
            &nora.url,
            4,
            false,
            &reqwest::Client::new(),
        )
        .await;
        assert!(mirrored.is_ok(), "mirror failed: {mirrored:?}");
        let offline = offline(&ctx);
        for (name, _) in &files[..2] {
            get_ok(&offline, &format!("/simple/demo-pkg/{name}"), "*/*").await;
        }
        drop(upstream);
        assert_eq!(
            listed_files(&offline, "demo-pkg").await,
            vec!["demo_pkg-1.0-py3-none-any.whl", "demo_pkg-1.0.tar.gz"]
        );
    }

    /// A requirement not pinned to one version names no files: the mirror says so and fails
    /// rather than reporting a store that serves nothing offline as mirrored.
    #[tokio::test]
    async fn pip_mirror_fails_on_a_requirement_it_cannot_resolve_to_files() {
        for requirement in ["demo>=1.0\n", "demo\n", "demo==1.*\n", "demo==3.0\n"] {
            let upstream = fake_pypi("demo", &DEMO_FILES).await;
            let uri = upstream.uri();
            let ctx = create_test_context_in_memory(move |cfg| cfg.pypi.proxy = Some(uri));
            let nora = serve(&ctx).await;
            let dir = tempfile::tempdir().unwrap();
            let lockfile = lockfile(&dir, "requirements.txt", requirement);

            let mirrored = run_mirror(
                MirrorFormat::Pip { lockfile },
                &nora.url,
                4,
                false,
                &reqwest::Client::new(),
            )
            .await;
            assert!(mirrored.is_err(), "{requirement:?} reported as mirrored");
            drop(upstream);
            assert!(
                listed_files(&offline(&ctx), "demo").await.is_empty(),
                "{requirement:?} stored files"
            );
        }
    }

    /// A file of the pinned version NORA cannot fetch leaves the requirement unmirrored: which
    /// file an offline client will need is not known here, so each one counts.
    #[tokio::test]
    async fn pip_mirror_fails_when_a_file_of_the_version_is_not_fetched() {
        let upstream = fake_pypi_with("demo", &DEMO_FILES, &["demo-1.0.tar.gz"]).await;
        let uri = upstream.uri();
        let ctx = create_test_context_in_memory(move |cfg| cfg.pypi.proxy = Some(uri));
        let nora = serve(&ctx).await;
        let dir = tempfile::tempdir().unwrap();
        let lockfile = lockfile(&dir, "requirements.txt", "demo==1.0\n");

        let mirrored = run_mirror(
            MirrorFormat::Pip { lockfile },
            &nora.url,
            4,
            false,
            &reqwest::Client::new(),
        )
        .await;
        assert_eq!(mirrored, Err("1 packages failed to mirror".to_string()));
    }

    /// `pip-compile --generate-hashes` and `pip freeze` output: continuation lines, `--hash`
    /// options, extras and environment markers are not part of a name or a version.
    #[test]
    fn requirements_parse_hashes_extras_and_markers_out() {
        let content = "\
# pip-compile output
flask==2.3.0 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
    # via -r requirements.in
requests[socks]==2.32.3 ; python_version >= \"3.8\"
pkg5==1.0 ; python_version>='3.8'
-r other.txt
--index-url https://example.invalid/simple
";
        let got: Vec<(String, String)> = parse_requirements_txt(content)
            .into_iter()
            .map(|t| (t.name, t.version))
            .collect();
        let want: Vec<(String, String)> =
            [("flask", "2.3.0"), ("requests", "2.32.3"), ("pkg5", "1.0")]
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
        assert_eq!(got, want);
    }

    /// A fake sparse registry (NORA's custom-upstream layout `{proxy}/index/{prefix}/{name}`,
    /// downloads at `{proxy}/api/v1/crates/{name}/{version}/download`).
    async fn fake_crates(crates: &[(&str, &str, &str)]) -> MockServer {
        let upstream = MockServer::start().await;
        let mut index: std::collections::BTreeMap<(String, String), String> = Default::default();
        for (prefix, name, version) in crates {
            let body = format!("crate {name} {version}");
            let cksum = hex::encode(sha2::Sha256::digest(body.as_bytes()));
            index
                .entry((prefix.to_string(), name.to_lowercase()))
                .or_default()
                .push_str(&format!(
                    "{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{cksum}\",\"features\":{{}},\"yanked\":false}}\n"
                ));
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/crates/{name}/{version}/download")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&upstream)
                .await;
        }
        for ((prefix, name), lines) in index {
            Mock::given(method("GET"))
                .and(path(format!("/index/{prefix}/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(lines))
                .mount(&upstream)
                .await;
        }
        upstream
    }

    /// The issue as reported for cargo: after `nora mirror cargo`, an offline cargo reads every
    /// locked crate's sparse index entry from NORA (names of 1, 2, 3 and 4+ characters, one with
    /// capitals, one locked at two versions) and downloads every `.crate`.
    #[tokio::test]
    async fn cargo_mirror_leaves_the_index_entries_an_offline_client_reads() {
        // (index prefix, name as locked, version)
        let crates = [
            ("1", "a", "0.1.0"),
            ("2", "cc", "1.0.83"),
            ("3/l", "log", "0.4.22"),
            ("se/rd", "serde", "1.0.197"),
            ("in/fl", "Inflector", "0.11.4"),
            ("it/oa", "itoa", "0.4.8"),
            ("it/oa", "itoa", "1.0.11"),
        ];
        let upstream = fake_crates(&crates).await;
        let uri = upstream.uri();
        let ctx = create_test_context_in_memory(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        });
        let nora = serve(&ctx).await;
        let mut lock = String::from("version = 3\n");
        for (_, name, version) in &crates {
            lock.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ));
        }
        lock.push_str("\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n");
        let dir = tempfile::tempdir().unwrap();
        let lockfile = lockfile(&dir, "Cargo.lock", &lock);

        let mirrored = run_mirror(
            MirrorFormat::Cargo { lockfile },
            &nora.url,
            4,
            false,
            &reqwest::Client::new(),
        )
        .await;
        assert!(mirrored.is_ok(), "mirror failed: {mirrored:?}");

        let offline = offline(&ctx);
        for (prefix, name, version) in &crates {
            let index_uri = format!("/cargo/index/{prefix}/{}", name.to_lowercase());
            let body = String::from_utf8(get_ok(&offline, &index_uri, "*/*").await).unwrap();
            assert!(
                body.contains(&format!("\"vers\":\"{version}\"")),
                "{index_uri} offline lists {version}: {body}"
            );
            let body = get_ok(
                &offline,
                &format!("/cargo/api/v1/crates/{name}/{version}/download"),
                "*/*",
            )
            .await;
            assert_eq!(body, format!("crate {name} {version}").into_bytes());
        }
        drop(upstream);
    }

    /// A locked crate whose index entry NORA cannot serve, or whose entry does not list the
    /// locked version, is not usable offline: each is a failure, even when its `.crate` downloads.
    #[tokio::test]
    async fn cargo_mirror_fails_on_a_crate_whose_index_entry_does_not_serve_it() {
        let upstream = fake_crates(&[("ok/ay", "okay", "1.0.0")]).await;
        // `lost`: no index entry upstream; `listed`: an entry without 2.0.0.
        Mock::given(method("GET"))
            .and(path("/index/li/st/listed"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "{\"name\":\"listed\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"00\",\"features\":{},\"yanked\":false}\n",
            ))
            .mount(&upstream)
            .await;
        for (name, version) in [("lost", "1.0.0"), ("listed", "2.0.0")] {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/crates/{name}/{version}/download")))
                .respond_with(ResponseTemplate::new(200).set_body_string("crate"))
                .mount(&upstream)
                .await;
        }
        let uri = upstream.uri();
        let ctx = create_test_context_in_memory(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        });
        let nora = serve(&ctx).await;
        let mut lock = String::from("version = 3\n");
        for (name, version) in [("okay", "1.0.0"), ("lost", "1.0.0"), ("listed", "2.0.0")] {
            lock.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ));
        }
        let dir = tempfile::tempdir().unwrap();
        let lockfile = lockfile(&dir, "Cargo.lock", &lock);

        let mirrored = run_mirror(
            MirrorFormat::Cargo { lockfile },
            &nora.url,
            4,
            false,
            &reqwest::Client::new(),
        )
        .await;
        assert_eq!(mirrored, Err("2 packages failed to mirror".to_string()));
    }
}
