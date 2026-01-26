use super::components::{format_size, format_timestamp, html_escape};
use super::templates::encode_uri_component;
use crate::activity_log::ActivityEntry;
use crate::AppState;
use crate::Storage;
use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Serialize)]
pub struct RegistryStats {
    pub docker: usize,
    pub maven: usize,
    pub npm: usize,
    pub cargo: usize,
    pub pypi: usize,
}

#[derive(Serialize, Clone)]
pub struct RepoInfo {
    pub name: String,
    pub versions: usize,
    pub size: u64,
    pub updated: String,
}

#[derive(Serialize)]
pub struct TagInfo {
    pub name: String,
    pub size: u64,
    pub created: String,
}

#[derive(Serialize)]
pub struct DockerDetail {
    pub tags: Vec<TagInfo>,
}

#[derive(Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub size: u64,
    pub published: String,
}

#[derive(Serialize)]
pub struct PackageDetail {
    pub versions: Vec<VersionInfo>,
}

#[derive(Serialize)]
pub struct MavenArtifact {
    pub filename: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct MavenDetail {
    pub artifacts: Vec<MavenArtifact>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

#[derive(Serialize)]
pub struct DashboardResponse {
    pub global_stats: GlobalStats,
    pub registry_stats: Vec<RegistryCardStats>,
    pub mount_points: Vec<MountPoint>,
    pub activity: Vec<ActivityEntry>,
    pub uptime_seconds: u64,
}

#[derive(Serialize)]
pub struct GlobalStats {
    pub downloads: u64,
    pub uploads: u64,
    pub artifacts: u64,
    pub cache_hit_percent: f64,
    pub storage_bytes: u64,
}

#[derive(Serialize)]
pub struct RegistryCardStats {
    pub name: String,
    pub artifact_count: usize,
    pub downloads: u64,
    pub uploads: u64,
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct MountPoint {
    pub registry: String,
    pub mount_path: String,
    pub proxy_upstream: Option<String>,
}

// ============ API Handlers ============

pub async fn api_stats(State(state): State<Arc<AppState>>) -> Json<RegistryStats> {
    let stats = get_registry_stats(&state.storage).await;
    Json(stats)
}

pub async fn api_dashboard(State(state): State<Arc<AppState>>) -> Json<DashboardResponse> {
    let registry_stats = get_registry_stats(&state.storage).await;

    // Calculate total storage size
    let all_keys = state.storage.list("").await;
    let mut total_storage: u64 = 0;
    let mut docker_size: u64 = 0;
    let mut maven_size: u64 = 0;
    let mut npm_size: u64 = 0;
    let mut cargo_size: u64 = 0;
    let mut pypi_size: u64 = 0;

    for key in &all_keys {
        if let Some(meta) = state.storage.stat(key).await {
            total_storage += meta.size;
            if key.starts_with("docker/") {
                docker_size += meta.size;
            } else if key.starts_with("maven/") {
                maven_size += meta.size;
            } else if key.starts_with("npm/") {
                npm_size += meta.size;
            } else if key.starts_with("cargo/") {
                cargo_size += meta.size;
            } else if key.starts_with("pypi/") {
                pypi_size += meta.size;
            }
        }
    }

    let total_artifacts = registry_stats.docker
        + registry_stats.maven
        + registry_stats.npm
        + registry_stats.cargo
        + registry_stats.pypi;

    let global_stats = GlobalStats {
        downloads: state.metrics.downloads.load(Ordering::Relaxed),
        uploads: state.metrics.uploads.load(Ordering::Relaxed),
        artifacts: total_artifacts as u64,
        cache_hit_percent: state.metrics.cache_hit_rate(),
        storage_bytes: total_storage,
    };

    let registry_card_stats = vec![
        RegistryCardStats {
            name: "docker".to_string(),
            artifact_count: registry_stats.docker,
            downloads: state.metrics.get_registry_downloads("docker"),
            uploads: state.metrics.get_registry_uploads("docker"),
            size_bytes: docker_size,
        },
        RegistryCardStats {
            name: "maven".to_string(),
            artifact_count: registry_stats.maven,
            downloads: state.metrics.get_registry_downloads("maven"),
            uploads: state.metrics.get_registry_uploads("maven"),
            size_bytes: maven_size,
        },
        RegistryCardStats {
            name: "npm".to_string(),
            artifact_count: registry_stats.npm,
            downloads: state.metrics.get_registry_downloads("npm"),
            uploads: 0,
            size_bytes: npm_size,
        },
        RegistryCardStats {
            name: "cargo".to_string(),
            artifact_count: registry_stats.cargo,
            downloads: state.metrics.get_registry_downloads("cargo"),
            uploads: 0,
            size_bytes: cargo_size,
        },
        RegistryCardStats {
            name: "pypi".to_string(),
            artifact_count: registry_stats.pypi,
            downloads: state.metrics.get_registry_downloads("pypi"),
            uploads: 0,
            size_bytes: pypi_size,
        },
    ];

    let mount_points = vec![
        MountPoint {
            registry: "Docker".to_string(),
            mount_path: "/v2/".to_string(),
            proxy_upstream: None,
        },
        MountPoint {
            registry: "Maven".to_string(),
            mount_path: "/maven2/".to_string(),
            proxy_upstream: state.config.maven.proxies.first().cloned(),
        },
        MountPoint {
            registry: "npm".to_string(),
            mount_path: "/npm/".to_string(),
            proxy_upstream: state.config.npm.proxy.clone(),
        },
        MountPoint {
            registry: "Cargo".to_string(),
            mount_path: "/cargo/".to_string(),
            proxy_upstream: None,
        },
        MountPoint {
            registry: "PyPI".to_string(),
            mount_path: "/simple/".to_string(),
            proxy_upstream: None,
        },
    ];

    let activity = state.activity.recent(20);
    let uptime_seconds = state.start_time.elapsed().as_secs();

    Json(DashboardResponse {
        global_stats,
        registry_stats: registry_card_stats,
        mount_points,
        activity,
        uptime_seconds,
    })
}

pub async fn api_list(
    State(state): State<Arc<AppState>>,
    Path(registry_type): Path<String>,
) -> Json<Vec<RepoInfo>> {
    let repos = match registry_type.as_str() {
        "docker" => get_docker_repos(&state.storage).await,
        "maven" => get_maven_repos(&state.storage).await,
        "npm" => get_npm_packages(&state.storage).await,
        "cargo" => get_cargo_crates(&state.storage).await,
        "pypi" => get_pypi_packages(&state.storage).await,
        _ => vec![],
    };
    Json(repos)
}

pub async fn api_detail(
    State(state): State<Arc<AppState>>,
    Path((registry_type, name)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match registry_type.as_str() {
        "docker" => {
            let detail = get_docker_detail(&state.storage, &name).await;
            Json(serde_json::to_value(detail).unwrap_or_default())
        }
        "npm" => {
            let detail = get_npm_detail(&state.storage, &name).await;
            Json(serde_json::to_value(detail).unwrap_or_default())
        }
        "cargo" => {
            let detail = get_cargo_detail(&state.storage, &name).await;
            Json(serde_json::to_value(detail).unwrap_or_default())
        }
        _ => Json(serde_json::json!({})),
    }
}

pub async fn api_search(
    State(state): State<Arc<AppState>>,
    Path(registry_type): Path<String>,
    Query(params): Query<SearchQuery>,
) -> axum::response::Html<String> {
    let query = params.q.unwrap_or_default().to_lowercase();

    let repos = match registry_type.as_str() {
        "docker" => get_docker_repos(&state.storage).await,
        "maven" => get_maven_repos(&state.storage).await,
        "npm" => get_npm_packages(&state.storage).await,
        "cargo" => get_cargo_crates(&state.storage).await,
        "pypi" => get_pypi_packages(&state.storage).await,
        _ => vec![],
    };

    let filtered: Vec<_> = if query.is_empty() {
        repos
    } else {
        repos
            .into_iter()
            .filter(|r| r.name.to_lowercase().contains(&query))
            .collect()
    };

    // Return HTML fragment for HTMX
    let html = if filtered.is_empty() {
        r#"<tr><td colspan="4" class="px-6 py-12 text-center text-slate-500">
            <div class="text-4xl mb-2">🔍</div>
            <div>No matching repositories found</div>
        </td></tr>"#
            .to_string()
    } else {
        filtered
            .iter()
            .map(|repo| {
                let detail_url =
                    format!("/ui/{}/{}", registry_type, encode_uri_component(&repo.name));
                format!(
                    r#"
                <tr class="hover:bg-slate-50 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-6 py-4">
                        <a href="{}" class="text-blue-600 hover:text-blue-800 font-medium">{}</a>
                    </td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-600">{}</td>
                    <td class="px-6 py-4 text-slate-500 text-sm">{}</td>
                </tr>
            "#,
                    detail_url,
                    detail_url,
                    html_escape(&repo.name),
                    repo.versions,
                    format_size(repo.size),
                    &repo.updated
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    axum::response::Html(html)
}

// ============ Data Fetching Functions ============

pub async fn get_registry_stats(storage: &Storage) -> RegistryStats {
    let all_keys = storage.list("").await;

    let docker = all_keys
        .iter()
        .filter(|k| k.starts_with("docker/") && k.contains("/manifests/"))
        .filter_map(|k| k.split('/').nth(1))
        .collect::<HashSet<_>>()
        .len();

    let maven = all_keys
        .iter()
        .filter(|k| k.starts_with("maven/"))
        .filter_map(|k| {
            // Extract groupId/artifactId from maven path
            let parts: Vec<_> = k.strip_prefix("maven/")?.split('/').collect();
            if parts.len() >= 2 {
                Some(parts[..parts.len() - 1].join("/"))
            } else {
                None
            }
        })
        .collect::<HashSet<_>>()
        .len();

    let npm = all_keys
        .iter()
        .filter(|k| k.starts_with("npm/") && k.ends_with("/metadata.json"))
        .count();

    let cargo = all_keys
        .iter()
        .filter(|k| k.starts_with("cargo/") && k.ends_with("/metadata.json"))
        .count();

    let pypi = all_keys
        .iter()
        .filter(|k| k.starts_with("pypi/"))
        .filter_map(|k| k.strip_prefix("pypi/")?.split('/').next())
        .collect::<HashSet<_>>()
        .len();

    RegistryStats {
        docker,
        maven,
        npm,
        cargo,
        pypi,
    }
}

pub async fn get_docker_repos(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("docker/").await;

    let mut repos: HashMap<String, (RepoInfo, u64)> = HashMap::new(); // (info, latest_modified)

    for key in &keys {
        if let Some(rest) = key.strip_prefix("docker/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let entry = repos.entry(name.clone()).or_insert_with(|| {
                    (
                        RepoInfo {
                            name,
                            versions: 0,
                            size: 0,
                            updated: "N/A".to_string(),
                        },
                        0,
                    )
                });

                if parts[1] == "manifests" {
                    entry.0.versions += 1;
                    if let Some(meta) = storage.stat(key).await {
                        entry.0.size += meta.size;
                        if meta.modified > entry.1 {
                            entry.1 = meta.modified;
                            entry.0.updated = format_timestamp(meta.modified);
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<_> = repos.into_values().map(|(r, _)| r).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

pub async fn get_docker_detail(storage: &Storage, name: &str) -> DockerDetail {
    let prefix = format!("docker/{}/manifests/", name);
    let keys = storage.list(&prefix).await;

    let mut tags = Vec::new();
    for key in &keys {
        if let Some(tag_name) = key
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".json"))
        {
            let (size, created) = if let Some(meta) = storage.stat(key).await {
                (meta.size, format_timestamp(meta.modified))
            } else {
                (0, "N/A".to_string())
            };
            tags.push(TagInfo {
                name: tag_name.to_string(),
                size,
                created,
            });
        }
    }

    DockerDetail { tags }
}

pub async fn get_maven_repos(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("maven/").await;

    let mut repos: HashMap<String, (RepoInfo, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("maven/") {
            let parts: Vec<_> = rest.split('/').collect();
            if parts.len() >= 2 {
                let artifact_path = parts[..parts.len() - 1].join("/");
                let entry = repos.entry(artifact_path.clone()).or_insert_with(|| {
                    (
                        RepoInfo {
                            name: artifact_path,
                            versions: 0,
                            size: 0,
                            updated: "N/A".to_string(),
                        },
                        0,
                    )
                });
                entry.0.versions += 1;
                if let Some(meta) = storage.stat(key).await {
                    entry.0.size += meta.size;
                    if meta.modified > entry.1 {
                        entry.1 = meta.modified;
                        entry.0.updated = format_timestamp(meta.modified);
                    }
                }
            }
        }
    }

    let mut result: Vec<_> = repos.into_values().map(|(r, _)| r).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

pub async fn get_maven_detail(storage: &Storage, path: &str) -> MavenDetail {
    let prefix = format!("maven/{}/", path);
    let keys = storage.list(&prefix).await;

    let mut artifacts = Vec::new();
    for key in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if filename.contains('/') {
                continue;
            }
            let size = storage.stat(key).await.map(|m| m.size).unwrap_or(0);
            artifacts.push(MavenArtifact {
                filename: filename.to_string(),
                size,
            });
        }
    }

    MavenDetail { artifacts }
}

pub async fn get_npm_packages(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("npm/").await;

    let mut packages: HashMap<String, (RepoInfo, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("npm/") {
            let parts: Vec<_> = rest.split('/').collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let entry = packages.entry(name.clone()).or_insert_with(|| {
                    (
                        RepoInfo {
                            name,
                            versions: 0,
                            size: 0,
                            updated: "N/A".to_string(),
                        },
                        0,
                    )
                });

                if parts.len() >= 3 && parts[1] == "tarballs" {
                    entry.0.versions += 1;
                    if let Some(meta) = storage.stat(key).await {
                        entry.0.size += meta.size;
                        if meta.modified > entry.1 {
                            entry.1 = meta.modified;
                            entry.0.updated = format_timestamp(meta.modified);
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<_> = packages.into_values().map(|(r, _)| r).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

pub async fn get_npm_detail(storage: &Storage, name: &str) -> PackageDetail {
    let prefix = format!("npm/{}/tarballs/", name);
    let keys = storage.list(&prefix).await;

    let mut versions = Vec::new();
    for key in &keys {
        if let Some(tarball) = key.strip_prefix(&prefix) {
            if let Some(version) = tarball
                .strip_prefix(&format!("{}-", name))
                .and_then(|s| s.strip_suffix(".tgz"))
            {
                let (size, published) = if let Some(meta) = storage.stat(key).await {
                    (meta.size, format_timestamp(meta.modified))
                } else {
                    (0, "N/A".to_string())
                };
                versions.push(VersionInfo {
                    version: version.to_string(),
                    size,
                    published,
                });
            }
        }
    }

    PackageDetail { versions }
}

pub async fn get_cargo_crates(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("cargo/").await;

    let mut crates: HashMap<String, (RepoInfo, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("cargo/") {
            let parts: Vec<_> = rest.split('/').collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let entry = crates.entry(name.clone()).or_insert_with(|| {
                    (
                        RepoInfo {
                            name,
                            versions: 0,
                            size: 0,
                            updated: "N/A".to_string(),
                        },
                        0,
                    )
                });

                if parts.len() >= 3 && key.ends_with(".crate") {
                    entry.0.versions += 1;
                    if let Some(meta) = storage.stat(key).await {
                        entry.0.size += meta.size;
                        if meta.modified > entry.1 {
                            entry.1 = meta.modified;
                            entry.0.updated = format_timestamp(meta.modified);
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<_> = crates.into_values().map(|(r, _)| r).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

pub async fn get_cargo_detail(storage: &Storage, name: &str) -> PackageDetail {
    let prefix = format!("cargo/{}/", name);
    let keys = storage.list(&prefix).await;

    let mut versions = Vec::new();
    for key in keys.iter().filter(|k| k.ends_with(".crate")) {
        if let Some(rest) = key.strip_prefix(&prefix) {
            let parts: Vec<_> = rest.split('/').collect();
            if !parts.is_empty() {
                let (size, published) = if let Some(meta) = storage.stat(key).await {
                    (meta.size, format_timestamp(meta.modified))
                } else {
                    (0, "N/A".to_string())
                };
                versions.push(VersionInfo {
                    version: parts[0].to_string(),
                    size,
                    published,
                });
            }
        }
    }

    PackageDetail { versions }
}

pub async fn get_pypi_packages(storage: &Storage) -> Vec<RepoInfo> {
    let keys = storage.list("pypi/").await;

    let mut packages: HashMap<String, (RepoInfo, u64)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix("pypi/") {
            let parts: Vec<_> = rest.split('/').collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let entry = packages.entry(name.clone()).or_insert_with(|| {
                    (
                        RepoInfo {
                            name,
                            versions: 0,
                            size: 0,
                            updated: "N/A".to_string(),
                        },
                        0,
                    )
                });

                if parts.len() >= 2 {
                    entry.0.versions += 1;
                    if let Some(meta) = storage.stat(key).await {
                        entry.0.size += meta.size;
                        if meta.modified > entry.1 {
                            entry.1 = meta.modified;
                            entry.0.updated = format_timestamp(meta.modified);
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<_> = packages.into_values().map(|(r, _)| r).collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

pub async fn get_pypi_detail(storage: &Storage, name: &str) -> PackageDetail {
    let prefix = format!("pypi/{}/", name);
    let keys = storage.list(&prefix).await;

    let mut versions = Vec::new();
    for key in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if let Some(version) = extract_pypi_version(name, filename) {
                let (size, published) = if let Some(meta) = storage.stat(key).await {
                    (meta.size, format_timestamp(meta.modified))
                } else {
                    (0, "N/A".to_string())
                };
                versions.push(VersionInfo {
                    version,
                    size,
                    published,
                });
            }
        }
    }

    PackageDetail { versions }
}

fn extract_pypi_version(name: &str, filename: &str) -> Option<String> {
    // Handle both .tar.gz and .whl files
    let clean_name = name.replace('-', "_");

    if filename.ends_with(".tar.gz") {
        // package-1.0.0.tar.gz
        let base = filename.strip_suffix(".tar.gz")?;
        let version = base
            .strip_prefix(&format!("{}-", name))
            .or_else(|| base.strip_prefix(&format!("{}-", clean_name)))?;
        Some(version.to_string())
    } else if filename.ends_with(".whl") {
        // package-1.0.0-py3-none-any.whl
        let parts: Vec<_> = filename.split('-').collect();
        if parts.len() >= 2 {
            Some(parts[1].to_string())
        } else {
            None
        }
    } else {
        None
    }
}
