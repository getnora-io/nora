// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::components::{format_size, format_timestamp, html_escape};
use super::templates::encode_uri_component;
use crate::activity_log::ActivityEntry;
use crate::registry_type::RegistryType;
use crate::repo_index::RepoInfo;
use crate::AppState;
use crate::Storage;
use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Serialize)]
pub struct RegistryStats {
    pub docker: usize,
    pub maven: usize,
    pub npm: usize,
    pub cargo: usize,
    pub pypi: usize,
    pub go: usize,
    pub raw: usize,
    pub nuget: usize,
    pub gems: usize,
    pub terraform: usize,
    pub ansible: usize,
    #[serde(rename = "pub")]
    pub pub_dart: usize,
    pub conan: usize,
}

#[derive(Serialize)]
pub struct TagInfo {
    pub name: String,
    pub size: u64,
    pub created: String,
    pub downloads: u64,
    pub last_pulled: Option<String>,
    pub os: String,
    pub arch: String,
    pub layers_count: usize,
    pub pull_command: String,
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
    pub cached: bool,
}

#[derive(Serialize)]
pub struct PackageDetail {
    pub versions: Vec<VersionInfo>,
    pub prerelease_count: usize,
    /// Total stable versions available (may be > versions.len() if truncated)
    pub total_stable: usize,
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

#[derive(Serialize, ToSchema)]
pub struct DashboardResponse {
    pub global_stats: GlobalStats,
    pub registry_stats: Vec<RegistryCardStats>,
    pub mount_points: Vec<MountPoint>,
    pub activity: Vec<ActivityEntry>,
    pub uptime_seconds: u64,
    pub startup_duration_ms: u64,
}

#[derive(Serialize, ToSchema)]
pub struct GlobalStats {
    pub downloads: u64,
    pub uploads: u64,
    pub artifacts: u64,
    pub cache_hit_percent: f64,
    pub storage_bytes: u64,
}

#[derive(Serialize, ToSchema)]
pub struct RegistryCardStats {
    pub name: String,
    pub artifact_count: usize,
    pub downloads: u64,
    pub uploads: u64,
    pub size_bytes: u64,
}

#[derive(Serialize, ToSchema)]
pub struct MountPoint {
    pub registry: String,
    pub mount_path: String,
    pub proxy_upstream: Option<String>,
}

// ============ API Handlers ============

pub async fn api_stats(State(state): State<Arc<AppState>>) -> Json<RegistryStats> {
    // Trigger index rebuild if needed, then get counts
    for reg in &state.enabled_registries {
        let _ = state.repo_index.get(reg.as_str(), &state.storage).await;
    }

    let counts = state.repo_index.counts();
    let get = |rt: RegistryType| counts.get(&rt).copied().unwrap_or(0);
    Json(RegistryStats {
        docker: get(RegistryType::Docker),
        maven: get(RegistryType::Maven),
        npm: get(RegistryType::Npm),
        cargo: get(RegistryType::Cargo),
        pypi: get(RegistryType::PyPI),
        go: get(RegistryType::Go),
        raw: get(RegistryType::Raw),
        nuget: get(RegistryType::Nuget),
        gems: get(RegistryType::Gems),
        terraform: get(RegistryType::Terraform),
        ansible: get(RegistryType::Ansible),
        pub_dart: get(RegistryType::PubDart),
        conan: get(RegistryType::Conan),
    })
}

pub async fn api_dashboard(State(state): State<Arc<AppState>>) -> Json<DashboardResponse> {
    let mut total_storage: u64 = 0;
    let mut total_artifacts: usize = 0;
    let mut registry_card_stats = Vec::new();
    let mut mount_points = Vec::new();

    for reg in RegistryType::all() {
        if !state.enabled_registries.contains(reg) {
            continue;
        }

        let name = reg.as_str();
        let repos = state.repo_index.get(name, &state.storage).await;
        let size: u64 = repos.iter().map(|r| r.size).sum();
        let versions: usize = repos.iter().map(|r| r.versions).sum();

        total_storage += size;
        total_artifacts += versions;

        registry_card_stats.push(RegistryCardStats {
            name: name.to_string(),
            artifact_count: versions,
            downloads: state.metrics.get_registry_downloads(name),
            uploads: state.metrics.get_registry_uploads(name),
            size_bytes: size,
        });

        let proxy_upstream = match reg {
            RegistryType::Docker => state.config.docker.upstreams.first().map(|u| u.url.clone()),
            RegistryType::Maven => state
                .config
                .maven
                .proxies
                .first()
                .map(|p| p.url().to_string()),
            RegistryType::Npm => state.config.npm.proxy.clone(),
            RegistryType::Cargo => state.config.cargo.proxy.clone(),
            RegistryType::PyPI => state.config.pypi.proxy.clone(),
            RegistryType::Go => state.config.go.proxy.clone(),
            RegistryType::Raw => None,
            RegistryType::Gems => state.config.gems.proxy.clone(),
            RegistryType::Terraform => state.config.terraform.proxy.clone(),
            RegistryType::Ansible => state.config.ansible.proxy.clone(),
            RegistryType::Nuget => state.config.nuget.proxy.clone(),
            RegistryType::PubDart => state.config.pub_dart.proxy.clone(),
            RegistryType::Conan => state.config.conan.proxy.clone(),
        };

        mount_points.push(MountPoint {
            registry: reg.display_name().to_string(),
            mount_path: reg.mount_point().to_string(),
            proxy_upstream,
        });
    }

    let global_stats = GlobalStats {
        downloads: state.metrics.downloads.load(Ordering::Relaxed),
        uploads: state.metrics.uploads.load(Ordering::Relaxed),
        artifacts: total_artifacts as u64,
        cache_hit_percent: state.metrics.cache_hit_rate(),
        storage_bytes: total_storage,
    };

    let activity = state.activity.recent(20);
    let uptime_seconds = state.start_time.elapsed().as_secs();

    Json(DashboardResponse {
        global_stats,
        registry_stats: registry_card_stats,
        mount_points,
        activity,
        uptime_seconds,
        startup_duration_ms: state.startup_duration_ms,
    })
}

pub async fn api_list(
    State(state): State<Arc<AppState>>,
    Path(registry_type): Path<String>,
) -> Json<Vec<RepoInfo>> {
    let repos = state.repo_index.get(&registry_type, &state.storage).await;
    Json((*repos).clone())
}

pub async fn api_detail(
    State(state): State<Arc<AppState>>,
    Path((registry_type, name)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match registry_type.as_str() {
        "docker" => {
            let detail = get_docker_detail(&state, &name).await;
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

    let repos = state.repo_index.get(&registry_type, &state.storage).await;

    let filtered: Vec<&RepoInfo> = if query.is_empty() {
        repos.iter().collect()
    } else {
        repos
            .iter()
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
        let folder_icon = r#"<svg class="w-4 h-4 flex-shrink-0 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>"#;
        filtered
            .iter()
            .map(|repo| {
                let detail_url =
                    format!("/ui/{}/{}", registry_type, encode_uri_component(&repo.name));
                format!(
                    r#"
                <tr class="hover:bg-slate-700 cursor-pointer" onclick="window.location='{}'">
                    <td class="px-3 md:px-6 py-3 md:py-4">
                        <div class="flex items-center gap-3">{}<a href="{}" class="text-blue-400 hover:text-blue-300 font-medium">{}</a></div>
                    </td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-400 hidden md:table-cell">{}</td>
                    <td class="px-3 md:px-6 py-3 md:py-4 text-slate-500 text-sm hidden md:table-cell">{}</td>
                </tr>
            "#,
                    detail_url,
                    folder_icon,
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

pub async fn get_docker_detail(state: &AppState, name: &str) -> DockerDetail {
    let prefix = format!("docker/{}/manifests/", name);
    let keys = state.storage.list(&prefix).await;

    // Build public URL for pull commands
    let registry_host =
        state.config.server.public_url.clone().unwrap_or_else(|| {
            format!("{}:{}", state.config.server.host, state.config.server.port)
        });

    let mut tags = Vec::new();
    for key in &keys {
        // Skip .meta.json files
        if key.ends_with(".meta.json") {
            continue;
        }

        if let Some(tag_name) = key
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".json"))
        {
            // Load metadata from .meta.json file
            let meta_key = format!("{}.meta.json", key.trim_end_matches(".json"));
            let metadata = if let Ok(meta_data) = state.storage.get(&meta_key).await {
                serde_json::from_slice::<crate::registry::docker::ImageMetadata>(&meta_data)
                    .unwrap_or_default()
            } else {
                crate::registry::docker::ImageMetadata::default()
            };

            // Get file stats for created timestamp if metadata doesn't have push_timestamp
            let created = if metadata.push_timestamp > 0 {
                format_timestamp(metadata.push_timestamp)
            } else if let Some(file_meta) = state.storage.stat(key).await {
                format_timestamp(file_meta.modified)
            } else {
                "N/A".to_string()
            };

            // Calculate size from manifest layers (config + layers)
            let size = if metadata.size_bytes > 0 {
                metadata.size_bytes
            } else {
                // Parse manifest to get actual image size
                if let Ok(manifest_data) = state.storage.get(key).await {
                    if let Ok(manifest) =
                        serde_json::from_slice::<serde_json::Value>(&manifest_data)
                    {
                        let config_size = manifest
                            .get("config")
                            .and_then(|c| c.get("size"))
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0);
                        let layers_size: u64 = manifest
                            .get("layers")
                            .and_then(|l| l.as_array())
                            .map(|layers| {
                                layers
                                    .iter()
                                    .filter_map(|l| l.get("size").and_then(|s| s.as_u64()))
                                    .sum()
                            })
                            .unwrap_or(0);
                        config_size + layers_size
                    } else {
                        0
                    }
                } else {
                    0
                }
            };

            // Format last_pulled
            let last_pulled = if metadata.last_pulled > 0 {
                Some(format_timestamp(metadata.last_pulled))
            } else {
                None
            };

            // Build pull command
            let pull_command = format!("docker pull {}/{}:{}", registry_host, name, tag_name);

            tags.push(TagInfo {
                name: tag_name.to_string(),
                size,
                created,
                downloads: metadata.downloads,
                last_pulled,
                os: if metadata.os.is_empty() {
                    "unknown".to_string()
                } else {
                    metadata.os
                },
                arch: if metadata.arch.is_empty() {
                    "unknown".to_string()
                } else {
                    metadata.arch
                },
                layers_count: metadata.layers.len(),
                pull_command,
            });
        }
    }

    DockerDetail { tags }
}

/// List immediate children of a Maven namespace path for hierarchical browsing.
/// Returns (entries, is_leaf_artifact). A leaf artifact has maven-metadata.xml.
pub async fn get_maven_dir_listing(storage: &Storage, path: &str) -> (Vec<RepoInfo>, bool) {
    let prefix = if path.is_empty() {
        "maven/".to_string()
    } else {
        format!("maven/{}/", path)
    };
    let keys = storage.list(&prefix).await;

    if keys.is_empty() {
        return (vec![], false);
    }

    // Leaf = no subdirectories (only direct files like JARs, POMs, checksums)
    let has_subdirs = keys.iter().any(|k| {
        k.strip_prefix(&prefix)
            .is_some_and(|r| !r.is_empty() && r.contains('/'))
    });
    if !has_subdirs {
        return (vec![], true);
    }

    // Group by immediate child segment (skip direct files like maven-metadata.xml)
    let mut groups: HashMap<String, (usize, u64, u64)> = HashMap::new();
    for key in &keys {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if rest.is_empty() || !rest.contains('/') {
                continue;
            }
            let child_name = rest.split('/').next().unwrap_or(rest).to_string();
            let entry = groups.entry(child_name).or_insert((0, 0, 0));
            entry.0 += 1;
            if let Some(meta) = storage.stat(key).await {
                entry.1 += meta.size;
                if meta.modified > entry.2 {
                    entry.2 = meta.modified;
                }
            }
        }
    }

    let mut result: Vec<RepoInfo> = groups
        .into_iter()
        .map(|(name, (count, size, modified))| RepoInfo {
            name,
            versions: count,
            size,
            updated: format_timestamp(modified),
            ..Default::default()
        })
        .collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));

    (result, false)
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

pub async fn get_npm_detail(storage: &Storage, name: &str) -> PackageDetail {
    let metadata_key = format!("npm/{}/metadata.json", name);

    let mut versions = Vec::new();

    // Parse metadata.json for version info
    if let Ok(data) = storage.get(&metadata_key).await {
        if let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(versions_obj) = metadata.get("versions").and_then(|v| v.as_object()) {
                let time_obj = metadata.get("time").and_then(|t| t.as_object());

                for (version, info) in versions_obj {
                    let meta_size = info
                        .get("dist")
                        .and_then(|d| d.get("unpackedSize"))
                        .and_then(|s| s.as_u64())
                        .unwrap_or(0);

                    let published = time_obj
                        .and_then(|t| t.get(version))
                        .and_then(|p| p.as_str())
                        .map(|s| s[..10].to_string())
                        .unwrap_or_else(|| "N/A".to_string());

                    // Check if tarball is actually cached on disk
                    let tarball_key = format!("npm/{}/tarballs/{}-{}.tgz", name, name, version);
                    let (size, cached) = if let Some(meta) = storage.stat(&tarball_key).await {
                        (meta.size, true)
                    } else {
                        (meta_size, false)
                    };

                    versions.push(VersionInfo {
                        version: version.clone(),
                        size,
                        published,
                        cached,
                    });
                }
            }
        }
    }

    // Sort by version (semver-like, newest first)
    versions.sort_by(|a, b| {
        let a_parts: Vec<u32> = a
            .version
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let b_parts: Vec<u32> = b
            .version
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        b_parts.cmp(&a_parts)
    });

    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
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
                    cached: true,
                });
            }
        }
    }

    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
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
                    cached: true,
                });
            }
        }
    }

    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

pub async fn get_go_detail(storage: &Storage, module: &str) -> PackageDetail {
    let prefix = format!("go/{}/@v/", module);

    // Read version list file (populated by go proxy on list requests)
    let list_key = format!("{}list", prefix);
    let mut known_versions: Vec<String> = Vec::new();
    if let Ok(data) = storage.get(&list_key).await {
        if let Ok(text) = String::from_utf8(data.to_vec()) {
            for line in text.lines() {
                let v = line.trim();
                if !v.is_empty() {
                    known_versions.push(v.to_string());
                }
            }
        }
    }

    // Also scan for .zip files that might exist without being in the list
    let keys = storage.list(&prefix).await;
    for key in keys.iter().filter(|k| k.ends_with(".zip")) {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if let Some(version) = rest.strip_suffix(".zip") {
                if !known_versions.iter().any(|v| v == version) {
                    known_versions.push(version.to_string());
                }
            }
        }
    }

    let list_ts = storage
        .stat(&list_key)
        .await
        .map(|m| format_timestamp(m.modified))
        .unwrap_or_else(|| "N/A".to_string());

    let mut versions = Vec::new();
    for v in &known_versions {
        let zip_key = format!("{}{}.zip", prefix, v);
        let (size, published, cached) = if let Some(meta) = storage.stat(&zip_key).await {
            (meta.size, format_timestamp(meta.modified), true)
        } else {
            (0, list_ts.clone(), false)
        };
        versions.push(VersionInfo {
            version: v.clone(),
            size,
            published,
            cached,
        });
    }

    versions.sort_by(|a, b| b.version.cmp(&a.version));
    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

/// Generic detail for new-format registries (NuGet, Gems, Terraform, Ansible, Pub, Conan).
/// Reads version info from storage using registry-specific paths.
pub async fn get_generic_detail(
    storage: &Storage,
    registry: &str,
    name: &str,
    show_prerelease: bool,
) -> PackageDetail {
    let name_lower = name.to_lowercase();

    match registry {
        "nuget" => get_nuget_detail(storage, &name_lower, show_prerelease).await,
        "conan" => get_conan_detail(storage, &name_lower).await,
        "gems" => get_gems_detail(storage, &name_lower).await,
        "pub" => get_pub_detail(storage, &name_lower).await,
        _ => get_storage_scan_detail(storage, registry, &name_lower).await,
    }
}

async fn get_nuget_detail(storage: &Storage, name: &str, show_prerelease: bool) -> PackageDetail {
    // Load registration index for real published dates from upstream metadata
    let reg_key = format!("nuget/registration/{}/index.json", name);
    let reg_meta = load_nuget_registration_meta(storage, &reg_key).await;

    let key = format!("nuget/flatcontainer/{}/index.json", name);
    if let Ok(data) = storage.get(&key).await {
        if let Ok(index) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(versions) = index.get("versions").and_then(|v| v.as_array()) {
                let fallback_ts = storage
                    .stat(&key)
                    .await
                    .map(|m| format_timestamp(m.modified))
                    .unwrap_or_else(|| "N/A".to_string());

                let mut stable_versions = Vec::new();
                let mut prerelease_count: usize = 0;

                for v in versions.iter().rev().filter_map(|v| v.as_str()) {
                    let is_prerelease = v.contains('-');

                    // Get published date from registration metadata
                    let (published, _upstream_size) = reg_meta
                        .get(v)
                        .map(|(p, s)| (p.clone(), *s))
                        .unwrap_or_else(|| (fallback_ts.clone(), 0));

                    // Skip unlisted (NuGet convention: published=1900-01-01)
                    if published.starts_with("1900") {
                        continue;
                    }

                    // Count pre-release, skip unless toggled
                    if is_prerelease {
                        prerelease_count += 1;
                        if !show_prerelease {
                            continue;
                        }
                    }

                    // Check if .nupkg is cached locally
                    let nupkg_key =
                        format!("nuget/flatcontainer/{}/{}/{}.{}.nupkg", name, v, name, v);
                    let (size, cached) = if let Some(meta) = storage.stat(&nupkg_key).await {
                        (meta.size, true)
                    } else {
                        (0, false)
                    };

                    stable_versions.push(VersionInfo {
                        version: v.to_string(),
                        size,
                        published,
                        cached,
                    });
                }

                let total_stable = stable_versions
                    .iter()
                    .filter(|v| !v.version.contains('-'))
                    .count();
                // Limit default view to 20 versions when not showing all
                if !show_prerelease && stable_versions.len() > 20 {
                    stable_versions.truncate(20);
                }

                return PackageDetail {
                    versions: stable_versions,
                    prerelease_count,
                    total_stable,
                };
            }
        }
    }
    PackageDetail {
        versions: vec![],
        prerelease_count: 0,
        total_stable: 0,
    }
}

/// Extract per-version (published, packageSize) from cached NuGet registration index.
async fn load_nuget_registration_meta(
    storage: &Storage,
    key: &str,
) -> HashMap<String, (String, u64)> {
    let mut map = HashMap::new();
    let data = match storage.get(key).await {
        Ok(d) => d,
        Err(_) => return map,
    };
    let json: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return map,
    };
    if let Some(pages) = json.get("items").and_then(|v| v.as_array()) {
        for page in pages {
            if let Some(items) = page.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    if let Some(entry) = item.get("catalogEntry") {
                        let ver = entry
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let published = entry
                            .get("published")
                            .and_then(|v| v.as_str())
                            .map(|s| s.split('T').next().unwrap_or(s).to_string())
                            .unwrap_or_else(|| "N/A".to_string());
                        let size = entry
                            .get("packageSize")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if !ver.is_empty() {
                            map.insert(ver.to_string(), (published, size));
                        }
                    }
                }
            }
        }
    }
    map
}

async fn get_conan_detail(storage: &Storage, name: &str) -> PackageDetail {
    // Conan: conan/{name}/{version}/_/_/revisions.json (metadata)
    // Actual files: conan/{name}/{version}/_/_/{rrev}/export/* or /packages/*/
    let prefix = format!("conan/{}/", name);
    let keys = storage.list(&prefix).await;
    let mut version_data: HashMap<String, (u64, u64, bool)> = HashMap::new(); // (size, mtime, has_content)

    for key in &keys {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if let Some(version) = rest.split('/').next() {
                let entry = version_data
                    .entry(version.to_string())
                    .or_insert((0, 0, false));
                let is_content = !key.ends_with("/revisions.json");
                if let Some(meta) = storage.stat(key).await {
                    if is_content {
                        entry.0 += meta.size;
                        entry.2 = true;
                    }
                    if meta.modified > entry.1 {
                        entry.1 = meta.modified;
                    }
                }
            }
        }
    }

    let mut versions: Vec<VersionInfo> = version_data
        .into_iter()
        .map(|(version, (size, modified, has_content))| VersionInfo {
            version,
            size,
            published: format_timestamp(modified),
            cached: has_content,
        })
        .collect();
    versions.sort_by(|a, b| b.version.cmp(&a.version));
    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

async fn get_gems_detail(storage: &Storage, name: &str) -> PackageDetail {
    // Read compact index: gems/info/{name}
    // Format: "VERSION DEPS|checksum:HEX" per line, first line is "---"
    let info_key = format!("gems/info/{}", name);
    let info_ts = storage
        .stat(&info_key)
        .await
        .map(|m| format_timestamp(m.modified))
        .unwrap_or_else(|| "N/A".to_string());

    let mut versions = Vec::new();

    if let Ok(data) = storage.get(&info_key).await {
        if let Ok(text) = String::from_utf8(data.to_vec()) {
            for line in text.lines() {
                if line.starts_with('-') || line.is_empty() {
                    continue;
                }
                // "1.3.0 deps...|checksum:..." — version is first token
                let version = match line.split_whitespace().next() {
                    Some(v) if !v.is_empty() => v.to_string(),
                    _ => continue,
                };

                // Check if .gem is cached
                let gem_key = format!("gems/gems/{}-{}.gem", name, version);
                let (size, published, cached) = if let Some(meta) = storage.stat(&gem_key).await {
                    (meta.size, format_timestamp(meta.modified), true)
                } else {
                    (0, info_ts.clone(), false)
                };

                versions.push(VersionInfo {
                    version,
                    size,
                    published,
                    cached,
                });
            }
        }
    }

    // Reverse: newest first (compact index is chronological)
    versions.reverse();
    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

async fn get_pub_detail(storage: &Storage, name: &str) -> PackageDetail {
    // Pub: pub/packages/{name}/versions/{version}.tar.gz
    let prefix = format!("pub/packages/{}/versions/", name);
    let keys = storage.list(&prefix).await;
    let mut versions = Vec::new();

    for key in &keys {
        if key.ends_with(".sha256") {
            continue;
        }
        if let Some(rest) = key.strip_prefix(&prefix) {
            let version = rest.trim_end_matches(".tar.gz").to_string();
            if !version.is_empty() {
                let (size, published) = if let Some(meta) = storage.stat(key).await {
                    (meta.size, format_timestamp(meta.modified))
                } else {
                    (0, "N/A".to_string())
                };
                versions.push(VersionInfo {
                    version,
                    size,
                    published,
                    cached: true,
                });
            }
        }
    }
    versions.sort_by(|a, b| b.version.cmp(&a.version));
    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

/// Fallback: scan storage for files matching {registry}/{name}/*
async fn get_storage_scan_detail(storage: &Storage, registry: &str, name: &str) -> PackageDetail {
    let prefix = format!("{}/{}/", registry, name);
    let keys = storage.list(&prefix).await;
    let mut versions = Vec::new();
    for key in &keys {
        if let Some(rest) = key.strip_prefix(&prefix) {
            let version = rest
                .trim_end_matches(".tar.gz")
                .trim_end_matches(".gem")
                .trim_end_matches(".zip")
                .trim_end_matches(".tgz")
                .to_string();
            if !version.is_empty() && !version.contains('/') {
                let (size, published) = if let Some(meta) = storage.stat(key).await {
                    (meta.size, format_timestamp(meta.modified))
                } else {
                    (0, "N/A".to_string())
                };
                versions.push(VersionInfo {
                    version,
                    size,
                    published,
                    cached: true,
                });
            }
        }
    }
    versions.sort_by(|a, b| b.version.cmp(&a.version));
    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
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

pub async fn get_raw_detail(storage: &Storage, group: &str) -> PackageDetail {
    let prefix = format!("raw/{}/", group);
    let keys = storage.list(&prefix).await;

    let mut versions = Vec::new();

    if keys.is_empty() {
        // Root-level file: "raw/myfile.txt" (no subdirectory)
        let direct_key = format!("raw/{}", group);
        if let Some(meta) = storage.stat(&direct_key).await {
            versions.push(VersionInfo {
                version: group.to_string(),
                size: meta.size,
                published: format_timestamp(meta.modified),
                cached: true,
            });
            return PackageDetail {
                versions,
                prerelease_count: 0,
                total_stable: 0,
            };
        }
    }

    for key in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            let (size, published) = if let Some(meta) = storage.stat(key).await {
                (meta.size, format_timestamp(meta.modified))
            } else {
                (0, "N/A".to_string())
            };
            versions.push(VersionInfo {
                version: filename.to_string(),
                size,
                published,
                cached: true,
            });
        }
    }

    PackageDetail {
        versions,
        prerelease_count: 0,
        total_stable: 0,
    }
}

/// List immediate children (subfolders + files) of a raw directory path.
/// Returns (entries, is_directory). If the path is a single file, returns empty vec + false.
pub async fn get_raw_dir_listing(storage: &Storage, path: &str) -> (Vec<RepoInfo>, bool) {
    let prefix = format!("raw/{}/", path);
    let keys = storage.list(&prefix).await;

    if keys.is_empty() {
        // Check if it's a direct file
        let direct_key = format!("raw/{}", path);
        if storage.stat(&direct_key).await.is_some() {
            return (vec![], false); // It's a file, not a directory
        }
        return (vec![], true); // Empty directory
    }

    // Group by immediate child segment
    let mut groups: HashMap<String, (usize, u64, u64, bool)> = HashMap::new();

    for key in &keys {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if rest.is_empty() {
                continue;
            }
            let is_direct_file = !rest.contains('/');
            let child_name = rest.split('/').next().unwrap_or(rest).to_string();

            let entry = groups
                .entry(child_name)
                .or_insert((0, 0, 0, is_direct_file));
            entry.0 += 1;
            if let Some(meta) = storage.stat(key).await {
                entry.1 += meta.size;
                if meta.modified > entry.2 {
                    entry.2 = meta.modified;
                }
            }
        }
    }

    let mut result: Vec<RepoInfo> = groups
        .into_iter()
        .map(|(name, (count, size, modified, is_file))| RepoInfo {
            name,
            versions: count,
            size,
            updated: format_timestamp(modified),
            is_file,
        })
        .collect();

    // Sort: directories first, then files, alphabetical within each group
    result.sort_by(|a, b| a.is_file.cmp(&b.is_file).then_with(|| a.name.cmp(&b.name)));

    (result, true)
}
