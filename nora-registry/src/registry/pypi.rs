// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/simple/", get(list_packages))
        .route("/simple/{name}/", get(package_versions))
        .route("/simple/{name}/{filename}", get(download_file))
}

/// List all packages (Simple API index)
async fn list_packages(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.storage.list("pypi/").await;
    let mut packages = std::collections::HashSet::new();

    for key in keys {
        if let Some(pkg) = key.strip_prefix("pypi/").and_then(|k| k.split('/').next()) {
            if !pkg.is_empty() {
                packages.insert(pkg.to_string());
            }
        }
    }

    let mut html = String::from(
        "<!DOCTYPE html>\n<html><head><title>Simple Index</title></head><body><h1>Simple Index</h1>\n",
    );
    let mut pkg_list: Vec<_> = packages.into_iter().collect();
    pkg_list.sort();

    for pkg in pkg_list {
        html.push_str(&format!("<a href=\"/simple/{}/\">{}</a><br>\n", pkg, pkg));
    }
    html.push_str("</body></html>");

    (StatusCode::OK, Html(html))
}

/// List versions/files for a specific package
async fn package_versions(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    // Normalize package name (PEP 503)
    let normalized = normalize_name(&name);

    // Try to get local files first
    let prefix = format!("pypi/{}/", normalized);
    let keys = state.storage.list(&prefix).await;

    if !keys.is_empty() {
        // We have local files
        let mut html = format!(
            "<!DOCTYPE html>\n<html><head><title>Links for {}</title></head><body><h1>Links for {}</h1>\n",
            name, name
        );

        for key in &keys {
            if let Some(filename) = key.strip_prefix(&prefix) {
                if !filename.is_empty() {
                    html.push_str(&format!(
                        "<a href=\"/simple/{}/{}\">{}</a><br>\n",
                        normalized, filename, filename
                    ));
                }
            }
        }
        html.push_str("</body></html>");

        return (StatusCode::OK, Html(html)).into_response();
    }

    // Try proxy if configured
    if let Some(proxy_url) = &state.config.pypi.proxy {
        let url = format!("{}/{}/", proxy_url.trim_end_matches('/'), normalized);

        if let Ok(html) = fetch_package_page(&url, state.config.pypi.proxy_timeout).await {
            // Rewrite URLs in the HTML to point to our registry
            let rewritten = rewrite_pypi_links(&html, &normalized);
            return (StatusCode::OK, Html(rewritten)).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Download a specific file
async fn download_file(
    State(state): State<Arc<AppState>>,
    Path((name, filename)): Path<(String, String)>,
) -> Response {
    let normalized = normalize_name(&name);
    let key = format!("pypi/{}/{}", normalized, filename);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        state.metrics.record_download("pypi");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", name, filename),
            "pypi",
            "CACHE",
        ));

        let content_type = if filename.ends_with(".whl") {
            "application/zip"
        } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            "application/gzip"
        } else {
            "application/octet-stream"
        };

        return (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data).into_response();
    }

    // Try proxy if configured
    if let Some(proxy_url) = &state.config.pypi.proxy {
        // First, fetch the package page to find the actual download URL
        let page_url = format!("{}/{}/", proxy_url.trim_end_matches('/'), normalized);

        if let Ok(html) = fetch_package_page(&page_url, state.config.pypi.proxy_timeout).await {
            // Find the URL for this specific file
            if let Some(file_url) = find_file_url(&html, &filename) {
                if let Ok(data) = fetch_file(&file_url, state.config.pypi.proxy_timeout).await {
                    state.metrics.record_download("pypi");
                    state.metrics.record_cache_miss();
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        format!("{}/{}", name, filename),
                        "pypi",
                        "PROXY",
                    ));

                    // Cache in local storage
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let data_clone = data.clone();
                    tokio::spawn(async move {
                        let _ = storage.put(&key_clone, &data_clone).await;
                    });

                    let content_type = if filename.ends_with(".whl") {
                        "application/zip"
                    } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
                        "application/gzip"
                    } else {
                        "application/octet-stream"
                    };

                    return (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
                        .into_response();
                }
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Normalize package name according to PEP 503
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace(['-', '_', '.'], "-")
}

/// Fetch package page from upstream
async fn fetch_package_page(url: &str, timeout_secs: u64) -> Result<String, ()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|_| ())?;

    let response = client
        .get(url)
        .header("Accept", "text/html")
        .send()
        .await
        .map_err(|_| ())?;

    if !response.status().is_success() {
        return Err(());
    }

    response.text().await.map_err(|_| ())
}

/// Fetch file from upstream
async fn fetch_file(url: &str, timeout_secs: u64) -> Result<Vec<u8>, ()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|_| ())?;

    let response = client.get(url).send().await.map_err(|_| ())?;

    if !response.status().is_success() {
        return Err(());
    }

    response.bytes().await.map(|b| b.to_vec()).map_err(|_| ())
}

/// Rewrite PyPI links to point to our registry
fn rewrite_pypi_links(html: &str, package_name: &str) -> String {
    // Simple regex-free approach: find href="..." and rewrite
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        result.push_str(&remaining[..href_start + 6]);
        remaining = &remaining[href_start + 6..];

        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];

            // Extract filename from URL
            if let Some(filename) = extract_filename(url) {
                // Rewrite to our local URL
                result.push_str(&format!("/simple/{}/{}", package_name, filename));
            } else {
                result.push_str(url);
            }

            remaining = &remaining[href_end..];
        }
    }
    result.push_str(remaining);

    // Remove data-core-metadata and data-dist-info-metadata attributes
    // as we don't serve .metadata files (PEP 658)
    let result = remove_attribute(&result, "data-core-metadata");
    remove_attribute(&result, "data-dist-info-metadata")
}

/// Remove an HTML attribute from all tags
fn remove_attribute(html: &str, attr_name: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;
    let pattern = format!(" {}=\"", attr_name);

    while let Some(attr_start) = remaining.find(&pattern) {
        result.push_str(&remaining[..attr_start]);
        remaining = &remaining[attr_start + pattern.len()..];

        // Skip the attribute value
        if let Some(attr_end) = remaining.find('"') {
            remaining = &remaining[attr_end + 1..];
        }
    }
    result.push_str(remaining);
    result
}

/// Extract filename from PyPI download URL
fn extract_filename(url: &str) -> Option<&str> {
    // PyPI URLs look like:
    // https://files.pythonhosted.org/packages/.../package-1.0.0.tar.gz#sha256=...
    // or just the filename directly

    // Remove hash fragment
    let url = url.split('#').next()?;

    // Get the last path component
    let filename = url.rsplit('/').next()?;

    // Must be a valid package file
    if filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".whl")
        || filename.ends_with(".zip")
        || filename.ends_with(".egg")
    {
        Some(filename)
    } else {
        None
    }
}

/// Find the download URL for a specific file in the HTML
fn find_file_url(html: &str, target_filename: &str) -> Option<String> {
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        remaining = &remaining[href_start + 6..];

        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];

            if let Some(filename) = extract_filename(url) {
                if filename == target_filename {
                    // Remove hash fragment for actual download
                    return Some(url.split('#').next().unwrap_or(url).to_string());
                }
            }

            remaining = &remaining[href_end..];
        }
    }

    None
}
