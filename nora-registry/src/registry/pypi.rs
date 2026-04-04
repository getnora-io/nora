// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{proxy_fetch, proxy_fetch_text};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

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

        if let Ok(html) = proxy_fetch_text(
            &state.http_client,
            &url,
            state.config.pypi.proxy_timeout,
            state.config.pypi.proxy_auth.as_deref(),
            Some(("Accept", "text/html")),
        )
        .await
        {
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
        state
            .audit
            .log(AuditEntry::new("cache_hit", "api", "", "pypi", ""));

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

        if let Ok(html) = proxy_fetch_text(
            &state.http_client,
            &page_url,
            state.config.pypi.proxy_timeout,
            state.config.pypi.proxy_auth.as_deref(),
            Some(("Accept", "text/html")),
        )
        .await
        {
            // Find the URL for this specific file
            if let Some(file_url) = find_file_url(&html, &filename) {
                if let Ok(data) = proxy_fetch(
                    &state.http_client,
                    &file_url,
                    state.config.pypi.proxy_timeout,
                    state.config.pypi.proxy_auth.as_deref(),
                )
                .await
                {
                    state.metrics.record_download("pypi");
                    state.metrics.record_cache_miss();
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        format!("{}/{}", name, filename),
                        "pypi",
                        "PROXY",
                    ));
                    state
                        .audit
                        .log(AuditEntry::new("proxy_fetch", "api", "", "pypi", ""));

                    // Cache in local storage
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let data_clone = data.clone();
                    tokio::spawn(async move {
                        let _ = storage.put(&key_clone, &data_clone).await;
                    });

                    state.repo_index.invalidate("pypi");

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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_filename_never_panics(s in "\\PC{0,500}") {
            let _ = extract_filename(&s);
        }

        #[test]
        fn extract_filename_valid_tarball(
            name in "[a-z][a-z0-9_-]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/packages/{}-{}.tar.gz", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".tar.gz"));
        }

        #[test]
        fn extract_filename_valid_wheel(
            name in "[a-z][a-z0-9_]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/{}-{}-py3-none-any.whl", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".whl"));
        }

        #[test]
        fn extract_filename_strips_hash(
            name in "[a-z]{1,10}",
            hash in "[a-f0-9]{64}"
        ) {
            let url = format!("https://example.com/{}.tar.gz#sha256={}", name, hash);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            let fname = result.unwrap();
            prop_assert!(!fname.contains('#'));
        }

        #[test]
        fn extract_filename_rejects_unknown_ext(
            name in "[a-z]{1,10}",
            ext in "(exe|dll|so|bin|dat)"
        ) {
            let url = format!("https://example.com/{}.{}", name, ext);
            prop_assert!(extract_filename(&url).is_none());
        }
    }

    #[test]
    fn test_normalize_name_lowercase() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("REQUESTS"), "requests");
    }

    #[test]
    fn test_normalize_name_separators() {
        assert_eq!(normalize_name("my-package"), "my-package");
        assert_eq!(normalize_name("my_package"), "my-package");
        assert_eq!(normalize_name("my.package"), "my-package");
    }

    #[test]
    fn test_normalize_name_mixed() {
        assert_eq!(
            normalize_name("My_Complex.Package-Name"),
            "my-complex-package-name"
        );
    }

    #[test]
    fn test_normalize_name_empty() {
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn test_normalize_name_already_normal() {
        assert_eq!(normalize_name("simple"), "simple");
    }

    #[test]
    fn test_extract_filename_tarball() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0.tar.gz#sha256=abc123"
            ),
            Some("flask-2.0.0.tar.gz")
        );
    }

    #[test]
    fn test_extract_filename_wheel() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0-py3-none-any.whl"
            ),
            Some("flask-2.0.0-py3-none-any.whl")
        );
    }

    #[test]
    fn test_extract_filename_tgz() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.tgz"),
            Some("package-1.0.tgz")
        );
    }

    #[test]
    fn test_extract_filename_zip() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.zip"),
            Some("package-1.0.zip")
        );
    }

    #[test]
    fn test_extract_filename_egg() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.egg"),
            Some("package-1.0.egg")
        );
    }

    #[test]
    fn test_extract_filename_unknown_ext() {
        assert_eq!(extract_filename("https://example.com/readme.txt"), None);
    }

    #[test]
    fn test_extract_filename_no_path() {
        assert_eq!(extract_filename(""), None);
    }

    #[test]
    fn test_extract_filename_bare() {
        assert_eq!(
            extract_filename("package-1.0.tar.gz"),
            Some("package-1.0.tar.gz")
        );
    }

    #[test]
    fn test_remove_attribute_present() {
        let html = r#"<a href="url" data-core-metadata="true">link</a>"#;
        let result = remove_attribute(html, "data-core-metadata");
        assert_eq!(result, r#"<a href="url">link</a>"#);
    }

    #[test]
    fn test_remove_attribute_absent() {
        let html = r#"<a href="url">link</a>"#;
        let result = remove_attribute(html, "data-core-metadata");
        assert_eq!(result, html);
    }

    #[test]
    fn test_remove_attribute_multiple() {
        let html =
            r#"<a data-core-metadata="true">one</a><a data-core-metadata="sha256=abc">two</a>"#;
        let result = remove_attribute(html, "data-core-metadata");
        assert_eq!(result, r#"<a>one</a><a>two</a>"#);
    }

    #[test]
    fn test_rewrite_pypi_links_basic() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz#sha256=abc">flask-2.0.tar.gz</a>"#;
        let result = rewrite_pypi_links(html, "flask");
        assert!(result.contains("/simple/flask/flask-2.0.tar.gz"));
    }

    #[test]
    fn test_rewrite_pypi_links_unknown_ext() {
        let html = r#"<a href="https://example.com/readme.txt">readme</a>"#;
        let result = rewrite_pypi_links(html, "test");
        assert!(result.contains("https://example.com/readme.txt"));
    }

    #[test]
    fn test_rewrite_pypi_links_removes_metadata_attrs() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl" data-core-metadata="sha256=abc" data-dist-info-metadata="sha256=def">pkg</a>"#;
        let result = rewrite_pypi_links(html, "pkg");
        assert!(!result.contains("data-core-metadata"));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_pypi_links_empty() {
        assert_eq!(rewrite_pypi_links("", "pkg"), "");
    }

    #[test]
    fn test_find_file_url_found() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz#sha256=abc">flask-2.0.tar.gz</a>"#;
        let result = find_file_url(html, "flask-2.0.tar.gz");
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_file_url_not_found() {
        let html = r#"<a href="https://example.com/other-1.0.tar.gz">other</a>"#;
        let result = find_file_url(html, "flask-2.0.tar.gz");
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_file_url_strips_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=deadbeef">pkg</a>"#;
        let result = find_file_url(html, "pkg-1.0.whl");
        assert_eq!(result, Some("https://example.com/pkg-1.0.whl".to_string()));
    }
}
