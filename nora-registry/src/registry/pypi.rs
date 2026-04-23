// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! PyPI registry — PEP 503 (Simple HTML) + PEP 691 (JSON) + twine upload.
//!
//! Implements:
//!   GET  /simple/                     — package index (HTML or JSON)
//!   GET  /simple/{name}/              — package versions (HTML or JSON)
//!   GET  /simple/{name}/{filename}    — download file
//!   POST /simple/                     — twine upload (multipart/form-data)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{proxy_fetch, proxy_fetch_text};
use crate::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use sha2::Digest;
use std::sync::Arc;

/// PEP 691 JSON content type
const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/simple/", get(list_packages).post(upload))
        .route("/simple/{name}/", get(package_versions))
        .route("/simple/{name}/{filename}", get(download_file))
}

// ============================================================================
// Package index
// ============================================================================

/// GET /simple/ — list all packages (PEP 503 HTML or PEP 691 JSON).
async fn list_packages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let keys = state.storage.list("pypi/").await;
    let mut packages = std::collections::HashSet::new();

    for key in keys {
        if let Some(pkg) = key.strip_prefix("pypi/").and_then(|k| k.split('/').next()) {
            if !pkg.is_empty() {
                packages.insert(pkg.to_string());
            }
        }
    }

    let mut pkg_list: Vec<_> = packages.into_iter().collect();
    pkg_list.sort();

    if wants_json(&headers) {
        // PEP 691 JSON response
        let projects: Vec<serde_json::Value> = pkg_list
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect();
        let body = serde_json::json!({
            "meta": {"api-version": "1.0"},
            "projects": projects,
        });
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, PEP691_JSON)],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    } else {
        // PEP 503 HTML
        let mut html = String::from(
            "<!DOCTYPE html>\n<html><head><title>Simple Index</title></head><body><h1>Simple Index</h1>\n",
        );
        for pkg in pkg_list {
            html.push_str(&format!("<a href=\"/simple/{}/\">{}</a><br>\n", pkg, pkg));
        }
        html.push_str("</body></html>");
        (StatusCode::OK, Html(html)).into_response()
    }
}

// ============================================================================
// Package versions
// ============================================================================

/// Returns base URL for PyPI download links.
/// Uses public_url if set, otherwise http://host:port.
fn pypi_base_url(state: &AppState) -> String {
    state
        .config
        .server
        .public_url
        .as_deref()
        .map(|u| u.trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                state.config.server.host, state.config.server.port
            )
        })
}

/// GET /simple/{name}/ — list files for a package (PEP 503 HTML or PEP 691 JSON).
async fn package_versions(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let normalized = normalize_name(&name);
    let prefix = format!("pypi/{}/", normalized);
    let keys = state.storage.list(&prefix).await;
    let base_url = pypi_base_url(&state);

    // Collect files with their hashes
    let mut files: Vec<FileEntry> = Vec::new();
    for key in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if !filename.is_empty() && !filename.ends_with(".sha256") {
                let sha256 = state
                    .storage
                    .get(&format!("{}.sha256", key))
                    .await
                    .ok()
                    .and_then(|d| String::from_utf8(d.to_vec()).ok());
                files.push(FileEntry {
                    filename: filename.to_string(),
                    sha256,
                });
            }
        }
    }

    if !files.is_empty() {
        return if wants_json(&headers) {
            versions_json_response(&normalized, &files, &base_url)
        } else {
            versions_html_response(&normalized, &files, &base_url)
        };
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
            let rewritten = rewrite_pypi_links(&html, &normalized, &base_url);
            return (StatusCode::OK, Html(rewritten)).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

// ============================================================================
// Download
// ============================================================================

/// GET /simple/{name}/{filename} — download a specific file.
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

        let content_type = pypi_content_type(&filename);
        return (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data).into_response();
    }

    // Try proxy if configured
    if let Some(proxy_url) = &state.config.pypi.proxy {
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

                    // Cache in background + compute hash
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let data_clone = data.clone();
                    tokio::spawn(async move {
                        let _ = storage.put(&key_clone, &data_clone).await;
                        let hash = hex::encode(sha2::Sha256::digest(&data_clone));
                        let _ = storage
                            .put(&format!("{}.sha256", key_clone), hash.as_bytes())
                            .await;
                    });

                    state.repo_index.invalidate("pypi");

                    let content_type = pypi_content_type(&filename);
                    return (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
                        .into_response();
                }
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

// ============================================================================
// Twine upload (PEP 503 — POST /simple/)
// ============================================================================

/// POST /simple/ — upload a package via twine.
///
/// twine sends multipart/form-data with fields:
///   :action = "file_upload"
///   name = package name
///   version = package version
///   filetype = "sdist" | "bdist_wheel"
///   content = the file bytes
///   sha256_digest = hex SHA-256 of file (optional)
///   metadata_version, summary, etc. (optional metadata)
async fn upload(State(state): State<Arc<AppState>>, mut multipart: Multipart) -> Response {
    let mut action = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut filename = String::new();
    let mut file_data: Option<Vec<u8>> = None;
    let mut sha256_digest = String::new();

    // Parse multipart fields
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            ":action" => {
                action = field.text().await.ok().unwrap_or_default();
            }
            "name" => {
                name = field.text().await.ok().unwrap_or_default();
            }
            "version" => {
                version = field.text().await.ok().unwrap_or_default();
            }
            "sha256_digest" => {
                sha256_digest = field.text().await.ok().unwrap_or_default();
            }
            "content" => {
                filename = field.file_name().unwrap_or("unknown").to_string();
                match field.bytes().await {
                    Ok(b) => file_data = Some(b.to_vec()),
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Failed to read file: {}", e),
                        )
                            .into_response()
                    }
                }
            }
            _ => {
                // Skip other metadata fields (summary, author, etc.)
                let _ = field.bytes().await;
            }
        }
    }

    // Validate required fields
    if action != "file_upload" {
        return (StatusCode::BAD_REQUEST, "Unsupported action").into_response();
    }

    if name.is_empty() || version.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing name or version").into_response();
    }

    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => return (StatusCode::BAD_REQUEST, "Missing file content").into_response(),
    };

    // Validate filename
    if filename.is_empty() || !is_valid_pypi_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "Invalid filename").into_response();
    }

    // Verify SHA-256 if provided
    let computed_hash = hex::encode(sha2::Sha256::digest(&data));
    if !sha256_digest.is_empty() && sha256_digest != computed_hash {
        tracing::warn!(
            package = %name,
            expected = %sha256_digest,
            computed = %computed_hash,
            "SECURITY: PyPI upload SHA-256 mismatch"
        );
        return (StatusCode::BAD_REQUEST, "SHA-256 digest mismatch").into_response();
    }

    // Normalize name and store
    let normalized = normalize_name(&name);

    // TOCTOU protection: lock per file to prevent concurrent uploads
    let file_key = format!("pypi/{}/{}", normalized, filename);
    let lock = state.publish_lock(&file_key);
    let _guard = lock.lock().await;

    // Check immutability (same filename = already exists)
    if state.storage.stat(&file_key).await.is_some() {
        return (
            StatusCode::CONFLICT,
            format!("File {} already exists", filename),
        )
            .into_response();
    }

    // Store file
    if state.storage.put(&file_key, &data).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Store SHA-256 hash
    let hash_key = format!("{}.sha256", file_key);
    let _ = state.storage.put(&hash_key, computed_hash.as_bytes()).await;

    state.metrics.record_upload("pypi");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}-{}", name, version),
        "pypi",
        "LOCAL",
    ));
    state
        .audit
        .log(AuditEntry::new("push", "api", "", "pypi", ""));
    state.repo_index.invalidate("pypi");

    StatusCode::OK.into_response()
}

// ============================================================================
// PEP 691 JSON responses
// ============================================================================

struct FileEntry {
    filename: String,
    sha256: Option<String>,
}

fn versions_json_response(normalized: &str, files: &[FileEntry], base_url: &str) -> Response {
    let file_entries: Vec<serde_json::Value> = files
        .iter()
        .map(|f| {
            let mut entry = serde_json::json!({
                "filename": f.filename,
                "url": format!("{}/simple/{}/{}", base_url, normalized, f.filename),
            });
            if let Some(hash) = &f.sha256 {
                entry["digests"] = serde_json::json!({"sha256": hash});
            }
            entry
        })
        .collect();

    let body = serde_json::json!({
        "meta": {"api-version": "1.0"},
        "name": normalized,
        "files": file_entries,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PEP691_JSON)],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

fn versions_html_response(normalized: &str, files: &[FileEntry], base_url: &str) -> Response {
    let mut html = format!(
        "<!DOCTYPE html>\n<html><head><title>Links for {}</title></head><body><h1>Links for {}</h1>\n",
        normalized, normalized
    );

    for f in files {
        let hash_fragment = f
            .sha256
            .as_ref()
            .map(|h| format!("#sha256={}", h))
            .unwrap_or_default();
        html.push_str(&format!(
            "<a href=\"{}/simple/{}/{}{}\">{}</a><br>\n",
            base_url, normalized, f.filename, hash_fragment, f.filename
        ));
    }
    html.push_str("</body></html>");

    (StatusCode::OK, Html(html)).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Normalize package name according to PEP 503.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace(['-', '_', '.'], "-")
}

/// Check Accept header for PEP 691 JSON.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains(PEP691_JSON))
        .unwrap_or(false)
}

/// Content-type for PyPI files.
fn pypi_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".whl") {
        "application/zip"
    } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

/// Validate PyPI filename.
fn is_valid_pypi_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && (name.ends_with(".tar.gz")
            || name.ends_with(".tgz")
            || name.ends_with(".whl")
            || name.ends_with(".zip")
            || name.ends_with(".egg"))
}

/// Rewrite PyPI links to point to our registry.
fn rewrite_pypi_links(html: &str, package_name: &str, base_url: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        result.push_str(&remaining[..href_start + 6]);
        remaining = &remaining[href_start + 6..];

        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];

            if let Some(filename) = extract_filename(url) {
                // Extract hash fragment from original URL
                let hash_fragment = url.find('#').map(|pos| &url[pos..]).unwrap_or("");
                result.push_str(&format!(
                    "{}/simple/{}/{}{}",
                    base_url, package_name, filename, hash_fragment
                ));
            } else {
                result.push_str(url);
            }

            remaining = &remaining[href_end..];
        }
    }
    result.push_str(remaining);

    // Remove data-core-metadata and data-dist-info-metadata attributes
    let result = remove_attribute(&result, "data-core-metadata");
    remove_attribute(&result, "data-dist-info-metadata")
}

/// Remove an HTML attribute from all tags.
fn remove_attribute(html: &str, attr_name: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;
    let pattern = format!(" {}=\"", attr_name);

    while let Some(attr_start) = remaining.find(&pattern) {
        result.push_str(&remaining[..attr_start]);
        remaining = &remaining[attr_start + pattern.len()..];

        if let Some(attr_end) = remaining.find('"') {
            remaining = &remaining[attr_end + 1..];
        }
    }
    result.push_str(remaining);
    result
}

/// Extract filename from PyPI download URL.
fn extract_filename(url: &str) -> Option<&str> {
    let url = url.split('#').next()?;
    let filename = url.rsplit('/').next()?;

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

/// Find the download URL for a specific file in the HTML.
fn find_file_url(html: &str, target_filename: &str) -> Option<String> {
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        remaining = &remaining[href_start + 6..];

        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];

            if let Some(filename) = extract_filename(url) {
                if filename == target_filename {
                    return Some(url.split('#').next().unwrap_or(url).to_string());
                }
            }

            remaining = &remaining[href_end..];
        }
    }

    None
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
        let result = rewrite_pypi_links(html, "flask", "https://registry.example.com");
        assert!(result
            .contains("https://registry.example.com/simple/flask/flask-2.0.tar.gz#sha256=abc"));
    }

    #[test]
    fn test_rewrite_pypi_links_preserves_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=deadbeef">pkg</a>"#;
        let result = rewrite_pypi_links(html, "pkg", "http://localhost:4000");
        assert!(result.contains("#sha256=deadbeef"));
    }

    #[test]
    fn test_rewrite_pypi_links_unknown_ext() {
        let html = r#"<a href="https://example.com/readme.txt">readme</a>"#;
        let result = rewrite_pypi_links(html, "test", "http://localhost:4000");
        assert!(result.contains("https://example.com/readme.txt"));
    }

    #[test]
    fn test_rewrite_pypi_links_removes_metadata_attrs() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl" data-core-metadata="sha256=abc" data-dist-info-metadata="sha256=def">pkg</a>"#;
        let result = rewrite_pypi_links(html, "pkg", "http://localhost:4000");
        assert!(!result.contains("data-core-metadata"));
        assert!(!result.contains("data-dist-info-metadata"));
    }

    #[test]
    fn test_rewrite_pypi_links_empty() {
        assert_eq!(rewrite_pypi_links("", "pkg", "http://localhost:4000"), "");
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

    #[test]
    fn test_is_valid_pypi_filename() {
        assert!(is_valid_pypi_filename("flask-2.0.tar.gz"));
        assert!(is_valid_pypi_filename("flask-2.0-py3-none-any.whl"));
        assert!(is_valid_pypi_filename("flask-2.0.tgz"));
        assert!(is_valid_pypi_filename("flask-2.0.zip"));
        assert!(is_valid_pypi_filename("flask-2.0.egg"));
        assert!(!is_valid_pypi_filename(""));
        assert!(!is_valid_pypi_filename("../evil.tar.gz"));
        assert!(!is_valid_pypi_filename("evil/path.tar.gz"));
        assert!(!is_valid_pypi_filename("noext"));
        assert!(!is_valid_pypi_filename("bad.exe"));
    }

    #[test]
    fn test_wants_json_pep691() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, PEP691_JSON.parse().unwrap());
        assert!(wants_json(&headers));
    }

    #[test]
    fn test_wants_json_html() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!wants_json(&headers));
    }

    #[test]
    fn test_wants_json_no_header() {
        let headers = HeaderMap::new();
        assert!(!wants_json(&headers));
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send, send_with_headers};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_pypi_list_empty() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Simple Index"));
    }

    #[tokio::test]
    async fn test_pypi_list_with_packages() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask"));
    }

    #[tokio::test]
    async fn test_pypi_list_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["meta"]["api-version"].as_str() == Some("1.0"));
        assert!(json["projects"].as_array().unwrap().len() == 1);
    }

    #[tokio::test]
    async fn test_pypi_versions_local() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask-2.0.tar.gz"));
        // URL should contain base_url + /simple/flask/flask-2.0.tar.gz
        assert!(html.contains("/simple/flask/flask-2.0.tar.gz"));
    }

    #[tokio::test]
    async fn test_pypi_versions_with_hash() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/flask/flask-2.0.tar.gz.sha256",
                b"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("#sha256=abc123"));
    }

    #[tokio::test]
    async fn test_pypi_versions_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "flask");
        assert!(json["files"].as_array().unwrap().len() == 1);
        assert_eq!(json["files"][0]["filename"], "flask-2.0.tar.gz");
        assert_eq!(json["files"][0]["digests"]["sha256"], "deadbeef");
    }

    #[tokio::test]
    async fn test_pypi_download_local() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball-content";
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", tarball_data)
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], tarball_data);
    }

    #[tokio::test]
    async fn test_pypi_not_found_no_proxy() {
        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
