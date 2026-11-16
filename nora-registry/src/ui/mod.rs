// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
// Production code only: tests may seed storage and build a backend. The UI calls no Storage write (clippy.toml).
#![cfg_attr(not(test), deny(clippy::disallowed_methods))]

pub(crate) mod api;
pub mod components;
pub mod i18n;

mod static_assets;
mod templates;

use crate::repo_index::paginate;
use crate::tokens::Role;
use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};

use crate::auth::{AuthenticatedRole, AuthenticatedUser, MintLifetimeCeiling, NamespaceAuthority};
use api::*;
use i18n::Lang;
use templates::*;

/// Returns base URL for UI install commands.
///
/// Thin wrapper over [`ServerConfig::public_base_url`] — the single source of
/// truth for client-facing URLs.
fn resolve_base_url(state: &AppState) -> String {
    state.config.server.public_base_url()
}

#[derive(Debug, serde::Deserialize)]
struct LangQuery {
    lang: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DetailQuery {
    lang: Option<String>,
    prerelease: Option<bool>,
    all: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct ListQuery {
    lang: Option<String>,
    page: Option<usize>,
    limit: Option<usize>,
}

const DEFAULT_PAGE_SIZE: usize = 50;

fn extract_lang(query: &Query<LangQuery>, cookie_header: Option<&str>) -> Lang {
    // Priority: query param > cookie > default
    if let Some(ref lang) = query.lang {
        return Lang::from_str(lang);
    }

    // Try cookie
    if let Some(cookies) = cookie_header {
        for part in cookies.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("nora_lang=") {
                return Lang::from_str(value);
            }
        }
    }

    Lang::default()
}

fn extract_lang_from_list(query: &ListQuery, cookie_header: Option<&str>) -> Lang {
    if let Some(ref lang) = query.lang {
        return Lang::from_str(lang);
    }

    if let Some(cookies) = cookie_header {
        for part in cookies.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("nora_lang=") {
                return Lang::from_str(value);
            }
        }
    }

    Lang::default()
}

fn extract_lang_from_headers(headers: &axum::http::HeaderMap) -> Lang {
    // Try cookie
    if let Some(cookies) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookies.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("nora_lang=") {
                return Lang::from_str(value);
            }
        }
    }
    Lang::default()
}

/// The UI router: pages and the HTMX fragment endpoints under `/api/ui`.
pub fn routes() -> Router<AppState> {
    Router::new()
        // UI Pages
        .route("/", get(|| async { Redirect::to("/ui/") }))
        .route("/ui", get(|| async { Redirect::to("/ui/") }))
        .route("/ui/", get(dashboard))
        .route("/ui/docker", get(docker_list))
        .route("/ui/docker/{name}", get(docker_detail))
        .route("/ui/maven", get(maven_list))
        .route("/ui/maven/{*path}", get(maven_detail))
        .route("/ui/npm", get(npm_list))
        .route("/ui/npm/{name}", get(npm_detail))
        .route("/ui/cargo", get(cargo_list))
        .route("/ui/cargo/{name}", get(cargo_detail))
        .route("/ui/pypi", get(pypi_list))
        .route("/ui/pypi/{name}", get(pypi_detail))
        .route("/ui/go", get(go_list))
        .route("/ui/go/{*name}", get(go_detail))
        .route("/ui/raw", get(raw_list))
        .route("/ui/raw/{*name}", get(raw_detail))
        // New registries (v0.7 — generic list pages)
        .route("/ui/gems", get(generic_registry_list))
        .route("/ui/terraform", get(generic_registry_list))
        .route("/ui/ansible", get(ansible_browse_root))
        .route("/ui/ansible/{*path}", get(ansible_browse))
        .route("/ui/nuget", get(generic_registry_list))
        .route("/ui/nuget/{name}", get(generic_registry_detail))
        .route("/ui/pub", get(generic_registry_list))
        .route("/ui/pub/{name}", get(generic_registry_detail))
        .route("/ui/conan", get(generic_registry_list))
        .route("/ui/conan/{name}", get(generic_registry_detail))
        .route("/ui/rpm", get(generic_registry_list))
        .route("/ui/rpm/{name}", get(generic_registry_detail))
        .route("/ui/deb", get(generic_registry_list))
        .route("/ui/deb/{name}", get(generic_registry_detail))
        .route("/ui/cpan", get(cpan_browse_root))
        .route("/ui/cpan/{*path}", get(cpan_browse))
        .route("/ui/composer", get(generic_registry_list))
        .route("/ui/composer/{*name}", get(composer_detail))
        .route("/ui/hf", get(generic_registry_list))
        .route("/ui/hf/{*name}", get(hf_detail))
        .route("/ui/gems/{name}", get(generic_registry_detail))
        .route("/ui/terraform/{name}", get(generic_registry_detail))
        // Token management UI (protected by auth middleware)
        .route("/ui/tokens", get(tokens_page))
        // Token management API (HTMX endpoints)
        .route("/api/ui/tokens/create", post(tokens_create))
        .route("/api/ui/tokens/list", get(tokens_list))
        .route("/api/ui/tokens/{file_id}/revoke", post(tokens_revoke))
        // Static assets (embedded)
        .route(
            "/ui/static/tailwind.css",
            get(static_assets::serve_tailwind_css),
        )
        .route("/ui/static/htmx.min.js", get(static_assets::serve_htmx_js))
        // API endpoints for HTMX
        .route("/api/ui/stats", get(api_stats))
        .route("/api/ui/dashboard", get(api_dashboard))
        .route("/api/ui/{registry_type}/list", get(api_list))
        .route("/api/ui/{registry_type}/{name}", get(api_detail))
        .route("/api/ui/{registry_type}/search", get(api_search))
}

/// Prefix NORA's root-absolute UI self-links with `base` so the UI works when
/// NORA is mounted under a sub-path. Anchored on the quote that opens an HTML
/// attribute or JS string, so only emitted links (`href`/`src`/`hx-*`/`fetch(`)
/// are rewritten — never a link-like substring in page text. No-op when empty.
fn apply_base_path(html: &str, base: &str) -> String {
    if base.is_empty() {
        return html.to_string();
    }
    html.replace("\"/ui", &format!("\"{base}/ui"))
        .replace("'/ui", &format!("'{base}/ui"))
        .replace("\"/api/ui", &format!("\"{base}/api/ui"))
        .replace("'/api/ui", &format!("'{base}/api/ui"))
        // The API-docs (Swagger UI) entry link in the nav and the root-absolute
        // spec URL the Swagger initializer embeds ("/api-docs/openapi.json").
        .replace("\"/api-docs", &format!("\"{base}/api-docs"))
        .replace("'/api-docs", &format!("'{base}/api-docs"))
}

/// Response middleware: rewrite the UI's root-absolute self-links to carry the
/// configured `public_url` path prefix. Covers HTML bodies (links + inline JS
/// `fetch`), the Swagger UI initializer's spec URL, and redirect `Location`
/// headers. A no-op when `base_path` is empty (the router keeps serving `/ui`,
/// `/api/ui` and `/api-docs`; the proxy strips the prefix).
pub(crate) async fn rewrite_ui_base_path(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let base = state.config.server.base_path();
    // Capture the path before the request is consumed: the Swagger initializer
    // is served as JS (not HTML) yet embeds a root-absolute spec URL that needs
    // the same prefix, so it is rewritten by path rather than by content type.
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    if base.is_empty() {
        return resp;
    }
    // A redirect target (e.g. "/" -> "/ui/", "/api-docs" -> "/api-docs/") must
    // carry the prefix too.
    if let Some(loc) = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
    {
        if (loc.starts_with("/ui") || loc.starts_with("/api/ui") || loc.starts_with("/api-docs"))
            && !loc.starts_with(&base)
        {
            if let Ok(hv) = HeaderValue::from_str(&format!("{base}{loc}")) {
                resp.headers_mut().insert(header::LOCATION, hv);
            }
        }
    }
    let is_html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.contains("text/html"));
    // The Swagger UI initializer is JS but embeds a root-absolute spec URL
    // ("/api-docs/openapi.json"); rewrite it too so the docs load under a
    // sub-path. Scoped to that one small file — large JS bundles pass through.
    let is_swagger_init = path.ends_with("/swagger-initializer.js");
    if !is_html && !is_swagger_init {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let rewritten = apply_base_path(&String::from_utf8_lossy(&bytes), &base);
    // The body length changed; drop the stale Content-Length so it is recomputed.
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(rewritten))
}

// Dashboard page
async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
    user: Option<Extension<AuthenticatedUser>>,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();
    let authenticated = user.map(|Extension(u)| u.0 != "anonymous").unwrap_or(false);
    let response = build_dashboard_response(&state, authenticated).await;
    // Offer sign-in only to a caller who can sign in and has not.
    let can_sign_in = auth_enabled && !authenticated;
    Html(render_dashboard(&response, lang, auth_enabled, can_sign_in))
}

// Docker pages
async fn docker_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_repos = state.repo_index.get("docker", &state.storage).await;
    let (repos, total) = paginate(&all_repos, page, limit);

    Html(render_registry_list_paginated(
        "docker",
        "Docker Registry",
        &repos,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn docker_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    let detail = get_docker_detail(&state, &name).await;
    Html(render_docker_detail(
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// Maven pages
async fn maven_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let auth_enabled = state.auth.is_some();

    // Show top-level namespace directories (com, org, io, etc.)
    let index = state.repo_index.get("maven", &state.storage).await;
    let (entries, _) = api::maven_dir_listing(&index, "");
    let total = entries.len();

    Html(templates::render_maven_dir(
        "",
        &entries,
        total,
        lang,
        auth_enabled,
    ))
}

async fn maven_detail(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();

    // Try hierarchical browsing: check if this is a directory or leaf artifact
    let index = state.repo_index.get("maven", &state.storage).await;
    let (entries, is_leaf) = api::maven_dir_listing(&index, &path);

    if is_leaf || entries.is_empty() {
        // Leaf artifact — show files (JARs, POMs, etc.)
        let detail = get_maven_detail(&state.storage, &path).await;
        Html(render_maven_detail(&path, &detail, lang, auth_enabled))
    } else {
        // Namespace directory — show children
        let total = entries.len();
        Html(templates::render_maven_dir(
            &path,
            &entries,
            total,
            lang,
            auth_enabled,
        ))
    }
}

// npm pages
async fn npm_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_packages = state.repo_index.get("npm", &state.storage).await;
    let (packages, total) = paginate(&all_packages, page, limit);

    Html(render_registry_list_paginated(
        "npm",
        "npm Registry",
        &packages,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn npm_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    let show_prerelease = query.prerelease.unwrap_or(false);
    let show_all = query.all.unwrap_or(false);
    let detail = get_npm_detail(&state.storage, &name, show_prerelease, show_all).await;
    Html(render_package_detail(
        "npm",
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// Cargo pages
async fn cargo_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_crates = state.repo_index.get("cargo", &state.storage).await;
    let (crates, total) = paginate(&all_crates, page, limit);

    Html(render_registry_list_paginated(
        "cargo",
        "Cargo Registry",
        &crates,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn cargo_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    let show_prerelease = query.prerelease.unwrap_or(false);
    let show_all = query.all.unwrap_or(false);
    let detail = get_cargo_detail(&state.storage, &name, show_prerelease, show_all).await;
    Html(render_package_detail(
        "cargo",
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// PyPI pages
async fn pypi_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_packages = state.repo_index.get("pypi", &state.storage).await;
    let (packages, total) = paginate(&all_packages, page, limit);

    Html(render_registry_list_paginated(
        "pypi",
        "PyPI Repository",
        &packages,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn pypi_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    let show_prerelease = query.prerelease.unwrap_or(false);
    let show_all = query.all.unwrap_or(false);
    let detail = get_pypi_detail(&state.storage, &name, show_prerelease, show_all).await;
    Html(render_package_detail(
        "pypi",
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// Go pages
async fn go_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let auth_enabled = state.auth.is_some();

    // Show top-level namespace directories (github.com, golang.org, etc.)
    let (entries, _) = api::get_go_dir_listing(&state.storage, "").await;
    let total = entries.len();

    Html(templates::render_go_dir(
        "",
        &entries,
        total,
        lang,
        auth_enabled,
    ))
}

async fn go_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let auth_enabled = state.auth.is_some();

    // Try hierarchical browsing: check if this is a directory or leaf module
    let (entries, is_leaf) = api::get_go_dir_listing(&state.storage, &name).await;

    if is_leaf || entries.is_empty() {
        // Leaf module — show version detail page
        let base_url = resolve_base_url(&state);
        let show_prerelease = query.prerelease.unwrap_or(false);
        let show_all = query.all.unwrap_or(false);
        let detail = get_go_detail(&state.storage, &name, show_prerelease, show_all).await;
        Html(render_package_detail(
            "go",
            &name,
            &detail,
            lang,
            &base_url,
            auth_enabled,
        ))
    } else {
        // Namespace directory — show children
        let total = entries.len();
        Html(templates::render_go_dir(
            &name,
            &entries,
            total,
            lang,
            auth_enabled,
        ))
    }
}

// Raw pages
async fn raw_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_files = state.repo_index.get("raw", &state.storage).await;
    let (files, total) = paginate(&all_files, page, limit);

    Html(render_registry_list_paginated(
        "raw",
        "Raw Storage",
        &files,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn raw_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();

    // Check if this path is a directory (has children) or a single file
    let (entries, is_dir) = api::get_raw_dir_listing(&state.storage, &name).await;

    if is_dir && !entries.is_empty() {
        // Directory with children — render as browsable folder listing
        let total = entries.len();
        Html(templates::render_raw_dir(
            &name,
            &entries,
            total,
            lang,
            auth_enabled,
        ))
    } else {
        // Single file or leaf directory — render detail page
        let detail = api::get_raw_detail(&state.storage, &name).await;
        Html(templates::render_package_detail(
            "raw",
            &name,
            &detail,
            lang,
            &base_url,
            auth_enabled,
        ))
    }
}

// Generic registry list handler for new formats (v0.7)
async fn generic_registry_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    // Extract registry type from URI path: /ui/{type}
    let registry_key = uri.path().strip_prefix("/ui/").unwrap_or("raw");
    let title = match crate::registry_type::RegistryType::from_str_opt(registry_key) {
        Some(crate::registry_type::RegistryType::Gems) => "RubyGems",
        Some(crate::registry_type::RegistryType::Terraform) => "Terraform Registry",
        Some(crate::registry_type::RegistryType::Ansible) => "Ansible Galaxy",
        Some(crate::registry_type::RegistryType::Nuget) => "NuGet Gallery",
        Some(crate::registry_type::RegistryType::PubDart) => "Pub (Dart/Flutter)",
        Some(crate::registry_type::RegistryType::Conan) => "Conan (C/C++)",
        Some(crate::registry_type::RegistryType::Rpm) => "RPM (yum/dnf)",
        Some(crate::registry_type::RegistryType::Deb) => "Debian (APT)",
        Some(crate::registry_type::RegistryType::Cpan) => "CPAN",
        Some(crate::registry_type::RegistryType::Composer) => "Composer (PHP)",
        Some(crate::registry_type::RegistryType::HuggingFace) => "Hugging Face Hub",
        _ => registry_key,
    };

    let all_items = state.repo_index.get(registry_key, &state.storage).await;
    let (items, total) = paginate(&all_items, page, limit);

    Html(render_registry_list_paginated(
        registry_key,
        title,
        &items,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn generic_registry_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    let show_prerelease = query.prerelease.unwrap_or(false);
    let show_all = query.all.unwrap_or(false);

    // Extract registry type from URI: /ui/{type}/{name}
    let registry_key = uri
        .path()
        .strip_prefix("/ui/")
        .and_then(|s| s.split('/').next())
        .unwrap_or("raw");

    let detail = get_generic_detail(
        &state.storage,
        registry_key,
        &name,
        show_prerelease,
        show_all,
    )
    .await;
    Html(render_package_detail(
        registry_key,
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// CPAN hierarchical browsing (author prefix → author → distribution)
async fn cpan_browse_root(
    State(state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();

    let entries = api::get_cpan_dir_listing(&state.storage, "").await;
    let total = entries.len();

    Html(templates::render_cpan_dir(
        "",
        &entries,
        total,
        lang,
        auth_enabled,
    ))
}

async fn cpan_browse(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let auth_enabled = state.auth.is_some();

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match segments.len() {
        // /ui/cpan/L or /ui/cpan/LC or /ui/cpan/LCONS → list directory contents
        0..=3 => {
            let entries = api::get_cpan_dir_listing(&state.storage, &path).await;
            let total = entries.len();
            Html(templates::render_cpan_dir(
                &path,
                &entries,
                total,
                lang,
                auth_enabled,
            ))
            .into_response()
        }
        // Preserve old file-shaped links, but make the distribution URL
        // canonical so all cached releases share one detail page.
        _ => {
            let filename = path.rsplit('/').next().unwrap_or(&path);
            if let Some((distribution, _)) =
                crate::registry::cpan::parse_dist_archive_filename(filename)
            {
                let author_path = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                let encoded_author_path = author_path
                    .split('/')
                    .map(templates::encode_uri_component)
                    .collect::<Vec<_>>()
                    .join("/");
                let location = format!(
                    "/ui/cpan/{}/{}",
                    encoded_author_path,
                    templates::encode_uri_component(&distribution)
                );
                return Redirect::permanent(&location).into_response();
            }

            let base_url = resolve_base_url(&state);
            let show_prerelease = query.prerelease.unwrap_or(false);
            let show_all = query.all.unwrap_or(false);
            let detail =
                api::get_cpan_detail(&state.storage, &path, show_prerelease, show_all).await;
            Html(templates::render_package_detail(
                "cpan",
                &path,
                &detail,
                lang,
                &base_url,
                auth_enabled,
            ))
            .into_response()
        }
    }
}

// Composer detail: a package is `vendor/package`, linked with its slash encoded or not
async fn composer_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let valid = name.split_once('/').is_some_and(|(vendor, package)| {
        crate::registry::composer::is_valid_package_name(vendor, package)
    });
    if !valid {
        return StatusCode::NOT_FOUND.into_response();
    }
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();
    let detail = api::get_composer_detail(&state.storage, &name).await;
    Html(templates::render_composer_detail(
        &name,
        &detail,
        lang,
        auth_enabled,
    ))
    .into_response()
}

// Hugging Face detail: a repository id is `name` or `org/name`, linked with its slash encoded
// or not; the page lists the files NORA has cached for it.
async fn hf_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(detail) = api::get_hf_detail(&state.storage, &name).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();
    Html(templates::render_package_detail(
        "hf",
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
    .into_response()
}

// Ansible Galaxy hierarchical browsing (namespace → collection → versions)
async fn ansible_browse_root(
    State(state): State<AppState>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();

    let entries = api::get_ansible_namespace_listing(&state.storage, "").await;
    let total = entries.len();

    Html(templates::render_ansible_dir(
        "",
        &entries,
        total,
        lang,
        auth_enabled,
    ))
}

async fn ansible_browse(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Query(query): Query<DetailQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = {
        let lang_q = LangQuery {
            lang: query.lang.clone(),
        };
        extract_lang(
            &Query(lang_q),
            headers.get("cookie").and_then(|v| v.to_str().ok()),
        )
    };
    let auth_enabled = state.auth.is_some();

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match segments.len() {
        // /ui/ansible/community → list collections in namespace
        1 => {
            let entries = api::get_ansible_namespace_listing(&state.storage, &path).await;
            let total = entries.len();
            Html(templates::render_ansible_dir(
                &path,
                &entries,
                total,
                lang,
                auth_enabled,
            ))
        }
        // /ui/ansible/community/general → version detail
        2 => {
            let base_url = resolve_base_url(&state);
            let show_prerelease = query.prerelease.unwrap_or(false);
            let show_all = query.all.unwrap_or(false);
            let full_name = format!("{}.{}", segments[0], segments[1]);
            let detail = get_generic_detail(
                &state.storage,
                "ansible",
                &full_name,
                show_prerelease,
                show_all,
            )
            .await;
            Html(render_package_detail(
                "ansible",
                &full_name,
                &detail,
                lang,
                &base_url,
                auth_enabled,
            ))
        }
        // Deeper paths: 404
        _ => Html(templates::render_ansible_dir(
            &path,
            &[],
            0,
            lang,
            auth_enabled,
        )),
    }
}

// ==================== Token Management Handlers ====================

/// Token management page (GET /ui/tokens)
async fn tokens_page(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_headers(&headers);

    // Owner-scope: non-admins see only their own tokens; admins see all
    // (GHSA-78cx-cfhm-rgmx — cross-user token enumeration).
    let tokens = match &state.tokens {
        Some(store) if role.0.can_admin() => store.list_all_tokens(),
        Some(store) => store.list_tokens(&user.0),
        None => vec![],
    };

    Html(render_tokens_page(&tokens, lang, true))
}

/// Create token (POST /api/ui/tokens/create)
#[derive(serde::Deserialize)]
struct CreateTokenForm {
    description: String,
    role: String,
    ttl_days: Option<u64>,
}

/// Why a UI token-mint request is refused. One variant per refusal branch so
/// the error text cannot drift from the reason it reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UiMintRefusal {
    /// An admin token was requested by a caller who cannot admin.
    AdminRequiresAdmin,
    /// The caller's identity is namespace-scoped; the UI mints only unrestricted
    /// opaque tokens, so handing one out would widen the caller's authority.
    ScopedCannotMintUnrestricted,
    /// The caller's credential has expired (an OIDC JWT still inside the
    /// validator's leeway): a token from it would outlive it at once.
    CredentialExpired,
}

impl UiMintRefusal {
    fn message(self) -> &'static str {
        match self {
            UiMintRefusal::AdminRequiresAdmin => {
                "An admin token may be minted only by an admin identity"
            }
            UiMintRefusal::ScopedCannotMintUnrestricted => {
                "A namespace-scoped identity cannot mint an unrestricted token"
            }
            UiMintRefusal::CredentialExpired => {
                "The credential has expired; a token minted from it would outlive it"
            }
        }
    }
}

/// Decide the role of a UI-minted token, or refuse — pure: no I/O, no state.
///
/// A UI-minted opaque (`nra_`) token is always role-only and namespace-
/// *unrestricted* (`auth::namespace`): it carries no scope. So two invariants
/// must hold before one is handed out (#1094, GHSA-78cx-cfhm-rgmx class):
///
/// * an admin token may be minted only by a caller who `can_admin()` — a write
///   identity must not mint admin; and
/// * a namespace-*scoped* caller must not mint one at all — an identity limited
///   to `ci-transport/**` would otherwise obtain an unrestricted token and write
///   to `prod/`, escalating past its own scope.
///
/// The POST write-method gate in the auth middleware already bounds callers that
/// reach this path to write-or-admin, so a read caller cannot mint write here;
/// the admin check is kept as defence in depth. Table-tested in this module's
/// tests — this replaces an inline gate that a regression could slip past.
fn decide_ui_token_mint(
    caller_role: Role,
    caller_authority: &NamespaceAuthority,
    requested_role: Role,
) -> Result<Role, UiMintRefusal> {
    if requested_role == Role::Admin && !caller_role.can_admin() {
        return Err(UiMintRefusal::AdminRequiresAdmin);
    }
    if caller_authority.is_scoped() {
        return Err(UiMintRefusal::ScopedCannotMintUnrestricted);
    }
    Ok(requested_role)
}

async fn tokens_create(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthenticatedUser>,
    Extension(caller_role): Extension<AuthenticatedRole>,
    Extension(caller_authority): Extension<NamespaceAuthority>,
    caller_mint_ceiling: Option<Extension<MintLifetimeCeiling>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<CreateTokenForm>,
) -> impl IntoResponse {
    // CSRF check: require HX-Request header (HTMX sets this automatically)
    if headers.get("hx-request").is_none() {
        return (StatusCode::FORBIDDEN, Html("Forbidden".to_string()));
    }

    let lang = extract_lang_from_headers(&headers);

    let store = match &state.tokens {
        Some(store) => store,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Token store not configured".to_string()),
            );
        }
    };

    // The owner is the authenticated caller — the token owner on the Basic-token
    // path (#1094), NOT the forgeable Basic-header username.
    let user = caller.0;

    let requested_role = match form.role.as_str() {
        "read" => Role::Read,
        "write" => Role::Write,
        "admin" => Role::Admin,
        _ => Role::Read,
    };
    // Who may mint what is a pure decision over the caller's role AND namespace
    // authority (#1094) — kept in `decide_ui_token_mint` with a unit
    // table, because an inline gate here could let a regression slip the owner
    // source and the admin-by-name check past the tests.
    let granted_role = match decide_ui_token_mint(caller_role.0, &caller_authority, requested_role)
    {
        Ok(role) => role,
        Err(refusal) => {
            return (
                StatusCode::FORBIDDEN,
                Html(format!(
                    r##"<div class="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-400">{}</div>"##,
                    refusal.message()
                )),
            );
        }
    };

    let lifetime = crate::tokens::MintLifetime::days(
        form.ttl_days.unwrap_or(90).max(1),
        caller_mint_ceiling.map(|Extension(MintLifetimeCeiling(secs))| secs),
    );
    // Nothing left of the caller's credential: fail closed, mint nothing.
    if lifetime.secs() == 0 {
        return (
            StatusCode::FORBIDDEN,
            Html(format!(
                r##"<div class="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-400">{}</div>"##,
                UiMintRefusal::CredentialExpired.message()
            )),
        );
    }

    let description = if form.description.trim().is_empty() {
        None
    } else {
        Some(form.description.trim().to_string())
    };

    match store.mint_token(&user, lifetime, description, granted_role) {
        Ok(minted) => {
            state.audit.log(crate::audit::AuditEntry::token_mint(
                &user,
                "ui",
                &minted.owner,
                &minted.role,
                minted.ttl_secs,
            ));
            let html = render_token_created_fragment(&minted.token, lang);
            (StatusCode::OK, Html(html))
        }
        Err(e) => {
            let html = format!(
                r##"<div class="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-400">Error: {}</div>"##,
                components::html_escape(&e.to_string())
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Html(html))
        }
    }
}

/// List tokens HTMX fragment (GET /api/ui/tokens/list)
async fn tokens_list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_headers(&headers);

    // Owner-scope: non-admins see only their own tokens; admins see all
    // (GHSA-78cx-cfhm-rgmx — cross-user token enumeration).
    let tokens = match &state.tokens {
        Some(store) if role.0.can_admin() => store.list_all_tokens(),
        Some(store) => store.list_tokens(&user.0),
        None => vec![],
    };

    Html(render_token_list_fragment(&tokens, lang))
}

/// Revoke token (POST /api/ui/tokens/{file_id}/revoke)
async fn tokens_revoke(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // CSRF check
    if headers.get("hx-request").is_none() {
        return (StatusCode::FORBIDDEN, Html("Forbidden".to_string()));
    }

    // Validate file_id: must be exactly 16 hex chars (path traversal prevention)
    if file_id.len() != 16 || !file_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Html("Invalid token ID".to_string()),
        );
    }

    let lang = extract_lang_from_headers(&headers);

    let store = match &state.tokens {
        Some(store) => store,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("Token store not configured".to_string()),
            );
        }
    };

    // Owner-scope: non-admins may revoke only their own tokens. Return 404 (not
    // 403) so a non-owner cannot probe which token IDs exist
    // (GHSA-78cx-cfhm-rgmx — cross-user token revocation).
    let is_admin = role.0.can_admin();
    if !is_admin
        && !store
            .list_tokens(&user.0)
            .iter()
            .any(|t| t.file_id == file_id)
    {
        return (StatusCode::NOT_FOUND, Html("Token not found".to_string()));
    }

    match store.revoke_token(&file_id).await {
        Ok(()) => {
            // Return refreshed token list (same owner-scope as the list view)
            let tokens = if is_admin {
                store.list_all_tokens()
            } else {
                store.list_tokens(&user.0)
            };
            (
                StatusCode::OK,
                Html(render_token_list_fragment(&tokens, lang)),
            )
        }
        Err(crate::tokens::TokenError::NotFound) => {
            (StatusCode::NOT_FOUND, Html("Token not found".to_string()))
        }
        Err(e) => {
            let html = format!(
                r##"<div class="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-400">Error: {}</div>"##,
                components::html_escape(&e.to_string())
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Html(html))
        }
    }
}

#[cfg(test)]
mod base_path_tests {
    use super::*;

    #[test]
    fn apply_base_path_is_noop_when_empty() {
        let html = r#"<a href="/ui/docker">d</a><script src="/ui/static/x.js"></script>"#;
        assert_eq!(apply_base_path(html, ""), html);
    }

    #[test]
    fn apply_base_path_prefixes_ui_and_api_links() {
        let html = concat!(
            r#"<link href="/ui/static/tailwind.css">"#,
            r#"<a href="/ui/docker">d</a>"#,
            r#"<script>fetch('/api/ui/dashboard')</script>"#,
            r#"<form action="/api/ui/tokens/create">"#,
        );
        let out = apply_base_path(html, "/nora");
        assert!(out.contains(r#"href="/nora/ui/static/tailwind.css""#));
        assert!(out.contains(r#"href="/nora/ui/docker""#));
        assert!(out.contains("fetch('/nora/api/ui/dashboard')"));
        assert!(out.contains(r#"action="/nora/api/ui/tokens/create""#));
        // No leftover bare links, no double-prefix.
        assert!(!out.contains(r#"href="/ui/"#));
        assert!(!out.contains("fetch('/api/ui"));
        assert!(!out.contains("/nora/nora/"));
    }

    #[test]
    fn apply_base_path_prefixes_api_docs_link_and_spec_url() {
        // The "API Docs" nav link (HTML) and the Swagger initializer's embedded
        // spec URL (JS) are both root-absolute /api-docs paths that break under a
        // sub-path unless prefixed. Regression guard for the #686 residual.
        let html = r#"<a href="/api-docs" title="API Docs">d</a>"#;
        let init = r#"window.ui = SwaggerUIBundle({ "url": "/api-docs/openapi.json" });"#;
        assert!(apply_base_path(html, "/nora").contains(r#"href="/nora/api-docs""#));
        let out = apply_base_path(init, "/nora");
        assert!(out.contains(r#""url": "/nora/api-docs/openapi.json""#));
        assert!(!out.contains(r#""/api-docs/openapi.json""#));
        // Empty base is still a no-op for the api-docs paths.
        assert_eq!(apply_base_path(html, ""), html);
    }

    #[test]
    fn apply_base_path_leaves_non_link_text_untouched() {
        // A link-like substring not anchored on an attribute/JS quote (e.g. in
        // body text) is not a self-link and must not be rewritten.
        let html = r#"<p>the path /ui/docker is shown</p>"#;
        assert_eq!(apply_base_path(html, "/nora"), html);
    }

    /// A namespace-scoped authority, as an OIDC identity limited to
    /// `ci-transport/**` carries.
    fn scoped_authority() -> NamespaceAuthority {
        let scope = vec!["ci-transport/**".to_string()];
        NamespaceAuthority::from_oidc_scopes(
            "test-ci",
            std::iter::once(scope.as_slice()),
            crate::config::ScopeEnforcement::Enforce,
        )
    }

    /// #1094: the UI mint decision, as a table. This is the acceptance
    /// test — an inline gate was slipped twice (owner source,
    /// admin-by-name), so the decision is a pure function verified exhaustively
    /// here rather than through an integration regex.
    #[test]
    fn decide_ui_token_mint_table() {
        use crate::tokens::Role::{Admin, Read, Write};
        let open = NamespaceAuthority::Unrestricted;
        let scoped = scoped_authority();
        assert!(scoped.is_scoped());
        assert!(!open.is_scoped());

        // Unrestricted admin caller: mints any role.
        assert_eq!(decide_ui_token_mint(Admin, &open, Admin), Ok(Admin));
        assert_eq!(decide_ui_token_mint(Admin, &open, Write), Ok(Write));
        assert_eq!(decide_ui_token_mint(Admin, &open, Read), Ok(Read));

        // Unrestricted write caller: read/write ok, admin refused by role.
        assert_eq!(decide_ui_token_mint(Write, &open, Write), Ok(Write));
        assert_eq!(decide_ui_token_mint(Write, &open, Read), Ok(Read));
        assert_eq!(
            decide_ui_token_mint(Write, &open, Admin),
            Err(UiMintRefusal::AdminRequiresAdmin)
        );
        // Defence in depth: a read caller (stopped earlier by the POST
        // write-method gate) is still refused an admin token here.
        assert_eq!(
            decide_ui_token_mint(Read, &open, Admin),
            Err(UiMintRefusal::AdminRequiresAdmin)
        );

        // Scoped caller: refused for every role it could request — handing out
        // an unrestricted token would widen its authority (the scope escape).
        assert_eq!(
            decide_ui_token_mint(Write, &scoped, Write),
            Err(UiMintRefusal::ScopedCannotMintUnrestricted)
        );
        assert_eq!(
            decide_ui_token_mint(Write, &scoped, Read),
            Err(UiMintRefusal::ScopedCannotMintUnrestricted)
        );
        assert_eq!(
            decide_ui_token_mint(Admin, &scoped, Admin),
            Err(UiMintRefusal::ScopedCannotMintUnrestricted)
        );
        // A scoped non-admin requesting admin is refused either way.
        assert!(decide_ui_token_mint(Write, &scoped, Admin).is_err());

        // The refusal text matches its branch (no drift).
        assert!(UiMintRefusal::AdminRequiresAdmin
            .message()
            .contains("admin"));
        assert!(UiMintRefusal::ScopedCannotMintUnrestricted
            .message()
            .contains("scoped"));
    }
}

/// The Composer pages: a list of `vendor/package` names, and a detail page per package whose
/// versions say whether NORA hosts them or cached them.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod composer_pages {
    use crate::registry::composer::build_test_zip;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};

    fn ctx() -> TestContext {
        create_test_context_with_config(|c| c.composer.enabled = true)
    }

    async fn page(ctx: &TestContext, uri: &str) -> (StatusCode, String) {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn upload(ctx: &TestContext, name: &str, version: &str) {
        let manifest = serde_json::json!({"name": name}).to_string();
        let zip = build_test_zip(&[("composer.json", manifest.as_bytes(), false)]);
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/composer/packages/upload/{name}/{version}"),
            zip,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn an_uploaded_package_is_listed_and_has_a_page_of_hosted_versions() {
        let ctx = ctx();
        upload(&ctx, "acme/greeter", "1.0.0").await;
        upload(&ctx, "acme/greeter", "1.1.0").await;

        let (status, list) = page(&ctx, "/ui/composer").await;
        assert_eq!(status, StatusCode::OK);
        assert!(list.contains("Composer (PHP)"));
        assert!(
            list.contains(">acme/greeter</a>"),
            "the list names the package"
        );
        assert!(list.contains(r#"hx-get="/api/ui/composer/search""#));

        // The list links the name as the client would write it, with the slash encoded: the
        // page answers to that link and to the plain one alike.
        let (_, search) = page(&ctx, "/api/ui/composer/search?q=greet").await;
        assert!(search.contains("/ui/composer/acme%2Fgreeter"));
        for uri in ["/ui/composer/acme/greeter", "/ui/composer/acme%2Fgreeter"] {
            let (status, html) = page(&ctx, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(html.contains("composer require acme/greeter"), "{uri}");
            for version in ["1.0.0", "1.1.0"] {
                assert!(
                    html.contains(&format!(r#"data-version="{version}""#)),
                    "{uri}: no row for {version}"
                );
            }
            assert!(
                html.contains(">hosted<") && !html.contains(">cached<"),
                "{uri}"
            );
            assert!(html.contains("(2 total)"), "{uri}");
        }
    }

    #[tokio::test]
    async fn a_cached_archive_is_a_cached_version() {
        let ctx = ctx();
        ctx.state
            .storage
            .put("composer/dists/acme/lib/2.3.4/aaaa.zip", b"PK")
            .await
            .unwrap();
        let (status, html) = page(&ctx, "/ui/composer/acme/lib").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(r#"data-version="2.3.4""#));
        assert!(html.contains(">cached<") && !html.contains(">hosted<"));
    }

    #[tokio::test]
    async fn a_package_nora_holds_nothing_of_has_an_empty_page() {
        let ctx = ctx();
        let (status, html) = page(&ctx, "/ui/composer/acme/none").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("composer require acme/none"));
        assert!(!html.contains("version-row"));
    }

    #[tokio::test]
    async fn only_a_package_name_has_a_page() {
        let ctx = ctx();
        for uri in [
            "/ui/composer/acme",
            "/ui/composer/acme/greeter/extra",
            "/ui/composer/Acme/Greeter",
            "/ui/composer/acme/gree%20ter",
            "/ui/composer/acme/..",
            "/ui/composer/acme/",
            "/ui/composer/%2F",
        ] {
            let (status, _) = page(&ctx, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
    }
}

#[cfg(test)]
/// #1172: a UI page that lists stored files takes their size and time from the listing
/// that names them. On an object store every `stat` is one HEAD request, sent one after
/// another, so a page that stats each listed file costs a request per stored version.
mod listing_cost_tests {
    use super::api::{
        get_cargo_detail, get_generic_detail, get_go_detail, get_go_dir_listing, get_npm_detail,
        get_pypi_detail, get_raw_detail, get_raw_dir_listing, PackageDetail,
    };
    use crate::repo_index::RepoInfo;
    use crate::storage::Storage;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage, op_counting_storage, send,
    };
    use axum::http::{Method, StatusCode};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    /// Stored files of every page under test, `n` versions of each package: key and length.
    /// Lengths differ per file, so a page that shows one file's size for another shows it.
    fn layout(n: usize) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let sized = |key: String, len: usize| (key, vec![b'x'; len]);

        // Go: one module with `n` cached versions and one more its list names but not cached,
        // and two more modules for the namespace pages.
        let mut list = String::new();
        for k in 0..n {
            list.push_str(&format!("v1.{k}.0\n"));
            files.push(sized(
                format!("go/github.com/acme/mod/@v/v1.{k}.0.zip"),
                500 + k,
            ));
            files.push(sized(
                format!("go/github.com/acme/mod/@v/v1.{k}.0.mod"),
                10 + k,
            ));
        }
        list.push_str("v2.0.0\n");
        files.push((
            "go/github.com/acme/mod/@v/list".to_string(),
            list.into_bytes(),
        ));
        files.push(sized(
            "go/github.com/acme/lib/@v/v0.1.0.zip".to_string(),
            700,
        ));
        files.push(sized(
            "go/golang.org/x/text/@v/v0.20.0.zip".to_string(),
            900,
        ));

        // npm: a packument naming `n` versions with stored tarballs and one without, and a
        // stored tarball the packument does not name.
        let mut versions = serde_json::Map::new();
        let mut time = serde_json::Map::new();
        for k in 0..n {
            let v = format!("1.0.{k}");
            versions.insert(v.clone(), json!({"dist": {"unpackedSize": 5}}));
            time.insert(v.clone(), json!("2026-01-02T03:04:05.000Z"));
            files.push(sized(format!("npm/pkg/tarballs/pkg-{v}.tgz"), 2000 + k));
        }
        versions.insert("2.0.0".to_string(), json!({"dist": {"unpackedSize": 77}}));
        time.insert("2.0.0".to_string(), json!("2026-03-04T05:06:07.000Z"));
        files.push(sized("npm/pkg/tarballs/pkg-3.0.0.tgz".to_string(), 3000));
        files.push((
            "npm/pkg/metadata.json".to_string(),
            serde_json::to_vec(&json!({"versions": versions, "time": time})).unwrap(),
        ));

        for k in 0..n {
            files.push(sized(
                format!("cargo/serde/1.0.{k}/serde-1.0.{k}.crate"),
                3100 + k,
            ));
            files.push(sized(
                format!("pypi/requests/requests-2.0.{k}.tar.gz"),
                3200 + k,
            ));
            files.push(sized(format!("conan/zlib/1.{k}.0/_/_/revisions.json"), 30));
            files.push(sized(
                format!("conan/zlib/1.{k}.0/_/_/rrev/export/conanfile.py"),
                3300 + k,
            ));
            files.push(sized(
                format!("pub/packages/http/versions/1.0.{k}.tar.gz"),
                3400 + k,
            ));
            files.push(sized(
                format!("pub/packages/http/versions/1.0.{k}.tar.gz.sha256"),
                64,
            ));
            files.push(sized(
                format!("ansible/download/community-general-1.0.{k}.tar.gz"),
                3500 + k,
            ));
            files.push(sized(format!("terraform/aws/5.0.{k}.zip"), 3600 + k));
            files.push(sized(format!("raw/tools/file-{k}.bin"), 3700 + k));
            files.push(sized(format!("raw/tools/sub/part-{k}.bin"), 3800 + k));
        }
        files.push(sized(
            "ansible/download/community-other-0.1.0.tar.gz".to_string(),
            3550,
        ));
        files
    }

    /// What one page shows: every listed entry with the size and time it shows.
    fn detail_view(d: &PackageDetail) -> Value {
        let versions: Vec<Value> = d
            .versions
            .iter()
            .map(|v| json!([v.version, v.size, v.published, v.cached]))
            .collect();
        json!({"versions": versions, "prerelease": d.prerelease_count, "stable": d.total_stable})
    }

    fn dir_view(entries: &[RepoInfo]) -> Value {
        let rows: Vec<Value> = entries
            .iter()
            .map(|e| json!([e.name, e.versions, e.size, e.updated, e.is_file]))
            .collect();
        Value::Array(rows)
    }

    /// How many pages [`page`] shows.
    const PAGES: usize = 13;

    /// Page `i` under test, by name, as it shows the stored files.
    async fn page(storage: &Storage, i: usize) -> (&'static str, Value) {
        let detail = |name, d: PackageDetail| (name, detail_view(&d));
        let dir = |name, entries: Vec<RepoInfo>| (name, dir_view(&entries));
        match i {
            0 => dir("go dir /", get_go_dir_listing(storage, "").await.0),
            1 => dir(
                "go dir github.com",
                get_go_dir_listing(storage, "github.com").await.0,
            ),
            2 => dir(
                "go dir github.com/acme",
                get_go_dir_listing(storage, "github.com/acme").await.0,
            ),
            3 => detail(
                "go module",
                get_go_detail(storage, "github.com/acme/mod", true, true).await,
            ),
            4 => detail("npm", get_npm_detail(storage, "pkg", true, true).await),
            5 => detail(
                "cargo",
                get_cargo_detail(storage, "serde", true, true).await,
            ),
            6 => detail(
                "pypi",
                get_pypi_detail(storage, "requests", true, true).await,
            ),
            7 => detail(
                "conan",
                get_generic_detail(storage, "conan", "zlib", true, true).await,
            ),
            8 => detail(
                "pub",
                get_generic_detail(storage, "pub", "http", true, true).await,
            ),
            9 => detail(
                "ansible",
                get_generic_detail(storage, "ansible", "community.general", true, true).await,
            ),
            10 => detail(
                "terraform (storage scan)",
                get_generic_detail(storage, "terraform", "aws", true, true).await,
            ),
            11 => detail("raw detail", get_raw_detail(storage, "tools").await),
            12 => dir("raw dir", get_raw_dir_listing(storage, "tools").await.0),
            _ => panic!("no page {i}"),
        }
    }

    /// Every page under test, by name, as it shows the stored files.
    async fn pages(storage: &Storage) -> BTreeMap<&'static str, Value> {
        let mut out = BTreeMap::new();
        for i in 0..PAGES {
            let (name, shown) = page(storage, i).await;
            out.insert(name, shown);
        }
        out
    }

    /// The round-trips each page costs against an object store, by page.
    async fn costs(n: usize) -> BTreeMap<&'static str, BTreeMap<&'static str, usize>> {
        let (storage, ops) = op_counting_storage();
        for (key, data) in layout(n) {
            storage.put(&key, &data).await.unwrap();
        }
        let mut out = BTreeMap::new();
        for i in 0..PAGES {
            // One page at a time, so each count is that page's own.
            ops.reset();
            let (name, shown) = page(&storage, i).await;
            assert_ne!(
                shown,
                json!({"versions": [], "prerelease": 0, "stable": 0}),
                "{name}"
            );
            assert_ne!(shown, json!([]), "{name}");
            out.insert(name, ops.snapshot());
        }
        out
    }

    /// #1172: what a page costs against an object store does not grow with the number of
    /// stored versions: 3 versions and 40 cost the same round-trips, method by method. A
    /// page that stats each listed file costs 37 more HEADs at 40.
    #[tokio::test]
    async fn a_listing_page_costs_the_same_requests_for_3_versions_and_for_40() {
        let few = costs(3).await;
        let many = costs(40).await;
        let mut grew = Vec::new();
        for (page, cost) in &many {
            if few[page] != *cost {
                grew.push(format!(
                    "{page}: 3 versions {:?}, 40 versions {cost:?}",
                    few[page]
                ));
            }
        }
        assert!(
            grew.is_empty(),
            "requests grow with versions:\n{}",
            grew.join("\n")
        );
    }

    /// #1172, the reported pages: the Go root, a namespace and a module's versions, through
    /// the router, send no `stat` at all — the listing already carries size and time.
    #[tokio::test]
    async fn the_go_pages_send_no_stat_per_stored_file() {
        let (storage, ops) = op_counting_storage();
        for (key, data) in layout(40) {
            storage.put(&key, &data).await.unwrap();
        }
        let ctx = create_test_context_with_storage(storage);
        for uri in ["/ui/go", "/ui/go/github.com", "/ui/go/github.com/acme/mod"] {
            ops.reset();
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let page = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
            let cost = ops.snapshot();
            assert_eq!(cost.get("stat"), None, "{uri}: {cost:?}");
            if uri.ends_with("/mod") {
                // The page does show the stored versions, with their own sizes.
                assert!(
                    page.contains("v1.39.0") && page.contains("v2.0.0"),
                    "{page}"
                );
                assert!(page.contains("539 B"), "{page}");
            }
        }
    }

    /// #1172: what the pages show — each entry's size and time, cached or not — on the
    /// local store, whose file times the test sets. Times are set back from now by a
    /// different number of hours per file, so a page that shows one file's time for another
    /// shows a different "N hours ago". Recorded before the change, unchanged by it.
    #[tokio::test]
    async fn the_listing_pages_show_each_files_own_size_and_time() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let now = std::time::SystemTime::now();
        // Per top-level directory, the next file is one hour older: at most 23 per directory
        // keep the "N hours ago" form.
        let mut per_registry: BTreeMap<String, u64> = BTreeMap::new();
        for (key, data) in layout(3) {
            storage.put(&key, &data).await.unwrap();
            let registry = key.split('/').next().unwrap().to_string();
            let slot = per_registry.entry(registry).or_insert(0);
            *slot += 1;
            assert!(*slot < 23, "{key}: too many files to tell apart by hour");
            let age = std::time::Duration::from_secs(*slot * 3600 + 1800);
            std::fs::File::options()
                .write(true)
                .open(dir.path().join(&key))
                .unwrap()
                .set_modified(now - age)
                .unwrap();
        }
        let shown = pages(&storage).await;
        insta::assert_json_snapshot!("ui_listing_pages", shown);
    }

    /// #1172: a folded entry (a Go namespace, a raw directory, a Conan version) is as recent
    /// as its newest file wherever that file comes in the listing, and as large as all of
    /// them. The newest file is listed between two older ones here: the first one seen and
    /// the last one seen are both older.
    #[tokio::test]
    async fn a_folded_entry_is_as_recent_as_its_newest_file_wherever_it_is_listed() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let now = std::time::SystemTime::now();
        let hours = |h: u64| now - std::time::Duration::from_secs(h * 3600 + 1800);
        let groups = [
            "go/example.com/m/@v/v1.",
            "raw/t/sub/",
            "conan/z/1.0.0/_/_/rrev/export/",
        ];
        for prefix in groups {
            // Listed in this order; the middle one is the newest.
            for (file, age, len) in [("0.zip", 5, 100), ("1.zip", 1, 20), ("2.zip", 3, 3)] {
                let key = format!("{prefix}{file}");
                storage.put(&key, &vec![b'x'; len]).await.unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(dir.path().join(&key))
                    .unwrap()
                    .set_modified(hours(age))
                    .unwrap();
            }
        }
        let go = get_go_dir_listing(&storage, "").await.0;
        let raw = get_raw_dir_listing(&storage, "t").await.0;
        let conan = get_generic_detail(&storage, "conan", "z", true, true).await;
        let shown = json!({
            "go": dir_view(&go),
            "raw": dir_view(&raw),
            "conan": detail_view(&conan),
        });
        assert_eq!(
            shown,
            json!({
                "go": [["example.com", 3, 123, "1 hour ago", false]],
                "raw": [["sub", 3, 123, "1 hour ago", false]],
                "conan": {"versions": [["1.0.0", 123, "1 hour ago", true]], "prerelease": 0, "stable": 1},
            })
        );
    }

    /// Each version as its page shows it: version, size, time, cached.
    fn rows(detail: &PackageDetail) -> Vec<(String, u64, String, bool)> {
        detail
            .versions
            .iter()
            .map(|v| (v.version.clone(), v.size, v.published.clone(), v.cached))
            .collect()
    }

    fn row(version: &str, size: u64, published: &str, cached: bool) -> (String, u64, String, bool) {
        (version.to_string(), size, published.to_string(), cached)
    }

    /// An in-memory object store, and a writer of objects under the key a NORA of 0.9.2 or
    /// earlier gave them: `@` spelled `_at_`, the encoding #534 replaced and reads still
    /// fall back to.
    fn object_store_with_old_keys() -> (
        Storage,
        impl Fn(&'static str, &'static [u8]) -> futures::future::BoxFuture<'static, ()>,
    ) {
        use crate::storage::{ObjectStorage, StorageBackend};
        use object_store::{path::Path, ObjectStoreExt, PutPayload};
        use std::sync::Arc;

        let backend = Arc::new(ObjectStorage::in_memory());
        let storage = Storage::from_backend(Arc::clone(&backend) as Arc<dyn StorageBackend>);
        let put_old = move |key: &'static str, data: &'static [u8]| {
            let backend = Arc::clone(&backend);
            let old = key.replace('@', "_at_");
            Box::pin(async move {
                backend
                    .store()
                    .put(&Path::from(old.as_str()), PutPayload::from_static(data))
                    .await
                    .unwrap();
            }) as futures::future::BoxFuture<'static, ()>
        };
        (storage, put_old)
    }

    /// #1172: on an object store, a Go version stored by NORA 0.9.2 or earlier — under the
    /// `_at_` key encoding #534 replaced, which reads still fall back to — shows as it did
    /// with a stat per version: cached, with its archive's size and time; a version list
    /// stored that way gives the time of the versions not cached. Where both forms hold a
    /// file, the current one is shown, as a read finds it first.
    #[tokio::test]
    async fn a_go_version_stored_under_the_pre_534_key_encoding_shows_as_cached() {
        let (storage, put_old) = object_store_with_old_keys();
        put_old("go/example.com/m/@v/list", b"v1.0.0\nv1.1.0\nv2.0.0\n").await;
        put_old("go/example.com/m/@v/v1.0.0.zip", b"legacy").await;
        put_old("go/example.com/m/@v/v1.1.0.zip", &[b'o'; 99]).await;
        storage
            .put("go/example.com/m/@v/v1.1.0.zip", &[b'x'; 11])
            .await
            .unwrap();

        let detail = get_go_detail(&storage, "example.com/m", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("v2.0.0", 0, "just now", false),
                row("v1.1.0", 11, "just now", true),
                row("v1.0.0", 6, "just now", true),
            ]
        );
    }

    /// Characters `object_store` percent-encodes in a part of a key (its `INVALID` set, less
    /// `/` and the control characters storage keys refuse).
    const ENCODED_BY_OBJECT_STORE: &[char] = &[
        '\\', '{', '^', '}', '%', '`', ']', '"', '>', '[', '~', '<', '#', '|', '*', '?',
    ];

    /// Write `data` at `path` of the raw store, as `object_store` names it.
    async fn put_raw(raw: &object_store::memory::InMemory, path: &str, data: &[u8]) {
        use object_store::ObjectStoreExt;
        raw.put(
            &object_store::path::Path::from(path),
            object_store::PutPayload::from(data.to_vec()),
        )
        .await
        .unwrap();
    }

    /// #1172: on S3, a Go module whose path holds a character `object_store` encodes shows its
    /// versions as a stat per version did: the current file wins over one under the old key
    /// form, and with no old one the current file still shows as cached with its size.
    #[tokio::test]
    async fn go_versions_under_keys_object_store_encodes_show_as_a_read_finds_them() {
        let mut taken = Vec::new();
        let mut wrong = Vec::new();
        for &c in ENCODED_BY_OBJECT_STORE {
            let (storage, raw, _) = crate::test_helpers::list_counting_storage("s3");
            let both = format!("example.com/m{c}x");
            let current_only = format!("example.com/n{c}x");
            // A key storage refuses is not one a page can show.
            if storage
                .put(&format!("go/{both}/@v/list"), b"v1.0.0\n")
                .await
                .is_err()
            {
                continue;
            }
            taken.push(c);
            storage
                .put(&format!("go/{both}/@v/v1.0.0.zip"), &[b'x'; 11])
                .await
                .unwrap();
            put_raw(&raw, &format!("go/{both}/_at_v/v1.0.0.zip"), &[b'o'; 99]).await;
            storage
                .put(&format!("go/{current_only}/@v/list"), b"v1.0.0\n")
                .await
                .unwrap();
            storage
                .put(&format!("go/{current_only}/@v/v1.0.0.zip"), &[b'x'; 11])
                .await
                .unwrap();
            for module in [&both, &current_only] {
                let shown = rows(&get_go_detail(&storage, module, true, true).await);
                if shown != [row("v1.0.0", 11, "just now", true)] {
                    wrong.push(format!("{module}: {shown:?}"));
                }
            }
        }
        assert!(taken.contains(&'~'), "keys taken: {taken:?}");
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// #1172: the same on the npm versions page, for a scoped package whose name holds `~`.
    #[tokio::test]
    async fn an_npm_tarball_under_a_key_object_store_encodes_shows_as_a_read_finds_it() {
        let (storage, raw, _) = crate::test_helpers::list_counting_storage("s3");
        storage
            .put("npm/@sc~pe/pkg/metadata.json", &npm_packument())
            .await
            .unwrap();
        storage
            .put("npm/@sc~pe/pkg/tarballs/pkg-1.1.0.tgz", &[b'x'; 11])
            .await
            .unwrap();
        put_raw(
            &raw,
            "npm/_at_sc~pe/pkg/tarballs/pkg-1.1.0.tgz",
            &[b'o'; 99],
        )
        .await;
        storage
            .put("npm/@sc~pe/pkg/tarballs/pkg-1.0.0.tgz", &[b'x'; 10])
            .await
            .unwrap();

        let detail = get_npm_detail(&storage, "@sc~pe/pkg", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("2.0.0", 77, "2026-03-04", false),
                row("1.1.0", 11, "2026-01-02", true),
                row("1.0.0", 10, "2026-01-02", true),
            ]
        );
    }

    /// #1172: only the S3 backend wrote keys in the old `_at_` form (NORA 0.9.2 and earlier;
    /// the GCS backend came in 1.0.1): a versions page on GCS lists the current form alone, on
    /// S3 the old form too.
    #[tokio::test]
    async fn the_go_versions_page_lists_the_old_key_form_on_s3_only() {
        for (backend, expected) in [("gcs", (1, 0)), ("s3", (2, 1))] {
            let (storage, _, listings) = crate::test_helpers::list_counting_storage(backend);
            storage
                .put("go/example.com/m/@v/list", b"v1.0.0\n")
                .await
                .unwrap();
            storage
                .put("go/example.com/m/@v/v1.0.0.zip", &[b'x'; 11])
                .await
                .unwrap();
            listings.reset();

            let shown = rows(&get_go_detail(&storage, "example.com/m", true, true).await);
            assert_eq!(shown, [row("v1.0.0", 11, "just now", true)], "{backend}");
            assert_eq!(
                listings.counts(),
                expected,
                "{backend}: listings, of them in the old form"
            );
        }
    }

    /// #1172: when only the listing of the older key form fails, the page asks per version,
    /// as before #1172 — a stat finds either form — rather than show what it could not list
    /// as not cached.
    #[tokio::test]
    async fn a_failed_listing_of_older_keys_falls_back_to_reading_each_go_version() {
        let (storage, outage) = crate::test_helpers::outage_storage();
        storage
            .put("go/example.com/m/@v/list", b"v1.0.0\nv1.1.0\nv2.0.0\n")
            .await
            .unwrap();
        storage
            .put("go/example.com/m/@v/v1.0.0.zip", &[b'x'; 10])
            .await
            .unwrap();
        storage
            .put("go/example.com/m/@v/v1.1.0.zip", &[b'x'; 11])
            .await
            .unwrap();
        outage.fail_older_listings_of("go/example.com/m/@v/");

        let detail = get_go_detail(&storage, "example.com/m", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("v2.0.0", 0, "just now", false),
                row("v1.1.0", 11, "just now", true),
                row("v1.0.0", 10, "just now", true),
            ]
        );
    }

    /// #1172: the same for a scoped npm package's tarball stored by NORA 0.9.2 or earlier.
    #[tokio::test]
    async fn a_scoped_npm_tarball_stored_under_the_pre_534_key_encoding_shows_as_cached() {
        let (storage, put_old) = object_store_with_old_keys();
        storage
            .put("npm/@scope/pkg/metadata.json", &npm_packument())
            .await
            .unwrap();
        put_old("npm/@scope/pkg/tarballs/pkg-1.0.0.tgz", b"legacy").await;
        put_old("npm/@scope/pkg/tarballs/pkg-1.1.0.tgz", &[b'o'; 99]).await;
        storage
            .put("npm/@scope/pkg/tarballs/pkg-1.1.0.tgz", &[b'x'; 11])
            .await
            .unwrap();

        let detail = get_npm_detail(&storage, "@scope/pkg", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("2.0.0", 77, "2026-03-04", false),
                row("1.1.0", 11, "2026-01-02", true),
                row("1.0.0", 6, "2026-01-02", true),
            ]
        );
    }

    /// A packument naming 1.0.0, 1.1.0 and 2.0.0.
    fn npm_packument() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "versions": {
                "1.0.0": {"dist": {"unpackedSize": 5}},
                "1.1.0": {"dist": {"unpackedSize": 5}},
                "2.0.0": {"dist": {"unpackedSize": 77}},
            },
            "time": {
                "1.0.0": "2026-01-02T03:04:05.000Z",
                "1.1.0": "2026-01-02T03:04:05.000Z",
                "2.0.0": "2026-03-04T05:06:07.000Z",
            },
        }))
        .unwrap()
    }

    /// #1172: a store whose listing of a module's `@v/` fails while its reads answer shows
    /// the module's versions as a stat per version did — cached, with sizes and times — not
    /// as "not cached": a failed listing is not an empty one.
    #[tokio::test]
    async fn a_failed_listing_does_not_show_the_go_versions_as_not_cached() {
        let (storage, outage) = crate::test_helpers::outage_storage();
        storage
            .put("go/example.com/m/@v/list", b"v1.0.0\nv1.1.0\nv2.0.0\n")
            .await
            .unwrap();
        storage
            .put("go/example.com/m/@v/v1.0.0.zip", &[b'x'; 10])
            .await
            .unwrap();
        storage
            .put("go/example.com/m/@v/v1.1.0.zip", &[b'x'; 11])
            .await
            .unwrap();
        outage.fail_listings_of("go/example.com/m/@v/");

        let detail = get_go_detail(&storage, "example.com/m", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("v2.0.0", 0, "just now", false),
                row("v1.1.0", 11, "just now", true),
                row("v1.0.0", 10, "just now", true),
            ]
        );
    }

    /// #1172: the same for an npm package whose listing of `tarballs/` fails.
    #[tokio::test]
    async fn a_failed_listing_does_not_show_the_npm_versions_as_not_cached() {
        let (storage, outage) = crate::test_helpers::outage_storage();
        storage
            .put("npm/pkg/metadata.json", &npm_packument())
            .await
            .unwrap();
        storage
            .put("npm/pkg/tarballs/pkg-1.0.0.tgz", &[b'x'; 10])
            .await
            .unwrap();
        storage
            .put("npm/pkg/tarballs/pkg-1.1.0.tgz", &[b'x'; 11])
            .await
            .unwrap();
        outage.fail_listings_of("npm/pkg/tarballs/");

        let detail = get_npm_detail(&storage, "pkg", true, true).await;
        assert_eq!(
            rows(&detail),
            [
                row("2.0.0", 77, "2026-03-04", false),
                row("1.1.0", 11, "2026-01-02", true),
                row("1.0.0", 10, "2026-01-02", true),
            ]
        );
    }
}

#[cfg(test)]
mod maven_pages_from_index {
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use crate::test_helpers::{body_bytes, create_test_context_with_storage, send, TestContext};
    use axum::http::{Method, StatusCode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// An in-memory object store counting the calls that walk storage: listings and stats.
    struct Counting {
        inner: ObjectStorage,
        walks: Arc<AtomicUsize>,
        stats: Arc<AtomicUsize>,
        gate: Option<Arc<Gate>>,
    }

    /// Holds one listing after it has read storage, until released: the window between a
    /// rebuild's listing and the index it stores.
    #[derive(Default)]
    struct Gate {
        armed: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl StorageBackend for Counting {
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            self.stats.fetch_add(1, Ordering::SeqCst);
            self.inner.stat(key).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            self.inner.put(k, d, sha256).await
        }
        async fn get(
            &self,
            k: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            self.inner.get(k).await
        }
        async fn pin(&self, k: &str) -> Option<String> {
            self.inner.pin(k).await
        }
        async fn delete(&self, k: &str) -> crate::storage::Result<()> {
            self.inner.delete(k).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            self.walks.fetch_add(1, Ordering::SeqCst);
            self.inner.list(prefix).await
        }
        async fn list_with_meta(
            &self,
            prefix: &str,
        ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
            self.walks.fetch_add(1, Ordering::SeqCst);
            let listed = self.inner.list_with_meta(prefix).await;
            if let Some(gate) = &self.gate {
                if gate.armed.swap(false, Ordering::SeqCst) {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
            }
            listed
        }
        async fn health_check(&self) -> bool {
            self.inner.health_check().await
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "walk-counting-test"
        }
        async fn put_from_path(
            &self,
            k: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.put_from_path(k, src, sha256).await
        }
        async fn copy(
            &self,
            src: &str,
            dst: &str,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn get_reader(
            &self,
            k: &str,
        ) -> crate::storage::Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(k).await
        }
    }

    struct Fixture {
        ctx: TestContext,
        walks: Arc<AtomicUsize>,
        stats: Arc<AtomicUsize>,
    }

    impl Fixture {
        fn reset(&self) {
            self.walks.store(0, Ordering::SeqCst);
            self.stats.store(0, Ordering::SeqCst);
        }
        fn walks_and_stats(&self) -> (usize, usize) {
            (
                self.walks.load(Ordering::SeqCst),
                self.stats.load(Ordering::SeqCst),
            )
        }
        async fn page(&self, uri: &str) -> String {
            let resp = send(&self.ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
        }
    }

    async fn fixture() -> Fixture {
        gated_fixture().await.0
    }

    async fn gated_fixture() -> (Fixture, Arc<Gate>) {
        let gate = Arc::new(Gate::default());
        let walks = Arc::new(AtomicUsize::new(0));
        let stats = Arc::new(AtomicUsize::new(0));
        let ctx = create_test_context_with_storage(Storage::from_backend(Arc::new(Counting {
            inner: ObjectStorage::in_memory(),
            walks: Arc::clone(&walks),
            stats: Arc::clone(&stats),
            gate: Some(Arc::clone(&gate)),
        })));
        for (key, len) in [
            ("maven/com/acme/lib/maven-metadata.xml", 100),
            ("maven/com/acme/lib/1.0/lib-1.0.jar", 1000),
            ("maven/com/acme/lib/1.0/lib-1.0.jar.sha1", 40),
            ("maven/com/acme/lib/1.0/lib-1.0.pom", 200),
            ("maven/com/acme/lib/2.0/lib-2.0.jar", 2000),
            ("maven/org/x/y/1/y-1.jar", 10),
        ] {
            ctx.state.storage.put(key, &vec![b'x'; len]).await.unwrap();
        }
        (Fixture { ctx, walks, stats }, gate)
    }

    /// #1216: once the index is built, a Maven directory page is answered from it: no listing
    /// and no stat per stored file on each visit.
    #[tokio::test]
    async fn a_maven_directory_page_does_not_walk_storage_on_each_visit() {
        let f = fixture().await;
        f.page("/ui/maven").await;
        f.reset();
        let root = f.page("/ui/maven").await;
        let dir = f.page("/ui/maven/com/acme").await;
        assert!(
            root.contains(">com</a>") && root.contains(">org</a>"),
            "{root}"
        );
        assert!(dir.contains(">lib</a>"), "{dir}");
        assert_eq!(f.walks_and_stats(), (0, 0));
    }

    /// #1216: the files of one version come from one listing that carries their sizes,
    /// not a stat per file.
    #[tokio::test]
    async fn a_version_page_lists_its_files_without_a_stat_per_file() {
        let f = fixture().await;
        f.page("/ui/maven").await;
        f.reset();
        let page = f.page("/ui/maven/com/acme/lib/1.0").await;
        assert!(
            page.contains("lib-1.0.jar") && page.contains("lib-1.0.pom"),
            "{page}"
        );
        assert!(page.contains("1000 B") && page.contains("200 B"), "{page}");
        assert_eq!(f.walks_and_stats().1, 0);
    }

    /// #1216: what the Maven directory pages show, folded from the index: per child the count
    /// of primary files (sidecars and maven-metadata.xml not counted, as on the dashboard),
    /// their bytes with sidecars, and leaf or not. Before #1216 the count was every stored file.
    #[tokio::test]
    async fn the_maven_directory_pages_fold_the_index() {
        let f = fixture().await;
        let index = f
            .ctx
            .state
            .repo_index
            .get("maven", &f.ctx.state.storage)
            .await;
        let pages: Vec<serde_json::Value> = [
            "",
            "com",
            "com/acme",
            "com/acme/lib",
            "com/acme/lib/1.0",
            "com/ac",
            "nope",
        ]
        .into_iter()
        .map(|path| {
            let (entries, leaf) = super::api::maven_dir_listing(&index, path);
            let children: Vec<_> = entries
                .iter()
                .map(|e| serde_json::json!({"name": e.name, "files": e.versions, "bytes": e.size}))
                .collect();
            serde_json::json!({"path": path, "leaf": leaf, "children": children})
        })
        .collect();
        insta::assert_json_snapshot!("maven_ui_directory_pages", pages);
    }

    /// #1216: a folded directory is as recent as the newest directory below it.
    #[test]
    fn a_folded_directory_is_as_recent_as_its_newest_entry() {
        let dir = |name: &str, modified| crate::repo_index::RepoInfo {
            name: name.to_string(),
            versions: 1,
            modified,
            ..Default::default()
        };
        // The newest comes first: the last one seen would answer 100.
        let index = [
            dir("com/a/1", 300),
            dir("com/a/2", 100),
            dir("com/b/1", 200),
        ];
        let (entries, _) = super::api::maven_dir_listing(&index, "com");
        let newest: Vec<_> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.modified))
            .collect();
        assert_eq!(newest, [("a", 300), ("b", 200)]);
    }

    /// Client-managed metadata stored after the index was built is on the directory page at once,
    /// as an uploaded artifact is.
    #[tokio::test]
    async fn stored_metadata_is_on_the_directory_page_at_once() {
        let f = fixture().await;
        assert!(!f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
        let resp = send(
            &f.ctx.app,
            Method::PUT,
            "/maven2/com/acme/tool/maven-metadata.xml",
            b"<metadata><plugins/></metadata>".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
    }

    /// Control for the test above: with the index marked for rebuild by hand, the same write is on
    /// the page, so a red above is the missing invalidation and not a page that never shows it.
    #[tokio::test]
    async fn stored_metadata_is_on_the_page_once_the_index_is_rebuilt() {
        let f = fixture().await;
        assert!(!f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
        let resp = send(
            &f.ctx.app,
            Method::PUT,
            "/maven2/com/acme/tool/maven-metadata.xml",
            b"<metadata><plugins/></metadata>".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        f.ctx.state.repo_index.invalidate("maven");
        assert!(f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
    }

    /// #1216: an artifact uploaded after the index was built is on the page at once: the upload
    /// marks the index for rebuild, so the page is not served from a stale one.
    #[tokio::test]
    async fn an_uploaded_artifact_is_on_the_directory_page_at_once() {
        let f = fixture().await;
        assert!(!f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
        let resp = send(
            &f.ctx.app,
            Method::PUT,
            "/maven2/com/acme/tool/3.0/tool-3.0.jar",
            vec![b'x'; 5],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
    }

    /// A write that lands while the index is being rebuilt is not lost: the rebuild that listed
    /// storage before the write leaves the index marked, and the next visit shows the write.
    #[tokio::test]
    async fn a_write_during_a_rebuild_is_on_the_next_page() {
        let (f, gate) = gated_fixture().await;
        gate.armed.store(true, Ordering::SeqCst);
        let app = f.ctx.app.clone();
        let visit = tokio::spawn(async move {
            send(&app, Method::GET, "/ui/maven/com/acme", "")
                .await
                .status()
        });
        // The rebuild has listed storage and has not stored the index yet.
        tokio::time::timeout(std::time::Duration::from_secs(10), gate.entered.notified())
            .await
            .expect("the rebuild never listed storage");
        let resp = send(
            &f.ctx.app,
            Method::PUT,
            "/maven2/com/acme/tool/3.0/tool-3.0.jar",
            vec![b'x'; 5],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        gate.release.notify_one();
        assert_eq!(visit.await.unwrap(), StatusCode::OK);
        // No write since: the next visit must still see the upload.
        assert!(f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
    }

    /// A checksum the client uploads for a file of a new version marks the index for rebuild, as
    /// the file it belongs to does.
    #[tokio::test]
    async fn an_uploaded_checksum_is_on_the_directory_page_at_once() {
        for rebuilt_by_hand in [true, false] {
            let f = fixture().await;
            assert!(!f.page("/ui/maven/com/acme").await.contains(">tool</a>"));
            let resp = send(
                &f.ctx.app,
                Method::PUT,
                "/maven2/com/acme/tool/3.0/tool-3.0.jar.sha1",
                b"da39a3ee5e6b4b0d3255bfef95601890afd80709".to_vec(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            // Control: with the index marked by hand the checksum is on the page, so a red
            // without it is the missing mark and not a page that never shows a checksum.
            if rebuilt_by_hand {
                f.ctx.state.repo_index.invalidate("maven");
            }
            assert!(
                f.page("/ui/maven/com/acme").await.contains(">tool</a>"),
                "marked by hand: {rebuilt_by_hand}"
            );
        }
    }

    /// Metadata fetched from the upstream and cached marks the index for rebuild, as a cached
    /// artifact does: the directory it lands in is on the page without another write.
    #[tokio::test]
    async fn proxied_metadata_is_on_the_directory_page() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/newproxy/thing/maven-metadata.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<metadata><groupId>newproxy</groupId><artifactId>thing</artifactId>\
                 <versioning><versions><version>1.0</version></versions></versioning></metadata>",
            ))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
        });
        let page = |uri: &'static str| {
            let app = ctx.app.clone();
            async move {
                let resp = send(&app, Method::GET, uri, "").await;
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
            }
        };
        assert!(!page("/ui/maven").await.contains(">newproxy</a>"));
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/newproxy/thing/maven-metadata.xml",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let key = "maven/newproxy/thing/maven-metadata.xml";
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ctx.state.storage.stat(key).await.is_none() {
            assert!(std::time::Instant::now() < deadline, "{key} never cached");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        while !page("/ui/maven").await.contains(">newproxy</a>") {
            assert!(
                std::time::Instant::now() < deadline,
                "proxied metadata never reached the directory page"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A file stored under a path that names no artifact (it is kept as uploaded) marks the index
    /// for rebuild, as an artifact does.
    #[tokio::test]
    async fn an_uploaded_file_outside_an_artifact_is_on_the_directory_page_at_once() {
        let f = fixture().await;
        assert!(!f.page("/ui/maven").await.contains(">neworg</a>"));
        let resp = send(
            &f.ctx.app,
            Method::PUT,
            "/maven2/neworg/thing/readme.txt",
            b"x".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(f.page("/ui/maven").await.contains(">neworg</a>"));
    }

    /// A file cached in the background (a proxied artifact) marks the index for rebuild once it
    /// is stored, so it shows on the directory page without another write.
    #[tokio::test]
    async fn a_file_cached_in_the_background_is_on_the_directory_page() {
        for immutable in [false, true] {
            let f = fixture().await;
            assert!(!f.page("/ui/maven").await.contains(">cached</a>"));
            let key = "maven/cached/a/1.0/a-1.0.jar".to_string();
            let data = axum::body::Bytes::from_static(b"jar");
            if immutable {
                f.ctx
                    .state
                    .spawn_cache_immutable("maven", key.clone(), data);
            } else {
                f.ctx.state.spawn_cache("maven", key.clone(), data);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while f.ctx.state.storage.stat(&key).await.is_none() {
                assert!(std::time::Instant::now() < deadline, "never stored");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            // The mark follows the write in the same task: wait for it up to the deadline.
            while !f.page("/ui/maven").await.contains(">cached</a>") {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a cached file never reached the directory page (immutable: {immutable})"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

/// The dashboard's mount points: who sees which upstream addresses. A caller NORA does not know
/// sees that a registry has upstreams, not where they are; a signed-in caller sees the addresses,
/// never the credentials an address may carry.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod mount_points {
    use crate::config::{EnableSpec, RegistriesSection};
    use crate::registry_type::RegistryType;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_anonymous_read_and_config,
        create_test_context_with_config, send, send_with_headers, TestContext,
    };
    use axum::http::{Method, StatusCode};

    const SECRET_MIRROR: &str = "https://ci-bot:s3cr3t-token@pypi.mirror.example/simple";

    fn configure(c: &mut crate::config::Config) {
        c.npm.proxy = Some("https://registry.npmjs.org".into());
        c.pypi.proxy = Some(SECRET_MIRROR.into());
        // Not an address the client can read: shown to nobody.
        c.cpan.enabled = true;
        c.cpan.proxy = Some("ci-bot:s3cr3t-token@cpan.mirror.example".into());
    }

    async fn get(ctx: &TestContext, uri: &str, auth: Option<&str>) -> String {
        let resp = match auth {
            Some(value) => {
                send_with_headers(
                    &ctx.app,
                    Method::GET,
                    uri,
                    vec![("authorization", value)],
                    "",
                )
                .await
            }
            None => send(&ctx.app, Method::GET, uri, "").await,
        };
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        String::from_utf8_lossy(&body_bytes(resp).await).into_owned()
    }

    fn mount<'a>(json: &'a serde_json::Value, registry: &str) -> &'a serde_json::Value {
        json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some(registry))
            .unwrap_or_else(|| panic!("{registry} mount"))
    }

    fn bearer(ctx: &TestContext, role: crate::tokens::Role) -> String {
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, role)
            .unwrap();
        format!("Bearer {token}")
    }

    /// The table row of `registry` on the dashboard page.
    fn row<'a>(html: &'a str, registry: &str) -> &'a str {
        let cell = format!(r#"<td class="px-4 py-3 text-slate-300">{registry}</td>"#);
        let start = html.find(&cell).unwrap_or_else(|| panic!("{registry} row"));
        let rest = &html[start..];
        &rest[..rest.find("</tr>").unwrap()]
    }

    /// An anonymous caller on an instance with sign-in: the registries with upstreams say the
    /// addresses are hidden until sign-in, the ones without say nothing, and no address shows.
    #[tokio::test]
    async fn an_anonymous_caller_is_told_the_upstreams_are_hidden() {
        let ctx =
            create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], configure);

        let json: serde_json::Value =
            serde_json::from_str(&get(&ctx, "/api/ui/dashboard", None).await).unwrap();
        for registry in ["npm", "PyPI"] {
            let m = mount(&json, registry);
            assert_eq!(m["proxy_upstreams"], serde_json::json!([]), "{registry}");
            assert_eq!(m["proxy_hidden"], true, "{registry} has hidden upstreams");
        }
        assert_eq!(mount(&json, "Raw")["proxy_hidden"], false, "raw has none");

        let html = get(&ctx, "/ui/", None).await;
        assert!(row(&html, "npm").contains("sign in"), "npm row says why");
        assert!(row(&html, "PyPI").contains("sign in"), "PyPI row says why");
        assert!(row(&html, "Raw").contains(">-<"), "raw row has no upstream");
        assert!(!html.contains("registry.npmjs.org"), "no address");
        assert!(!html.contains("pypi.mirror.example"), "no address");
    }

    /// Without sign-in on the instance nobody is known: the upstreams are hidden, and the page does
    /// not send the reader to a sign-in that does not exist.
    #[tokio::test]
    async fn without_auth_the_upstreams_are_hidden_with_no_sign_in_to_offer() {
        let ctx = create_test_context_with_config(configure);

        let json: serde_json::Value =
            serde_json::from_str(&get(&ctx, "/api/ui/dashboard", None).await).unwrap();
        assert_eq!(mount(&json, "npm")["proxy_hidden"], true);
        assert_eq!(
            mount(&json, "npm")["proxy_upstreams"],
            serde_json::json!([])
        );

        let html = get(&ctx, "/ui/", None).await;
        let npm = row(&html, "npm");
        assert!(
            npm.contains("Hidden"),
            "npm row says the upstreams are hidden"
        );
        assert!(!npm.contains("sign in"), "no sign-in to offer");
        assert!(!html.contains("registry.npmjs.org"), "no address");
    }

    /// Point `reg`'s upstream at `url`; `false` for a format with no upstream. The match is
    /// exhaustive, so a new format has to say here how it proxies.
    fn give_upstream(c: &mut crate::config::Config, reg: RegistryType, url: &str) -> bool {
        use crate::config::{DockerUpstream, MavenProxyEntry, RepoProxyEntry};
        let url = url.to_string();
        match reg {
            RegistryType::Docker => {
                c.docker.upstreams = vec![DockerUpstream {
                    url,
                    auth: None,
                    namespace: None,
                    prefix: None,
                    namespaces: Vec::new(),
                }]
            }
            RegistryType::Maven => c.maven.proxies = vec![MavenProxyEntry::Simple(url)],
            RegistryType::Npm => c.npm.proxy = Some(url),
            RegistryType::Cargo => c.cargo.proxy = Some(url),
            RegistryType::PyPI => c.pypi.proxy = Some(url),
            RegistryType::Go => c.go.proxy = Some(url),
            RegistryType::Raw => return false,
            RegistryType::Gems => c.gems.proxy = Some(url),
            RegistryType::Terraform => c.terraform.proxy = Some(url),
            RegistryType::Ansible => c.ansible.proxy = Some(url),
            RegistryType::Nuget => c.nuget.proxy = Some(url),
            RegistryType::PubDart => c.pub_dart.proxy = Some(url),
            RegistryType::Conan => c.conan.proxy = Some(url),
            RegistryType::Rpm => {
                c.rpm
                    .proxies
                    .insert("fedora".into(), RepoProxyEntry::Simple(url));
            }
            RegistryType::Deb => {
                c.deb
                    .proxies
                    .insert("debian".into(), RepoProxyEntry::Simple(url));
            }
            RegistryType::Cpan => c.cpan.proxy = Some(url),
            RegistryType::Composer => c.composer.proxy = Some(url),
            RegistryType::HuggingFace => c.hf.proxy = Some(url),
        }
        true
    }

    /// Each format alone, with an upstream where it has one: without authentication the
    /// dashboard says the upstream is hidden; signed in, the address shows, credentials cut.
    #[tokio::test]
    async fn every_format_with_an_upstream_reports_it() {
        for reg in RegistryType::all().iter().copied() {
            let url = format!("https://ci-bot:s3cr3t@up-{}.example/x", reg.as_str());
            let mut proxies = false;
            let only = vec![reg.as_str().to_string()];
            let open = create_test_context_with_config(|c| {
                c.registries = Some(RegistriesSection {
                    enable: Some(EnableSpec::List(only.clone())),
                });
                proxies = give_upstream(c, reg, &url);
            });
            let json: serde_json::Value =
                serde_json::from_str(&get(&open, "/api/ui/dashboard", None).await).unwrap();
            let m = mount(&json, reg.display_name());
            assert_eq!(
                m["proxy_hidden"],
                proxies,
                "{}: hidden without auth",
                reg.as_str()
            );
            assert_eq!(
                m["proxy_upstreams"],
                serde_json::json!([]),
                "{}",
                reg.as_str()
            );

            let signed =
                create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
                    c.registries = Some(RegistriesSection {
                        enable: Some(EnableSpec::List(only.clone())),
                    });
                    give_upstream(c, reg, &url);
                });
            let auth = bearer(&signed, crate::tokens::Role::Read);
            let body = get(&signed, "/api/ui/dashboard", Some(&auth)).await;
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            let m = mount(&json, reg.display_name());
            assert_eq!(
                m["proxy_hidden"],
                false,
                "{}: shown signed in",
                reg.as_str()
            );
            let host = format!("up-{}.example", reg.as_str());
            assert_eq!(
                m["proxy_upstreams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|u| u.as_str().unwrap().contains(&host)),
                proxies,
                "{}: the address shows",
                reg.as_str()
            );
            assert!(!body.contains("s3cr3t"), "{}: {body}", reg.as_str());
        }
    }

    /// A signed-in caller, a read-only one included, sees the addresses, and an address that
    /// carries credentials shows without them.
    #[tokio::test]
    async fn a_signed_in_caller_sees_addresses_without_their_credentials() {
        let ctx =
            create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], configure);

        for role in [crate::tokens::Role::Read, crate::tokens::Role::Admin] {
            let auth = bearer(&ctx, role);
            let body = get(&ctx, "/api/ui/dashboard", Some(&auth)).await;
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                mount(&json, "npm")["proxy_upstreams"],
                serde_json::json!(["https://registry.npmjs.org"]),
                "an address without credentials shows as written"
            );
            assert_eq!(
                mount(&json, "PyPI")["proxy_upstreams"],
                serde_json::json!(["https://pypi.mirror.example/simple"]),
                "the credentials are cut from the address"
            );
            assert_eq!(mount(&json, "npm")["proxy_hidden"], false);
            assert!(
                !body.contains("s3cr3t-token") && !body.contains("ci-bot"),
                "{body}"
            );

            let cpan = mount(&json, "CPAN");
            assert_eq!(
                cpan["proxy_upstreams"],
                serde_json::json!([]),
                "unreadable: not shown"
            );
            assert_eq!(cpan["proxy_hidden"], true, "unreadable: said to be hidden");

            let html = get(&ctx, "/ui/", Some(&auth)).await;
            assert!(
                html.contains("pypi.mirror.example/simple"),
                "the address shows"
            );
            let cpan_row = row(&html, "CPAN");
            assert!(cpan_row.contains("Hidden"), "CPAN row: hidden");
            assert!(
                !cpan_row.contains("sign in"),
                "signing in again shows nothing more"
            );
            assert!(!html.contains("s3cr3t-token") && !html.contains("ci-bot"));
        }
    }
}

/// The dashboard links each registry card to `/ui/{name}`: every such page has to answer, and
/// the cards are exactly the enabled registries. Hugging Face, the opt-in format, had a card
/// whose link answered 404.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod registry_pages {
    use crate::config::{EnableSpec, RegistriesSection};
    use crate::registry_type::RegistryType;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use std::collections::BTreeSet;

    fn ctx_enabling(spec: &[&str]) -> TestContext {
        let spec: Vec<String> = spec.iter().map(|s| s.to_string()).collect();
        create_test_context_with_config(move |c| {
            c.registries = Some(RegistriesSection {
                enable: Some(EnableSpec::List(spec)),
            });
        })
    }

    async fn page(ctx: &TestContext, uri: &str) -> (StatusCode, String) {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The registry pages the dashboard cards link to: `href="/ui/{name}"` with `{name}` a
    /// registry, a link of one segment.
    fn card_links(html: &str) -> BTreeSet<String> {
        html.split("href=\"/ui/")
            .skip(1)
            .filter_map(|rest| rest.split_once('"').map(|(name, _)| name))
            .filter(|name| RegistryType::from_str_opt(name).is_some())
            .map(str::to_string)
            .collect()
    }

    fn names(regs: &[RegistryType]) -> BTreeSet<String> {
        regs.iter().map(|r| r.as_str().to_string()).collect()
    }

    /// Everything on, the opt-in Hugging Face too: a card per registry, and each card's page
    /// answers.
    #[tokio::test]
    async fn every_dashboard_card_links_to_a_page_that_answers() {
        let ctx = ctx_enabling(&["all", "hf"]);
        let (status, dashboard) = page(&ctx, "/ui/").await;
        assert_eq!(status, StatusCode::OK);

        let (_, stats) = page(&ctx, "/api/ui/dashboard").await;
        let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let cards: BTreeSet<String> = stats["registry_stats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(cards, names(RegistryType::all()), "a card per registry");

        let linked = card_links(&dashboard);
        assert!(cards.is_subset(&linked), "each card links its page");
        for name in &linked {
            let (status, _) = page(&ctx, &format!("/ui/{name}")).await;
            assert_eq!(status, StatusCode::OK, "/ui/{name} answers");
        }
    }

    /// A registry left off has no card and no link on the dashboard.
    #[tokio::test]
    async fn a_registry_left_off_has_no_card() {
        let ctx = ctx_enabling(&["docker", "npm"]);
        let (_, stats) = page(&ctx, "/api/ui/dashboard").await;
        let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let cards: BTreeSet<String> = stats["registry_stats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(cards, names(&[RegistryType::Docker, RegistryType::Npm]));
        let (_, dashboard) = page(&ctx, "/ui/").await;
        // The sidebar of a test context lists every format (its filter is set at startup only),
        // so the card is told by its title.
        assert!(
            !dashboard.contains("Hugging Face Hub"),
            "no Hugging Face card"
        );
    }

    /// A cached Hugging Face file lists its repository, and the repository's page names the
    /// cached file, under the encoded link the list gives and the plain one alike.
    #[tokio::test]
    async fn a_cached_hugging_face_repository_is_listed_and_has_a_page() {
        let ctx = ctx_enabling(&["hf"]);
        let digest = "a".repeat(64);
        ctx.state
            .storage
            .put(&format!("hf/models/org/model/blobs/{digest}"), b"weights")
            .await
            .unwrap();
        // Not a cached file: a digest is one segment, nothing nests under `blobs/`.
        ctx.state
            .storage
            .put("hf/models/org/model/blobs/nested/stray", b"x")
            .await
            .unwrap();

        let (status, list) = page(&ctx, "/ui/hf").await;
        assert_eq!(status, StatusCode::OK);
        assert!(list.contains("Hugging Face"), "the list is titled");
        assert!(
            list.contains("/ui/hf/org%2Fmodel"),
            "the list links the repository"
        );

        // A repository id is not a path: three segments, a segment that does not start with a
        // letter or digit, or one holding `..`, have no page.
        for uri in [
            "/ui/hf/org/model/blobs",
            "/ui/hf/org/.model",
            "/ui/hf/org/model..x",
            "/ui/hf/..%2Fmodel",
        ] {
            let (status, _) = page(&ctx, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }

        // The cache keeps ids in lower case; the page answers to the id as the Hub writes it.
        for uri in ["/ui/hf/org%2Fmodel", "/ui/hf/org/model", "/ui/hf/Org/Model"] {
            let (status, detail) = page(&ctx, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(detail.contains(&digest), "{uri} names the cached file");
            assert!(!detail.contains("stray"), "{uri} lists cached files only");
            // The rows are cached files named by digest, not versions.
            assert!(
                detail.contains(">Digest</th>"),
                "{uri} names the column by what it holds"
            );
            assert!(
                !detail.contains(">Versions</th>") && !detail.contains(">Versions ("),
                "{uri} does not call the files versions"
            );
            assert!(
                detail.contains("HF_ENDPOINT="),
                "{uri} shows how to download"
            );
        }
    }
}
