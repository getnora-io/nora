// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

pub(crate) mod api;
pub mod components;
pub mod i18n;
mod logo;
mod static_assets;
mod templates;

use crate::repo_index::paginate;
use crate::tokens::Role;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use std::sync::Arc;

use api::*;
use i18n::Lang;
use templates::*;

/// Returns base URL for UI install commands.
/// Uses public_url if set (trimming trailing slash), otherwise http://host:port.
fn resolve_base_url(state: &AppState) -> String {
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

#[derive(Debug, serde::Deserialize)]
struct LangQuery {
    lang: Option<String>,
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

/// Extract username from Basic Auth header (already validated by auth middleware)
fn extract_basic_auth_user(headers: &axum::http::HeaderMap) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (user, _) = decoded.split_once(':')?;
    Some(user.to_string())
}

pub fn routes() -> Router<Arc<AppState>> {
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
        .route("/ui/ansible", get(generic_registry_list))
        .route("/ui/nuget", get(generic_registry_list))
        .route("/ui/nuget/{name}", get(generic_registry_detail))
        .route("/ui/pub", get(generic_registry_list))
        .route("/ui/pub/{name}", get(generic_registry_detail))
        .route("/ui/conan", get(generic_registry_list))
        .route("/ui/conan/{name}", get(generic_registry_detail))
        .route("/ui/gems/{name}", get(generic_registry_detail))
        .route("/ui/terraform/{name}", get(generic_registry_detail))
        .route("/ui/ansible/{name}", get(generic_registry_detail))
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

// Dashboard page
async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();
    let response = api_dashboard(State(state)).await.0;
    Html(render_dashboard(&response, lang, auth_enabled))
}

// Docker pages
async fn docker_list(
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_repos = state.repo_index.get("maven", &state.storage).await;
    let (repos, total) = paginate(&all_repos, page, limit);

    Html(render_registry_list_paginated(
        "maven",
        "Maven Repository",
        &repos,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn maven_detail(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let auth_enabled = state.auth.is_some();
    let detail = get_maven_detail(&state.storage, &path).await;
    Html(render_maven_detail(&path, &detail, lang, auth_enabled))
}

// npm pages
async fn npm_list(
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    let detail = get_npm_detail(&state.storage, &name).await;
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
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    let detail = get_cargo_detail(&state.storage, &name).await;
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
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    let detail = get_pypi_detail(&state.storage, &name).await;
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
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_list(&query, headers.get("cookie").and_then(|v| v.to_str().ok()));
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
    let auth_enabled = state.auth.is_some();

    let all_modules = state.repo_index.get("go", &state.storage).await;
    let (modules, total) = paginate(&all_modules, page, limit);

    Html(render_registry_list_paginated(
        "go",
        "Go Modules",
        &modules,
        page,
        limit,
        total,
        lang,
        auth_enabled,
    ))
}

async fn go_detail(
    State(state): State<Arc<AppState>>,
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
    let detail = get_go_detail(&state.storage, &name).await;
    Html(render_package_detail(
        "go",
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// Raw pages
async fn raw_list(
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    State(state): State<Arc<AppState>>,
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
    let title = match registry_key {
        "gems" => "RubyGems",
        "terraform" => "Terraform Registry",
        "ansible" => "Ansible Galaxy",
        "nuget" => "NuGet Gallery",
        "pub" => "Pub (Dart/Flutter)",
        "conan" => "Conan (C/C++)",
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
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let base_url = resolve_base_url(&state);
    let auth_enabled = state.auth.is_some();

    // Extract registry type from URI: /ui/{type}/{name}
    let registry_key = uri
        .path()
        .strip_prefix("/ui/")
        .and_then(|s| s.split('/').next())
        .unwrap_or("raw");

    let detail = get_generic_detail(&state.storage, registry_key, &name).await;
    Html(render_package_detail(
        registry_key,
        &name,
        &detail,
        lang,
        &base_url,
        auth_enabled,
    ))
}

// ==================== Token Management Handlers ====================

/// Token management page (GET /ui/tokens)
async fn tokens_page(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_headers(&headers);

    let tokens = match &state.tokens {
        Some(store) => store.list_all_tokens(),
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

async fn tokens_create(
    State(state): State<Arc<AppState>>,
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

    // Get authenticated user from Basic Auth header
    let user = extract_basic_auth_user(&headers).unwrap_or_else(|| "admin".to_string());

    let role = match form.role.as_str() {
        "read" => Role::Read,
        "write" => Role::Write,
        "admin" => Role::Admin,
        _ => Role::Read,
    };

    let ttl_days = form.ttl_days.unwrap_or(90).clamp(1, 3650);

    let description = if form.description.trim().is_empty() {
        None
    } else {
        Some(form.description.trim().to_string())
    };

    match store.create_token(&user, ttl_days, description, role) {
        Ok(raw_token) => {
            let html = render_token_created_fragment(&raw_token, lang);
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
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang_from_headers(&headers);

    let tokens = match &state.tokens {
        Some(store) => store.list_all_tokens(),
        None => vec![],
    };

    Html(render_token_list_fragment(&tokens, lang))
}

/// Revoke token (POST /api/ui/tokens/{file_id}/revoke)
async fn tokens_revoke(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
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

    match store.revoke_token(&file_id) {
        Ok(()) => {
            // Return refreshed token list
            let tokens = store.list_all_tokens();
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
