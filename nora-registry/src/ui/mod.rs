// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod api;
pub mod components;
pub mod i18n;
mod logo;
mod templates;

use crate::repo_index::paginate;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use std::sync::Arc;

use api::*;
use i18n::Lang;
use templates::*;

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
    let response = api_dashboard(State(state)).await.0;
    Html(render_dashboard(&response, lang))
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
    let detail = get_docker_detail(&state, &name).await;
    Html(render_docker_detail(&name, &detail, lang))
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
    let detail = get_maven_detail(&state.storage, &path).await;
    Html(render_maven_detail(&path, &detail, lang))
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
    let detail = get_npm_detail(&state.storage, &name).await;
    Html(render_package_detail("npm", &name, &detail, lang))
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
    let detail = get_cargo_detail(&state.storage, &name).await;
    Html(render_package_detail("cargo", &name, &detail, lang))
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
    let detail = get_pypi_detail(&state.storage, &name).await;
    Html(render_package_detail("pypi", &name, &detail, lang))
}
