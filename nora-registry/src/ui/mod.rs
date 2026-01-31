// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod api;
mod components;
pub mod i18n;
mod logo;
mod templates;

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
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let repos = get_docker_repos(&state.storage).await;
    Html(render_registry_list(
        "docker",
        "Docker Registry",
        &repos,
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
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let repos = get_maven_repos(&state.storage).await;
    Html(render_registry_list(
        "maven",
        "Maven Repository",
        &repos,
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
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let packages = get_npm_packages(&state.storage).await;
    Html(render_registry_list("npm", "npm Registry", &packages, lang))
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
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let crates = get_cargo_crates(&state.storage).await;
    Html(render_registry_list(
        "cargo",
        "Cargo Registry",
        &crates,
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
    Query(query): Query<LangQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let lang = extract_lang(
        &Query(query),
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    );
    let packages = get_pypi_packages(&state.storage).await;
    Html(render_registry_list(
        "pypi",
        "PyPI Repository",
        &packages,
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
