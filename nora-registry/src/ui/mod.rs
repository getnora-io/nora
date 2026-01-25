mod api;
mod components;
mod templates;

use crate::AppState;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use std::sync::Arc;

use api::*;
use templates::*;

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
        .route("/api/ui/{registry_type}/list", get(api_list))
        .route("/api/ui/{registry_type}/{name}", get(api_detail))
        .route("/api/ui/{registry_type}/search", get(api_search))
}

// Dashboard page
async fn dashboard(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = get_registry_stats(&state.storage).await;
    Html(render_dashboard(&stats))
}

// Docker pages
async fn docker_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let repos = get_docker_repos(&state.storage).await;
    Html(render_registry_list("docker", "Docker Registry", &repos))
}

async fn docker_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let detail = get_docker_detail(&state.storage, &name).await;
    Html(render_docker_detail(&name, &detail))
}

// Maven pages
async fn maven_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let repos = get_maven_repos(&state.storage).await;
    Html(render_registry_list("maven", "Maven Repository", &repos))
}

async fn maven_detail(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let detail = get_maven_detail(&state.storage, &path).await;
    Html(render_maven_detail(&path, &detail))
}

// npm pages
async fn npm_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packages = get_npm_packages(&state.storage).await;
    Html(render_registry_list("npm", "npm Registry", &packages))
}

async fn npm_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let detail = get_npm_detail(&state.storage, &name).await;
    Html(render_package_detail("npm", &name, &detail))
}

// Cargo pages
async fn cargo_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let crates = get_cargo_crates(&state.storage).await;
    Html(render_registry_list("cargo", "Cargo Registry", &crates))
}

async fn cargo_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let detail = get_cargo_detail(&state.storage, &name).await;
    Html(render_package_detail("cargo", &name, &detail))
}

// PyPI pages
async fn pypi_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let packages = get_pypi_packages(&state.storage).await;
    Html(render_registry_list("pypi", "PyPI Repository", &packages))
}

async fn pypi_detail(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let detail = get_pypi_detail(&state.storage, &name).await;
    Html(render_package_detail("pypi", &name, &detail))
}
