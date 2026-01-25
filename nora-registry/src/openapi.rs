//! OpenAPI documentation and Swagger UI
//!
//! Functions in this module are stubs used only for generating OpenAPI documentation.

#![allow(dead_code)]

use axum::Router;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Nora",
        version = "0.1.0",
        description = "Multi-protocol package registry supporting Docker, Maven, npm, Cargo, and PyPI",
        license(name = "MIT"),
        contact(name = "DevITWay", url = "https://github.com/getnora-io/nora")
    ),
    servers(
        (url = "/", description = "Current server")
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "docker", description = "Docker Registry v2 API"),
        (name = "maven", description = "Maven Repository API"),
        (name = "npm", description = "npm Registry API"),
        (name = "cargo", description = "Cargo Registry API"),
        (name = "pypi", description = "PyPI Simple API"),
        (name = "auth", description = "Authentication & API Tokens")
    ),
    paths(
        // Health
        crate::openapi::health_check,
        crate::openapi::readiness_check,
        // Docker
        crate::openapi::docker_version,
        crate::openapi::docker_catalog,
        crate::openapi::docker_tags,
        crate::openapi::docker_manifest,
        crate::openapi::docker_blob,
        // Maven
        crate::openapi::maven_artifact,
        // npm
        crate::openapi::npm_package,
        // PyPI
        crate::openapi::pypi_simple,
        crate::openapi::pypi_package,
        // Tokens
        crate::openapi::create_token,
        crate::openapi::list_tokens,
        crate::openapi::revoke_token,
    ),
    components(
        schemas(
            HealthResponse,
            StorageHealth,
            RegistriesHealth,
            DockerVersion,
            DockerCatalog,
            DockerTags,
            TokenRequest,
            TokenResponse,
            TokenListResponse,
            TokenInfo,
            ErrorResponse
        )
    )
)]
pub struct ApiDoc;

// ============ Schemas ============

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Current health status
    pub status: String,
    /// Application version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Storage backend health
    pub storage: StorageHealth,
    /// Registry health status
    pub registries: RegistriesHealth,
}

#[derive(Serialize, ToSchema)]
pub struct StorageHealth {
    /// Backend type (local, s3)
    pub backend: String,
    /// Whether storage is reachable
    pub reachable: bool,
    /// Storage endpoint/path
    pub endpoint: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegistriesHealth {
    pub docker: String,
    pub maven: String,
    pub npm: String,
    pub cargo: String,
    pub pypi: String,
}

#[derive(Serialize, ToSchema)]
pub struct DockerVersion {
    /// API version
    #[serde(rename = "Docker-Distribution-API-Version")]
    pub version: String,
}

#[derive(Serialize, ToSchema)]
pub struct DockerCatalog {
    /// List of repository names
    pub repositories: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DockerTags {
    /// Repository name
    pub name: String,
    /// List of tags
    pub tags: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// Token TTL in days (default: 30)
    #[serde(default = "default_ttl")]
    pub ttl_days: u32,
    /// Optional description
    pub description: Option<String>,
}

fn default_ttl() -> u32 {
    30
}

#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    /// Generated API token (starts with nra_)
    pub token: String,
    /// Token expiration in days
    pub expires_in_days: u32,
}

#[derive(Serialize, ToSchema)]
pub struct TokenListResponse {
    /// List of tokens
    pub tokens: Vec<TokenInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct TokenInfo {
    /// Token hash prefix (for identification)
    pub hash_prefix: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Last used timestamp
    pub last_used: Option<u64>,
    /// Description
    pub description: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

// ============ Path Operations (documentation only) ============

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is unhealthy", body = HealthResponse)
    )
)]
pub async fn health_check() {}

/// Readiness probe
#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    responses(
        (status = 200, description = "Service is ready"),
        (status = 503, description = "Service is not ready")
    )
)]
pub async fn readiness_check() {}

/// Docker Registry version check
#[utoipa::path(
    get,
    path = "/v2/",
    tag = "docker",
    responses(
        (status = 200, description = "Registry is available", body = DockerVersion),
        (status = 401, description = "Authentication required")
    )
)]
pub async fn docker_version() {}

/// List all repositories
#[utoipa::path(
    get,
    path = "/v2/_catalog",
    tag = "docker",
    responses(
        (status = 200, description = "Repository list", body = DockerCatalog)
    )
)]
pub async fn docker_catalog() {}

/// List tags for a repository
#[utoipa::path(
    get,
    path = "/v2/{name}/tags/list",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name")
    ),
    responses(
        (status = 200, description = "Tag list", body = DockerTags),
        (status = 404, description = "Repository not found")
    )
)]
pub async fn docker_tags() {}

/// Get manifest
#[utoipa::path(
    get,
    path = "/v2/{name}/manifests/{reference}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("reference" = String, Path, description = "Tag or digest")
    ),
    responses(
        (status = 200, description = "Manifest content"),
        (status = 404, description = "Manifest not found")
    )
)]
pub async fn docker_manifest() {}

/// Get blob
#[utoipa::path(
    get,
    path = "/v2/{name}/blobs/{digest}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("digest" = String, Path, description = "Blob digest (sha256:...)")
    ),
    responses(
        (status = 200, description = "Blob content"),
        (status = 404, description = "Blob not found")
    )
)]
pub async fn docker_blob() {}

/// Get Maven artifact
#[utoipa::path(
    get,
    path = "/maven2/{path}",
    tag = "maven",
    params(
        ("path" = String, Path, description = "Artifact path (e.g., org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar)")
    ),
    responses(
        (status = 200, description = "Artifact content"),
        (status = 404, description = "Artifact not found, trying upstream proxies")
    )
)]
pub async fn maven_artifact() {}

/// Get npm package metadata
#[utoipa::path(
    get,
    path = "/npm/{name}",
    tag = "npm",
    params(
        ("name" = String, Path, description = "Package name")
    ),
    responses(
        (status = 200, description = "Package metadata (JSON)"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn npm_package() {}

/// PyPI Simple index
#[utoipa::path(
    get,
    path = "/simple/",
    tag = "pypi",
    responses(
        (status = 200, description = "HTML list of packages")
    )
)]
pub async fn pypi_simple() {}

/// PyPI package page
#[utoipa::path(
    get,
    path = "/simple/{name}/",
    tag = "pypi",
    params(
        ("name" = String, Path, description = "Package name")
    ),
    responses(
        (status = 200, description = "HTML list of package files"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn pypi_package() {}

/// Create API token
#[utoipa::path(
    post,
    path = "/api/tokens",
    tag = "auth",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token created", body = TokenResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 400, description = "Auth not configured", body = ErrorResponse)
    )
)]
pub async fn create_token() {}

/// List user's tokens
#[utoipa::path(
    post,
    path = "/api/tokens/list",
    tag = "auth",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token list", body = TokenListResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse)
    )
)]
pub async fn list_tokens() {}

/// Revoke a token
#[utoipa::path(
    post,
    path = "/api/tokens/revoke",
    tag = "auth",
    responses(
        (status = 200, description = "Token revoked"),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 404, description = "Token not found", body = ErrorResponse)
    )
)]
pub async fn revoke_token() {}

// ============ Routes ============

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(SwaggerUi::new("/api-docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
}
