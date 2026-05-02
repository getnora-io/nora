// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! OpenAPI documentation and Swagger UI
//!
//! Functions in this module are stubs used only for generating OpenAPI documentation.

#![allow(dead_code)] // utoipa doc stubs — not called at runtime, used by derive macros

use axum::Router;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::activity_log::ActivityEntry;
use crate::auth::{TokenListItem, TokenListResponse};
use crate::health::StorageHealth;
use crate::ui::api::{DashboardResponse, GlobalStats, MountPoint, RegistryCardStats};
use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Nora",
        version = "0.8.0",
        description = "Multi-protocol package registry supporting Docker, Maven, npm, Cargo, PyPI, Go, Raw, RubyGems, Terraform, Ansible, NuGet, pub.dev, and Conan",
        license(name = "MIT"),
        contact(name = "The NORA Authors", url = "https://getnora.dev")
    ),
    servers(
        (url = "/", description = "Current server")
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "metrics", description = "Prometheus metrics"),
        (name = "dashboard", description = "Dashboard & Metrics API"),
        (name = "docker", description = "Docker Registry v2 API"),
        (name = "maven", description = "Maven Repository API"),
        (name = "npm", description = "npm Registry API"),
        (name = "cargo", description = "Cargo Registry API"),
        (name = "pypi", description = "PyPI Simple API"),
        (name = "go", description = "Go Module Proxy API"),
        (name = "raw", description = "Raw File Storage API"),
        (name = "gems", description = "RubyGems Proxy API"),
        (name = "terraform", description = "Terraform Registry Proxy API"),
        (name = "ansible", description = "Ansible Galaxy Proxy API"),
        (name = "nuget", description = "NuGet v3 Registry Proxy API"),
        (name = "pub", description = "Dart/Flutter Pub Registry Proxy API"),
        (name = "conan", description = "Conan V2 Registry Proxy API (C/C++)"),
        (name = "auth", description = "Authentication & API Tokens")
    ),
    paths(
        // Health
        crate::openapi::health_check,
        crate::openapi::readiness_check,
        // Metrics
        crate::openapi::prometheus_metrics,
        // Dashboard
        crate::openapi::dashboard_metrics,
        // Docker - Read
        crate::openapi::docker_version,
        crate::openapi::docker_catalog,
        crate::openapi::docker_tags,
        crate::openapi::docker_manifest_get,
        crate::openapi::docker_blob_head,
        crate::openapi::docker_blob_get,
        // Docker - Write
        crate::openapi::docker_manifest_put,
        crate::openapi::docker_manifest_delete,
        crate::openapi::docker_blob_upload_start,
        crate::openapi::docker_blob_upload_patch,
        crate::openapi::docker_blob_upload_put,
        // Maven
        crate::openapi::maven_artifact_get,
        crate::openapi::maven_artifact_put,
        // npm
        crate::openapi::npm_package,
        crate::openapi::npm_publish,
        // Cargo
        crate::openapi::cargo_index_config,
        crate::openapi::cargo_sparse_index,
        crate::openapi::cargo_metadata,
        crate::openapi::cargo_download,
        crate::openapi::cargo_publish,
        // PyPI
        crate::openapi::pypi_simple,
        crate::openapi::pypi_package,
        crate::openapi::pypi_upload,
        // Go
        crate::openapi::go_module_latest,
        crate::openapi::go_module_info,
        crate::openapi::go_module_mod,
        crate::openapi::go_module_zip,
        // Raw
        crate::openapi::raw_file_get,
        crate::openapi::raw_file_put,
        // RubyGems
        crate::openapi::gems_info,
        crate::openapi::gems_download,
        // Terraform
        crate::openapi::terraform_service_discovery,
        crate::openapi::terraform_provider_versions,
        // Ansible Galaxy
        crate::openapi::ansible_collection_list,
        crate::openapi::ansible_download,
        // NuGet
        crate::openapi::nuget_service_index,
        crate::openapi::nuget_download,
        // Pub (Dart/Flutter)
        crate::openapi::pub_package_list,
        crate::openapi::pub_archive_download,
        // Conan (C/C++)
        crate::openapi::conan_ping,
        crate::openapi::conan_recipe_file,
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
            DashboardResponse,
            GlobalStats,
            RegistryCardStats,
            MountPoint,
            ActivityEntry,
            DockerVersion,
            DockerCatalog,
            DockerTags,
            TokenRequest,
            TokenResponse,
            TokenListResponse,
            TokenListItem,
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
pub struct RegistriesHealth {
    pub docker: String,
    pub maven: String,
    pub npm: String,
    pub cargo: String,
    pub pypi: String,
    pub go: String,
    pub raw: String,
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
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

// ============ Path Operations (documentation only) ============

// -------------------- Health --------------------

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

// -------------------- Metrics --------------------

/// Prometheus metrics endpoint
///
/// Returns metrics in Prometheus text format for scraping.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "metrics",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    )
)]
pub async fn prometheus_metrics() {}

// -------------------- Dashboard --------------------

/// Dashboard metrics and activity
///
/// Returns comprehensive metrics including downloads, uploads, cache statistics,
/// per-registry stats, mount points configuration, and recent activity log.
#[utoipa::path(
    get,
    path = "/api/ui/dashboard",
    tag = "dashboard",
    responses(
        (status = 200, description = "Dashboard metrics", body = DashboardResponse)
    )
)]
pub async fn dashboard_metrics() {}

// -------------------- Docker Registry v2 - Read Operations --------------------

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
        ("name" = String, Path, description = "Repository name (e.g., 'alpine' or 'library/nginx')")
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
        ("reference" = String, Path, description = "Tag or digest (sha256:...)")
    ),
    responses(
        (status = 200, description = "Manifest content"),
        (status = 404, description = "Manifest not found")
    )
)]
pub async fn docker_manifest_get() {}

/// Check if blob exists
#[utoipa::path(
    head,
    path = "/v2/{name}/blobs/{digest}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("digest" = String, Path, description = "Blob digest (sha256:...)")
    ),
    responses(
        (status = 200, description = "Blob exists, Content-Length header contains size"),
        (status = 404, description = "Blob not found")
    )
)]
pub async fn docker_blob_head() {}

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
pub async fn docker_blob_get() {}

// -------------------- Docker Registry v2 - Write Operations --------------------

/// Push manifest
#[utoipa::path(
    put,
    path = "/v2/{name}/manifests/{reference}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("reference" = String, Path, description = "Tag or digest")
    ),
    responses(
        (status = 201, description = "Manifest created, Docker-Content-Digest header contains digest"),
        (status = 400, description = "Invalid manifest")
    )
)]
pub async fn docker_manifest_put() {}

/// Delete manifest
#[utoipa::path(
    delete,
    path = "/v2/{name}/manifests/{reference}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("reference" = String, Path, description = "Tag or digest (sha256:...)")
    ),
    responses(
        (status = 202, description = "Manifest deleted"),
        (status = 404, description = "Manifest not found")
    )
)]
pub async fn docker_manifest_delete() {}

/// Start blob upload
///
/// Initiates a resumable blob upload. Returns a Location header with the upload URL.
#[utoipa::path(
    post,
    path = "/v2/{name}/blobs/uploads/",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name")
    ),
    responses(
        (status = 202, description = "Upload started, Location header contains upload URL")
    )
)]
pub async fn docker_blob_upload_start() {}

/// Upload blob chunk (chunked upload)
///
/// Uploads a chunk of data to an in-progress upload session.
#[utoipa::path(
    patch,
    path = "/v2/{name}/blobs/uploads/{uuid}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("uuid" = String, Path, description = "Upload session UUID")
    ),
    responses(
        (status = 202, description = "Chunk accepted, Range header indicates bytes received")
    )
)]
pub async fn docker_blob_upload_patch() {}

/// Complete blob upload
///
/// Finalizes the blob upload. Can include final chunk data in the body.
#[utoipa::path(
    put,
    path = "/v2/{name}/blobs/uploads/{uuid}",
    tag = "docker",
    params(
        ("name" = String, Path, description = "Repository name"),
        ("uuid" = String, Path, description = "Upload session UUID"),
        ("digest" = String, Query, description = "Expected blob digest (sha256:...)")
    ),
    responses(
        (status = 201, description = "Blob created"),
        (status = 400, description = "Digest mismatch or missing")
    )
)]
pub async fn docker_blob_upload_put() {}

// -------------------- Maven --------------------

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
pub async fn maven_artifact_get() {}

/// Upload Maven artifact
#[utoipa::path(
    put,
    path = "/maven2/{path}",
    tag = "maven",
    params(
        ("path" = String, Path, description = "Artifact path")
    ),
    responses(
        (status = 201, description = "Artifact uploaded"),
        (status = 400, description = "Invalid path (non-ASCII characters)"),
        (status = 409, description = "Version already exists (immutable releases)"),
        (status = 500, description = "Storage error")
    )
)]
pub async fn maven_artifact_put() {}

// -------------------- npm --------------------

/// Get npm package metadata
#[utoipa::path(
    get,
    path = "/npm/{name}",
    tag = "npm",
    params(
        ("name" = String, Path, description = "Package name (e.g., 'lodash' or '@scope/package')")
    ),
    responses(
        (status = 200, description = "Package metadata (JSON)"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn npm_package() {}

/// Publish npm package
///
/// Accepts a full npm publish payload (packument with attachments).
#[utoipa::path(
    put,
    path = "/npm/{name}",
    tag = "npm",
    params(
        ("name" = String, Path, description = "Package name (e.g., 'lodash' or '@scope/package')")
    ),
    responses(
        (status = 200, description = "Package published"),
        (status = 409, description = "Version already exists"),
        (status = 400, description = "Invalid package data")
    )
)]
pub async fn npm_publish() {}

// -------------------- Cargo --------------------

/// Cargo sparse index configuration
///
/// Returns the registry configuration for sparse index protocol (RFC 2789).
#[utoipa::path(
    get,
    path = "/cargo/index/config.json",
    tag = "cargo",
    responses(
        (status = 200, description = "Sparse index configuration (JSON)")
    )
)]
pub async fn cargo_index_config() {}

/// Cargo sparse index lookup
///
/// Returns crate index entries for the sparse index protocol.
/// Path structure depends on crate name length (1/, 2/, 3/first-two/, etc.).
#[utoipa::path(
    get,
    path = "/cargo/index/{path}",
    tag = "cargo",
    params(
        ("path" = String, Path, description = "Sparse index path (e.g., 'se/rd/serde')")
    ),
    responses(
        (status = 200, description = "Crate index entries (one JSON per line)"),
        (status = 404, description = "Crate not found in index")
    )
)]
pub async fn cargo_sparse_index() {}

/// Get Cargo crate metadata
#[utoipa::path(
    get,
    path = "/cargo/api/v1/crates/{crate_name}",
    tag = "cargo",
    params(
        ("crate_name" = String, Path, description = "Crate name")
    ),
    responses(
        (status = 200, description = "Crate metadata (JSON)"),
        (status = 404, description = "Crate not found")
    )
)]
pub async fn cargo_metadata() {}

/// Download Cargo crate
#[utoipa::path(
    get,
    path = "/cargo/api/v1/crates/{crate_name}/{version}/download",
    tag = "cargo",
    params(
        ("crate_name" = String, Path, description = "Crate name"),
        ("version" = String, Path, description = "Crate version")
    ),
    responses(
        (status = 200, description = "Crate file (.crate)"),
        (status = 404, description = "Crate version not found")
    )
)]
pub async fn cargo_download() {}

/// Publish Cargo crate
///
/// Accepts a crate publish payload (metadata + .crate tarball).
#[utoipa::path(
    put,
    path = "/cargo/api/v1/crates/new",
    tag = "cargo",
    responses(
        (status = 200, description = "Crate published"),
        (status = 409, description = "Version already exists"),
        (status = 400, description = "Invalid crate data")
    )
)]
pub async fn cargo_publish() {}

// -------------------- PyPI --------------------

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

/// Upload Python package
///
/// Accepts a multipart form upload (twine-compatible).
#[utoipa::path(
    post,
    path = "/simple/",
    tag = "pypi",
    responses(
        (status = 200, description = "Package uploaded"),
        (status = 409, description = "Version already exists"),
        (status = 400, description = "Invalid upload data")
    )
)]
pub async fn pypi_upload() {}

// -------------------- Go Modules --------------------

/// Get latest version of a Go module
#[utoipa::path(
    get,
    path = "/go/{module}/@latest",
    tag = "go",
    params(
        ("module" = String, Path, description = "Module path (e.g., 'golang.org/x/text')")
    ),
    responses(
        (status = 200, description = "Latest version info (JSON)"),
        (status = 404, description = "Module not found")
    )
)]
pub async fn go_module_latest() {}

/// Get Go module version info
#[utoipa::path(
    get,
    path = "/go/{module}/@v/{version}.info",
    tag = "go",
    params(
        ("module" = String, Path, description = "Module path"),
        ("version" = String, Path, description = "Module version (e.g., 'v1.14.0')")
    ),
    responses(
        (status = 200, description = "Version info (JSON)"),
        (status = 404, description = "Version not found")
    )
)]
pub async fn go_module_info() {}

/// Get Go module go.mod file
#[utoipa::path(
    get,
    path = "/go/{module}/@v/{version}.mod",
    tag = "go",
    params(
        ("module" = String, Path, description = "Module path"),
        ("version" = String, Path, description = "Module version")
    ),
    responses(
        (status = 200, description = "go.mod file content"),
        (status = 404, description = "Version not found")
    )
)]
pub async fn go_module_mod() {}

/// Download Go module zip
#[utoipa::path(
    get,
    path = "/go/{module}/@v/{version}.zip",
    tag = "go",
    params(
        ("module" = String, Path, description = "Module path"),
        ("version" = String, Path, description = "Module version")
    ),
    responses(
        (status = 200, description = "Module zip archive"),
        (status = 404, description = "Version not found")
    )
)]
pub async fn go_module_zip() {}

// -------------------- Raw Files --------------------

/// Get raw file
#[utoipa::path(
    get,
    path = "/raw/{path}",
    tag = "raw",
    params(
        ("path" = String, Path, description = "File path (e.g., 'myproject/config.yaml')")
    ),
    responses(
        (status = 200, description = "File content"),
        (status = 404, description = "File not found")
    )
)]
pub async fn raw_file_get() {}

/// Upload raw file
#[utoipa::path(
    put,
    path = "/raw/{path}",
    tag = "raw",
    params(
        ("path" = String, Path, description = "File path")
    ),
    responses(
        (status = 201, description = "File uploaded"),
        (status = 400, description = "Invalid path (non-ASCII characters)"),
        (status = 409, description = "File already exists (immutable)"),
        (status = 413, description = "File too large"),
        (status = 500, description = "Storage error")
    )
)]
pub async fn raw_file_put() {}

// -------------------- RubyGems --------------------

/// Get gem compact index
#[utoipa::path(
    get,
    path = "/gems/info/{name}",
    tag = "gems",
    params(
        ("name" = String, Path, description = "Gem name (e.g., 'rails')")
    ),
    responses(
        (status = 200, description = "Compact index for gem"),
        (status = 404, description = "Gem not found")
    )
)]
pub async fn gems_info() {}

/// Download gem file
#[utoipa::path(
    get,
    path = "/gems/gems/{filename}",
    tag = "gems",
    params(
        ("filename" = String, Path, description = "Gem file (e.g., 'rails-7.0.0.gem')")
    ),
    responses(
        (status = 200, description = "Gem binary"),
        (status = 404, description = "Gem not found")
    )
)]
pub async fn gems_download() {}

// -------------------- Terraform --------------------

/// Terraform service discovery
#[utoipa::path(
    get,
    path = "/terraform/.well-known/terraform.json",
    tag = "terraform",
    responses(
        (status = 200, description = "Service discovery JSON")
    )
)]
pub async fn terraform_service_discovery() {}

/// List Terraform provider versions
#[utoipa::path(
    get,
    path = "/terraform/v1/providers/{ns}/{ptype}/versions",
    tag = "terraform",
    params(
        ("ns" = String, Path, description = "Provider namespace"),
        ("ptype" = String, Path, description = "Provider type")
    ),
    responses(
        (status = 200, description = "Version list"),
        (status = 404, description = "Provider not found")
    )
)]
pub async fn terraform_provider_versions() {}

// -------------------- Ansible Galaxy --------------------

/// List Ansible Galaxy collections
#[utoipa::path(
    get,
    path = "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
    tag = "ansible",
    responses(
        (status = 200, description = "Collection list"),
        (status = 502, description = "Upstream unreachable")
    )
)]
pub async fn ansible_collection_list() {}

/// Download Ansible collection tarball
#[utoipa::path(
    get,
    path = "/ansible/download/{filename}",
    tag = "ansible",
    params(
        ("filename" = String, Path, description = "Collection tarball (e.g., 'community-general-7.0.0.tar.gz')")
    ),
    responses(
        (status = 200, description = "Collection tarball"),
        (status = 404, description = "Collection not found")
    )
)]
pub async fn ansible_download() {}

// -------------------- NuGet --------------------

/// NuGet v3 service index
#[utoipa::path(
    get,
    path = "/nuget/v3/index.json",
    tag = "nuget",
    responses(
        (status = 200, description = "Service index JSON with @id URLs rewritten")
    )
)]
pub async fn nuget_service_index() {}

/// Download NuGet package
#[utoipa::path(
    get,
    path = "/nuget/v3/flatcontainer/{path}",
    tag = "nuget",
    params(
        ("path" = String, Path, description = "Package path (e.g., 'newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg')")
    ),
    responses(
        (status = 200, description = "Package file (.nupkg or .nuspec)"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn nuget_download() {}

// -------------------- Pub (Dart/Flutter) --------------------

/// List or search pub packages
#[utoipa::path(
    get,
    path = "/pub/api/packages/{package}",
    tag = "pub",
    params(
        ("package" = String, Path, description = "Package name")
    ),
    responses(
        (status = 200, description = "Package metadata with versions"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn pub_package_list() {}

/// Download pub package archive
#[utoipa::path(
    get,
    path = "/pub/packages/{package}/versions/{archive}",
    tag = "pub",
    params(
        ("package" = String, Path, description = "Package name"),
        ("archive" = String, Path, description = "Version archive (e.g., '1.2.0.tar.gz')")
    ),
    responses(
        (status = 200, description = "Package archive (.tar.gz)"),
        (status = 404, description = "Package not found")
    )
)]
pub async fn pub_archive_download() {}

// -------------------- Conan --------------------

/// Conan v2 ping (capabilities check)
#[utoipa::path(
    get,
    path = "/conan/v2/ping",
    tag = "conan",
    responses(
        (status = 200, description = "Ping response with X-Conan-Server-Capabilities header")
    )
)]
pub async fn conan_ping() {}

/// Download a Conan recipe or package file
#[utoipa::path(
    get,
    path = "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files/{filename}",
    tag = "conan",
    params(
        ("name" = String, Path, description = "Package name"),
        ("ver" = String, Path, description = "Package version"),
        ("user" = String, Path, description = "User (or _ for default)"),
        ("chan" = String, Path, description = "Channel (or _ for default)"),
        ("rrev" = String, Path, description = "Recipe revision hash"),
        ("filename" = String, Path, description = "File name (e.g., conanfile.py)")
    ),
    responses(
        (status = 200, description = "File content"),
        (status = 404, description = "File not found")
    )
)]
pub async fn conan_recipe_file() {}

// -------------------- Auth / Tokens --------------------

/// Create API token
#[utoipa::path(
    post,
    path = "/api/tokens",
    tag = "auth",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token created", body = TokenResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 422, description = "Missing required fields", body = ErrorResponse),
        (status = 503, description = "Auth not configured", body = ErrorResponse)
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
