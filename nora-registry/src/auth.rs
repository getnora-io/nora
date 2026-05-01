// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::tokens::Role;
use crate::AppState;

/// Htpasswd-based authentication
#[derive(Clone)]
pub struct HtpasswdAuth {
    users: HashMap<String, String>, // username -> bcrypt hash
}

impl HtpasswdAuth {
    /// Load users from htpasswd file
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut users = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((username, hash)) = line.split_once(':') {
                users.insert(username.to_string(), hash.to_string());
            }
        }

        if users.is_empty() {
            None
        } else {
            Some(Self { users })
        }
    }

    /// Verify username and password
    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        if let Some(hash) = self.users.get(username) {
            bcrypt::verify(password, hash).unwrap_or(false)
        } else {
            false
        }
    }

    /// Get list of usernames
    pub fn list_users(&self) -> Vec<&str> {
        self.users.keys().map(|s| s.as_str()).collect()
    }
}

/// Check if path is public (no auth required)
fn is_public_path(path: &str) -> bool {
    // Token UI pages require auth — exclude before wildcard match
    if path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens") {
        return false;
    }

    matches!(
        path,
        "/" | "/health"
            | "/ready"
            | "/metrics"
            | "/api/tokens"
            | "/api/tokens/list"
            | "/api/tokens/revoke"
    ) || path.starts_with("/ui")
        || path.starts_with("/api-docs")
        || path.starts_with("/api/ui")
}

/// Check if path is a Docker V2 auth challenge endpoint.
/// Per Docker Registry V2 spec, /v2/ must return 401 with WWW-Authenticate
/// header when auth is enabled, so Docker clients know to send credentials.
fn is_docker_auth_challenge_path(path: &str) -> bool {
    matches!(path, "/v2/" | "/v2")
}

/// Auth middleware - supports Basic auth and Bearer tokens
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth if disabled
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return next.run(request).await,
    };

    // Skip auth for public endpoints
    if is_public_path(request.uri().path()) {
        return next.run(request).await;
    }

    // Docker V2 auth challenge: /v2/ must NOT bypass auth via anonymous_read.
    // Per Docker Registry V2 spec, unauthenticated GET /v2/ must return 401
    // with WWW-Authenticate header, so Docker clients send credentials on
    // subsequent requests. If /v2/ returns 200 without auth, Docker assumes
    // the registry is anonymous and never sends Authorization headers.
    let is_docker_challenge = is_docker_auth_challenge_path(request.uri().path());

    // Allow anonymous read if configured (but not for Docker /v2/ endpoint)
    let is_read_method = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    );
    if state.config.auth.anonymous_read && is_read_method && !is_docker_challenge {
        // Read requests allowed without auth
        return next.run(request).await;
    }

    // Compute realm from public_url for WWW-Authenticate header
    let realm = state.config.server.public_url.as_deref().unwrap_or("Nora");

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => return unauthorized_response("Authentication required", realm),
    };

    // Try Bearer token first
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        if let Some(ref token_store) = state.tokens {
            match token_store.verify_token(token) {
                Ok((_user, role)) => {
                    let method = request.method().clone();
                    if (method == axum::http::Method::PUT
                        || method == axum::http::Method::POST
                        || method == axum::http::Method::DELETE
                        || method == axum::http::Method::PATCH)
                        && !role.can_write()
                    {
                        return (StatusCode::FORBIDDEN, "Read-only token").into_response();
                    }
                    return next.run(request).await;
                }
                Err(_) => return unauthorized_response("Invalid or expired token", realm),
            }
        } else {
            return unauthorized_response("Token authentication not configured", realm);
        }
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return unauthorized_response("Basic or Bearer authentication required", realm);
    }

    let encoded = &auth_header[6..];
    let decoded = match STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return unauthorized_response("Invalid credentials encoding", realm),
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(c) => c,
        Err(_) => return unauthorized_response("Invalid credentials encoding", realm),
    };

    let (username, password) = match credentials.split_once(':') {
        Some((u, p)) => (u, p),
        None => return unauthorized_response("Invalid credentials format", realm),
    };

    // Verify credentials
    if !auth.authenticate(username, password) {
        return unauthorized_response("Invalid username or password", realm);
    }

    // Auth successful
    next.run(request).await
}

fn unauthorized_response(message: &str, realm: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                format!("Basic realm=\"{}\"", realm),
            ),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        format!(r#"{{"error":"{}"}}"#, message),
    )
        .into_response()
}

/// Generate bcrypt hash for password (for CLI user management)
#[allow(dead_code)]
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

// Token management API routes
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub username: String,
    pub password: String,
    #[serde(default = "default_ttl")]
    pub ttl_days: u64,
    pub description: Option<String>,
    #[serde(default = "default_role_str")]
    pub role: String,
}

fn default_role_str() -> String {
    "read".to_string()
}

fn default_ttl() -> u64 {
    30
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub expires_in_days: u64,
}

#[derive(Serialize, ToSchema)]
#[schema(as = TokenInfo)]
pub struct TokenListItem {
    pub hash_prefix: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
    pub role: String,
}

#[derive(Serialize, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenListItem>,
}

/// Create a new API token (requires Basic auth)
async fn create_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    // Verify user credentials first
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let token_store = match &state.tokens {
        Some(ts) => ts,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Token storage not configured",
            )
                .into_response()
        }
    };

    let role = match req.role.as_str() {
        "read" => Role::Read,
        "write" => Role::Write,
        "admin" => Role::Admin,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid role. Use: read, write, admin",
            )
                .into_response()
        }
    };
    match token_store.create_token(&req.username, req.ttl_days, req.description, role) {
        Ok(token) => Json(CreateTokenResponse {
            token,
            expires_in_days: req.ttl_days,
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// List tokens for authenticated user
async fn list_tokens(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let token_store = match &state.tokens {
        Some(ts) => ts,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Token storage not configured",
            )
                .into_response()
        }
    };

    let tokens: Vec<TokenListItem> = token_store
        .list_tokens(&req.username)
        .into_iter()
        .map(|t| TokenListItem {
            hash_prefix: t.file_id,
            created_at: t.created_at,
            expires_at: t.expires_at,
            last_used: t.last_used,
            description: t.description,
            role: t.role.to_string(),
        })
        .collect();

    Json(TokenListResponse { tokens }).into_response()
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub username: String,
    pub password: String,
    pub hash_prefix: String,
}

/// Revoke a token
async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> Response {
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let token_store = match &state.tokens {
        Some(ts) => ts,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Token storage not configured",
            )
                .into_response()
        }
    };

    match token_store.revoke_token(&req.hash_prefix) {
        Ok(()) => (StatusCode::OK, "Token revoked").into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

/// Token management routes
pub fn token_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tokens", post(create_token))
        .route("/api/tokens/list", post(list_tokens))
        .route("/api/tokens/revoke", post(revoke_token))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_htpasswd(entries: &[(&str, &str)]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        for (username, password) in entries {
            let hash = bcrypt::hash(password, 4).unwrap(); // cost=4 for speed in tests
            writeln!(file, "{}:{}", username, hash).unwrap();
        }
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_htpasswd_loading() {
        let file = create_test_htpasswd(&[("admin", "secret"), ("user", "password")]);

        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        let users = auth.list_users();
        assert_eq!(users.len(), 2);
        assert!(users.contains(&"admin"));
        assert!(users.contains(&"user"));
    }

    #[test]
    fn test_htpasswd_loading_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let auth = HtpasswdAuth::from_file(file.path());
        assert!(auth.is_none());
    }

    #[test]
    fn test_htpasswd_loading_with_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file).unwrap();
        let hash = bcrypt::hash("secret", 4).unwrap();
        writeln!(file, "admin:{}", hash).unwrap();
        file.flush().unwrap();

        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert_eq!(auth.list_users().len(), 1);
    }

    #[test]
    fn test_authenticate_valid() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(auth.authenticate("test", "secret"));
    }

    #[test]
    fn test_authenticate_invalid_password() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.authenticate("test", "wrong"));
    }

    #[test]
    fn test_authenticate_unknown_user() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.authenticate("unknown", "secret"));
    }

    #[test]
    fn test_is_public_path() {
        // Public paths
        assert!(is_public_path("/"));
        assert!(is_public_path("/health"));
        assert!(is_public_path("/ready"));
        assert!(is_public_path("/metrics"));
        assert!(is_public_path("/ui"));
        assert!(is_public_path("/ui/dashboard"));
        assert!(is_public_path("/api-docs"));
        assert!(is_public_path("/api-docs/openapi.json"));
        assert!(is_public_path("/api/ui/stats"));
        assert!(is_public_path("/api/tokens"));
        assert!(is_public_path("/api/tokens/list"));
        assert!(is_public_path("/api/tokens/revoke"));

        // Docker /v2/ is NOT public — requires auth challenge per V2 spec
        assert!(!is_public_path("/v2/"));
        assert!(!is_public_path("/v2"));

        // Token UI pages are NOT public (require auth)
        assert!(!is_public_path("/ui/tokens"));
        assert!(!is_public_path("/ui/tokens/"));
        assert!(!is_public_path("/api/ui/tokens/create"));
        assert!(!is_public_path("/api/ui/tokens/list"));
        assert!(!is_public_path("/api/ui/tokens/abc123/revoke"));

        // Protected paths
        assert!(!is_public_path("/api/tokens/unknown"));
        assert!(!is_public_path("/api/tokens/admin"));
        assert!(!is_public_path("/api/tokens/extra/path"));
        assert!(!is_public_path("/v2/myimage/blobs/sha256:abc"));
        assert!(!is_public_path("/v2/library/nginx/manifests/latest"));
        assert!(!is_public_path(
            "/maven2/com/example/artifact/1.0/artifact.jar"
        ));
        assert!(!is_public_path("/npm/lodash"));
    }

    #[test]
    fn test_hash_password() {
        let hash = hash_password("test123").unwrap();
        assert!(hash.starts_with("$2"));
        assert!(bcrypt::verify("test123", &hash).unwrap());
    }

    #[test]
    fn test_is_public_path_health() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/ready"));
        assert!(is_public_path("/metrics"));
    }

    #[test]
    fn test_v2_is_not_public_path() {
        // Docker /v2/ must NOT be public — it needs auth challenge per V2 spec
        assert!(!is_public_path("/v2/"));
        assert!(!is_public_path("/v2"));
        // But it IS a docker auth challenge path
        assert!(is_docker_auth_challenge_path("/v2/"));
        assert!(is_docker_auth_challenge_path("/v2"));
        // Sub-paths are neither public nor docker challenge
        assert!(!is_docker_auth_challenge_path(
            "/v2/alpine/manifests/latest"
        ));
    }

    #[test]
    fn test_is_public_path_ui() {
        assert!(is_public_path("/ui"));
        assert!(is_public_path("/ui/dashboard"));
        assert!(is_public_path("/ui/repos"));
    }

    #[test]
    fn test_is_public_path_api_docs() {
        assert!(is_public_path("/api-docs"));
        assert!(is_public_path("/api-docs/openapi.json"));
        assert!(is_public_path("/api/ui"));
    }

    #[test]
    fn test_is_public_path_tokens() {
        assert!(is_public_path("/api/tokens"));
        assert!(is_public_path("/api/tokens/list"));
        assert!(is_public_path("/api/tokens/revoke"));
    }

    #[test]
    fn test_is_public_path_root() {
        assert!(is_public_path("/"));
    }

    #[test]
    fn test_is_not_public_path_registry() {
        assert!(!is_public_path("/v2/library/alpine/manifests/latest"));
        assert!(!is_public_path("/npm/lodash"));
        assert!(!is_public_path("/maven/com/example"));
        assert!(!is_public_path("/pypi/simple/flask"));
    }

    #[test]
    fn test_is_not_public_path_random() {
        assert!(!is_public_path("/admin"));
        assert!(!is_public_path("/secret"));
        assert!(!is_public_path("/api/data"));
    }

    #[test]
    fn test_default_role_str() {
        assert_eq!(default_role_str(), "read");
    }

    #[test]
    fn test_default_ttl() {
        assert_eq!(default_ttl(), 30);
    }

    #[test]
    fn test_create_token_request_defaults() {
        let json = r#"{"username":"admin","password":"pass"}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "admin");
        assert_eq!(req.password, "pass");
        assert_eq!(req.ttl_days, 30);
        assert_eq!(req.role, "read");
        assert!(req.description.is_none());
    }

    #[test]
    fn test_create_token_request_custom() {
        let json = r#"{"username":"admin","password":"pass","ttl_days":90,"role":"write","description":"CI token"}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ttl_days, 90);
        assert_eq!(req.role, "write");
        assert_eq!(req.description, Some("CI token".to_string()));
    }

    #[test]
    fn test_create_token_response_serialization() {
        let resp = CreateTokenResponse {
            token: "nora_abc123".to_string(),
            expires_in_days: 30,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("nora_abc123"));
        assert!(json.contains("30"));
    }

    #[test]
    fn test_token_ui_paths_not_public() {
        // Token management UI must require authentication
        assert!(!is_public_path("/ui/tokens"));
        assert!(!is_public_path("/ui/tokens/"));
        assert!(!is_public_path("/api/ui/tokens/create"));
        assert!(!is_public_path("/api/ui/tokens/list"));
        assert!(!is_public_path("/api/ui/tokens/abcd1234abcd1234/revoke"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[tokio::test]
    async fn test_auth_disabled_passes_all() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_auth_public_paths_always_pass() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(&ctx.app, Method::GET, "/ready", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Docker Registry V2 spec: GET /v2/ without credentials must return 401
    /// with WWW-Authenticate header when auth is enabled (issue #219)
    #[tokio::test]
    async fn test_docker_v2_requires_auth_when_enabled() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);

        // Without credentials: must return 401 + WWW-Authenticate
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));

        // With valid credentials: must return 200
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Docker /v2/ must NOT pass through anonymous_read bypass.
    /// Even with anonymous_read=true, /v2/ must require auth so Docker
    /// clients know to send credentials on subsequent push/pull requests.
    #[tokio::test]
    async fn test_docker_v2_ignores_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // /v2/ without auth: must still return 401 even with anonymous_read=true
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));

        // Other read endpoints should still work anonymously
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// When auth is disabled, /v2/ should pass through normally
    #[tokio::test]
    async fn test_docker_v2_passes_when_auth_disabled() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_blocks_without_credentials() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));
    }

    #[tokio::test]
    async fn test_auth_basic_works() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_auth_basic_wrong_password() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);
        // Upload with auth
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        // Read without auth should work
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        // Write without auth should fail
        let response = send(&ctx.app, Method::PUT, "/raw/test2.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_token_ui_requires_auth() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);

        // Token UI page without auth should return 401
        let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Token UI page with auth should work
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/ui/tokens",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_ui_create_requires_htmx() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // POST without HX-Request header should be rejected (CSRF)
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            "description=test&role=read&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // POST with HX-Request header should work
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            "description=test&role=read&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_ui_revoke_validates_file_id() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // Invalid file_id (not hex, no slashes so route matches)
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/not_valid_hex_xx/revoke",
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Valid hex but non-existent
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/abcd1234abcd1234/revoke",
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_token_ui_full_lifecycle() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

        // Create a token via UI endpoint
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/x-www-form-urlencoded"),
                ("hx-request", "true"),
            ],
            "description=CI+Pipeline&role=write&ttl_days=30",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        assert!(body.contains("nra_"), "Response should contain raw token");

        // List tokens
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/tokens/list",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        assert!(body.contains("CI Pipeline"), "List should show description");

        // Get file_id from the token store directly for revoke test
        let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens();
        assert_eq!(tokens.len(), 1);
        let file_id = &tokens[0].file_id;

        // Revoke
        let revoke_url = format!("/api/ui/tokens/{}/revoke", file_id);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            &revoke_url,
            vec![("authorization", &header_val), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // Verify token is gone
        let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens();
        assert_eq!(tokens.len(), 0);
    }
}
