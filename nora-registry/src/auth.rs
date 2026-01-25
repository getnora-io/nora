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
    matches!(
        path,
        "/" | "/health" | "/ready" | "/metrics" | "/v2/" | "/v2"
    ) || path.starts_with("/ui")
        || path.starts_with("/api-docs")
        || path.starts_with("/api/ui")
        || path.starts_with("/api/tokens")
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

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => return unauthorized_response("Authentication required"),
    };

    // Try Bearer token first
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        if let Some(ref token_store) = state.tokens {
            match token_store.verify_token(token) {
                Ok(_user) => return next.run(request).await,
                Err(_) => return unauthorized_response("Invalid or expired token"),
            }
        } else {
            return unauthorized_response("Token authentication not configured");
        }
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return unauthorized_response("Basic or Bearer authentication required");
    }

    let encoded = &auth_header[6..];
    let decoded = match STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return unauthorized_response("Invalid credentials encoding"),
    };

    let credentials = match String::from_utf8(decoded) {
        Ok(c) => c,
        Err(_) => return unauthorized_response("Invalid credentials encoding"),
    };

    let (username, password) = match credentials.split_once(':') {
        Some((u, p)) => (u, p),
        None => return unauthorized_response("Invalid credentials format"),
    };

    // Verify credentials
    if !auth.authenticate(username, password) {
        return unauthorized_response("Invalid username or password");
    }

    // Auth successful
    next.run(request).await
}

fn unauthorized_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, "Basic realm=\"Nora\""),
            (header::CONTENT_TYPE, "application/json"),
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

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub username: String,
    pub password: String,
    #[serde(default = "default_ttl")]
    pub ttl_days: u64,
    pub description: Option<String>,
}

fn default_ttl() -> u64 {
    30
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub expires_in_days: u64,
}

#[derive(Serialize)]
pub struct TokenListItem {
    pub hash_prefix: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
}

#[derive(Serialize)]
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

    match token_store.create_token(&req.username, req.ttl_days, req.description) {
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
            hash_prefix: t.token_hash[..16].to_string(),
            created_at: t.created_at,
            expires_at: t.expires_at,
            last_used: t.last_used,
            description: t.description,
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
