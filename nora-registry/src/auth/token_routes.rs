// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Token management API routes (create, list, revoke).

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::tokens::Role;
use crate::AppState;

use super::resolve_client_ip;

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
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    let client_ip = resolve_client_ip(addr.ip(), &headers, &state.config.auth.trusted_proxies);
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            format!(
                r#"{{"error":"Too many failed attempts. Retry after {} seconds."}}"#,
                retry_after
            ),
        )
            .into_response();
    }

    // Verify user credentials first
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        state.auth_failures.record_failure(client_ip);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state.auth_failures.record_success(&client_ip);

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
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    let client_ip = resolve_client_ip(addr.ip(), &headers, &state.config.auth.trusted_proxies);
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            format!(
                r#"{{"error":"Too many failed attempts. Retry after {} seconds."}}"#,
                retry_after
            ),
        )
            .into_response();
    }

    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        state.auth_failures.record_failure(client_ip);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state.auth_failures.record_success(&client_ip);

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
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Response {
    let client_ip = resolve_client_ip(addr.ip(), &headers, &state.config.auth.trusted_proxies);
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            format!(
                r#"{{"error":"Too many failed attempts. Retry after {} seconds."}}"#,
                retry_after
            ),
        )
            .into_response();
    }

    let auth = match &state.auth {
        Some(auth) => auth,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Auth not configured").into_response(),
    };

    if !auth.authenticate(&req.username, &req.password) {
        state.auth_failures.record_failure(client_ip);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state.auth_failures.record_success(&client_ip);

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
pub fn token_routes() -> Router<AppState> {
    Router::new()
        .route("/api/tokens", post(create_token))
        .route("/api/tokens/list", post(list_tokens))
        .route("/api/tokens/revoke", post(revoke_token))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
