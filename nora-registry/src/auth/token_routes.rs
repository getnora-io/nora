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

use crate::audit::AuditEntry;
use crate::tokens::{ttl_secs_for_days, Role, SECS_PER_DAY};
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
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip, &req.username) {
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

    if !auth.verify(&req.username, &req.password).await {
        state.auth_failures.record_failure(client_ip, &req.username);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state
        .auth_failures
        .record_success(&client_ip, &req.username);

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
    // Block role self-escalation: an admin token may be minted via this public
    // route only by an account listed in auth.admin_users. Read/write are
    // unaffected (GHSA-78cx-cfhm-rgmx).
    if role == Role::Admin
        && !state
            .config
            .auth
            .admin_users
            .iter()
            .any(|u| u == &req.username)
    {
        return (
            StatusCode::FORBIDDEN,
            "admin role is not permitted for this account; add it to auth.admin_users",
        )
            .into_response();
    }

    match token_store.mint_token(
        &req.username,
        ttl_secs_for_days(req.ttl_days),
        req.description,
        role,
    ) {
        Ok(minted) => {
            state.audit.log(AuditEntry::token_mint(
                &req.username,
                "api",
                &minted.owner,
                &minted.role,
                minted.ttl_secs,
            ));
            Json(CreateTokenResponse {
                token: minted.token,
                expires_in_days: minted.ttl_secs / SECS_PER_DAY,
            })
            .into_response()
        }
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
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip, &req.username) {
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

    if !auth.verify(&req.username, &req.password).await {
        state.auth_failures.record_failure(client_ip, &req.username);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state
        .auth_failures
        .record_success(&client_ip, &req.username);

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
    if let Some(retry_after) = state.auth_failures.check_blocked(&client_ip, &req.username) {
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

    if !auth.verify(&req.username, &req.password).await {
        state.auth_failures.record_failure(client_ip, &req.username);
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    state
        .auth_failures
        .record_success(&client_ip, &req.username);

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

    // Owner-scope: a self-service caller may revoke only its own tokens. 404 (not
    // 403) so a non-owner cannot probe which token IDs exist
    // (GHSA-78cx-cfhm-rgmx — cross-user token revocation).
    if !token_store
        .list_tokens(&req.username)
        .iter()
        .any(|t| t.file_id == req.hash_prefix)
    {
        return (StatusCode::NOT_FOUND, "Token not found").into_response();
    }

    match token_store.revoke_token(&req.hash_prefix).await {
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

/// Every route that mints a token caps its lifetime the same way and leaves an
/// audit entry naming who minted what.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod mint_tests {
    use crate::test_helpers::*;
    use crate::tokens::Role;
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const TEN_YEARS: u64 = 3650 * 86_400;

    fn audited(users: &[(&str, &str)]) -> TestContext {
        create_test_context_with_auth_and_config(users, |cfg| {
            cfg.audit.mode = crate::audit::AuditMode::File;
        })
    }

    /// The audit entries written so far (drains the log).
    async fn audit_entries(ctx: &TestContext) -> Vec<serde_json::Value> {
        let path = ctx.state.audit.path().clone();
        ctx.state.audit.shutdown().await;
        std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The one `token_mint` entry among `entries`; a mint that logs twice
    /// or not at all fails here.
    fn the_one_mint(entries: &[serde_json::Value]) -> &serde_json::Value {
        let mints: Vec<_> = entries
            .iter()
            .filter(|e| e["action"] == "token_mint")
            .collect();
        assert_eq!(mints.len(), 1, "one audit entry per mint: {entries:?}");
        mints[0]
    }

    /// The lifetime of the one token `owner` has.
    fn lifetime_of(ctx: &TestContext, owner: &str) -> u64 {
        let tokens = ctx.state.tokens.as_ref().unwrap().list_tokens(owner);
        assert_eq!(tokens.len(), 1, "{owner} has one token");
        tokens[0].expires_at - tokens[0].created_at
    }

    async fn post_json(
        ctx: &TestContext,
        uri: &str,
        auth: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut headers = vec![("content-type", "application/json")];
        if let Some(auth) = auth {
            headers.push(("authorization", auth));
        }
        let resp = send_with_headers(&ctx.app, Method::POST, uri, headers, body.to_string()).await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn api_tokens_caps_the_lifetime_and_audits_the_mint() {
        let ctx = audited(&[("alice", "alicepw"), ("bob", "bobpw")]);
        for (user, ttl) in [("alice", "1000000000"), ("bob", "213503982334602")] {
            let (status, json) = post_json(
                &ctx,
                "/api/tokens",
                None,
                &format!(r#"{{"username":"{user}","password":"{user}pw","ttl_days":{ttl},"role":"write"}}"#),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{json}");
            assert_eq!(
                json["expires_in_days"], 3650,
                "the answer names the lifetime granted"
            );
            assert_eq!(lifetime_of(&ctx, user), TEN_YEARS, "ttl_days={ttl}");
        }
        let token = ctx.state.tokens.as_ref().unwrap();
        let entries = audit_entries(&ctx).await;
        let mints: Vec<_> = entries
            .iter()
            .filter(|e| e["action"] == "token_mint")
            .collect();
        assert_eq!(mints.len(), 2, "one audit entry per mint: {entries:?}");
        for (mint, user) in mints.iter().zip(["alice", "bob"]) {
            assert_eq!(mint["actor"], user);
            assert_eq!(mint["artifact"], user);
            assert_eq!(mint["registry"], "api");
            assert_eq!(mint["detail"], format!("role=write ttl_secs={TEN_YEARS}"));
        }
        for t in token.list_all_tokens() {
            assert!(
                !entries.iter().any(|e| e.to_string().contains(&t.file_id)),
                "a token id in the audit log"
            );
        }
    }

    #[tokio::test]
    async fn admin_mint_caps_the_lifetime_it_reports_and_audits() {
        let ctx = audited(&[]);
        let admin = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("root", 30, None, Role::Admin)
            .unwrap();
        let (status, json) = post_json(
            &ctx,
            "/api/v1/admin/tokens",
            Some(&format!("Bearer {admin}")),
            r#"{"username":"svc","role":"read","ttl_days":1000000000}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["expires_in_days"], 3650,
            "the answer names the lifetime granted"
        );
        assert_eq!(lifetime_of(&ctx, "svc"), TEN_YEARS);
        let entries = audit_entries(&ctx).await;
        let mint = the_one_mint(&entries);
        assert_eq!(mint["actor"], "root");
        assert_eq!(mint["artifact"], "svc");
        assert_eq!(mint["registry"], "admin");
        assert_eq!(mint["detail"], format!("role=read ttl_secs={TEN_YEARS}"));
    }

    #[tokio::test]
    async fn ui_mint_is_audited() {
        let ctx = audited(&[("alice", "alicepw")]);
        let basic = format!("Basic {}", STANDARD.encode("alice:alicepw"));
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &basic),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=ci&role=write&ttl_days=30".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(lifetime_of(&ctx, "alice"), 30 * 86_400);
        let entries = audit_entries(&ctx).await;
        let mint = the_one_mint(&entries);
        assert_eq!(mint["actor"], "alice");
        assert_eq!(mint["artifact"], "alice");
        assert_eq!(mint["registry"], "ui");
        assert_eq!(
            mint["detail"],
            format!("role=write ttl_secs={}", 30 * 86_400)
        );
    }

    /// Each route that mints leaves exactly one `token_mint` entry per token,
    /// and a mint it refuses leaves none.
    #[tokio::test]
    async fn each_mint_is_one_audit_entry_and_a_refused_one_is_none() {
        let ctx = audited(&[("alice", "alicepw")]);
        let admin = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("root", 30, None, Role::Admin)
            .unwrap();
        let admin = format!("Bearer {admin}");
        let basic = format!("Basic {}", STANDARD.encode("alice:alicepw"));
        let ui = |hx: bool, body: &'static str| {
            let mut headers = vec![
                ("authorization", basic.as_str()),
                ("content-type", "application/x-www-form-urlencoded"),
            ];
            if hx {
                headers.push(("hx-request", "true"));
            }
            send_with_headers(
                &ctx.app,
                Method::POST,
                "/api/ui/tokens/create",
                headers,
                body.as_bytes().to_vec(),
            )
        };

        // Refused on every route: nothing minted, nothing audited.
        let (status, _) = post_json(
            &ctx,
            "/api/v1/admin/tokens",
            Some(&admin),
            r#"{"username":"svc","role":"read","ttl_days":0}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post_json(
            &ctx,
            "/api/tokens",
            None,
            r#"{"username":"alice","password":"wrong","role":"read"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = post_json(
            &ctx,
            "/api/tokens",
            None,
            r#"{"username":"alice","password":"alicepw","role":"admin"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let resp = ui(false, "description=ci&role=read&ttl_days=30").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = ui(true, "description=ci&role=admin&ttl_days=30").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ctx.state.tokens.as_ref().unwrap().list_all_tokens().len(),
            1
        );

        // One mint on each route.
        let (status, json) = post_json(
            &ctx,
            "/api/v1/admin/tokens",
            Some(&admin),
            r#"{"username":"svc","role":"read","ttl_days":30}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = post_json(
            &ctx,
            "/api/tokens",
            None,
            r#"{"username":"alice","password":"alicepw","ttl_days":30,"role":"read"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let resp = ui(true, "description=ci&role=read&ttl_days=30").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let entries = audit_entries(&ctx).await;
        let mut routes: Vec<_> = entries
            .iter()
            .filter(|e| e["action"] == "token_mint")
            .map(|e| e["registry"].as_str().unwrap().to_string())
            .collect();
        routes.sort();
        assert_eq!(routes, ["admin", "api", "ui"], "{entries:?}");
    }
}
