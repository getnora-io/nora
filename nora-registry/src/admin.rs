// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Admin control-plane API (operator-triggered, admin-role gated).
//!
//! Routes here live under `/api/v1/admin/` and are enforced as admin-only by the
//! auth middleware (`auth::is_admin_path`): an `Admin`-role token is required,
//! anonymous and Basic-auth requests are denied fail-closed. Keep this module
//! to operational actions an operator triggers by hand — not per-artifact CRUD.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit::AuditEntry;
use crate::auth::AuthenticatedUser;
use crate::registry_type::RegistryType;
use crate::tokens::Role;
use crate::AppState;

/// Minimum seconds between two accepted reindex calls. A reindex flips dirty
/// flags cheaply, but each subsequent read triggers a full storage scan, so a
/// tight `reindex + read` loop is a cheap-request → expensive-work amplifier.
/// This debounce caps that even when HTTP rate limiting is disabled in config.
const REINDEX_MIN_INTERVAL_SECS: u64 = 10;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/reindex", post(reindex))
        .route("/api/v1/admin/tokens", post(admin_create_token))
}

#[derive(Debug, Default, Deserialize)]
struct ReindexQuery {
    /// Optional single registry to reindex (e.g. `?registry=cargo`). When absent,
    /// every registry is reindexed.
    registry: Option<String>,
}

#[derive(Serialize)]
struct ReindexResponse {
    status: &'static str,
    /// Registry name being reindexed, or `"all"`.
    scope: String,
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Trigger an in-memory index rebuild from storage so the UI reflects artifacts
/// copied in out-of-band (rsync, BTRFS send/receive, S3 sync) without a restart
/// or dummy client pull. Marks the target index(es) dirty and warms them in the
/// background, returning `202 Accepted` immediately.
///
/// Admin-only (enforced in middleware). Debounced; returns `429` with
/// `Retry-After` if called again within `REINDEX_MIN_INTERVAL_SECS`.
///
/// Operator note: on a large S3-backed store prefer scoping to the synced
/// registry (`?registry=<name>`). An unscoped reindex rebuilds all registries,
/// and each rebuild currently issues one HEAD per object on S3 (see #738);
/// local FS pays only a cheap `stat` syscall per key.
async fn reindex(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<ReindexQuery>,
) -> Response {
    // Resolve the optional scope up front so a typo fails loudly (400) instead of
    // silently no-op'ing — `invalidate("crago")` would otherwise return success.
    let target = match query.registry.as_deref() {
        Some(name) => match RegistryType::from_str_opt(name) {
            Some(rt) => Some(rt),
            None => {
                return (StatusCode::BAD_REQUEST, format!("unknown registry: {name}"))
                    .into_response()
            }
        },
        None => None,
    };

    // Debounce: cap the amplification of repeated reindex → full-storage scans.
    if let Err(retry_after) = state
        .repo_index
        .try_accept_reindex(now_epoch_secs(), REINDEX_MIN_INTERVAL_SECS)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            "reindex debounced; retry later",
        )
            .into_response();
    }

    let scope = target.map(|rt| rt.as_str().to_string());

    // Mark dirty: cheap flag flip, the actual rebuild reads disk lazily.
    match target {
        Some(rt) => state.repo_index.invalidate(rt.as_str()),
        None => state.repo_index.invalidate_all(),
    }

    state.audit.log(AuditEntry::new(
        "reindex",
        &user.0,
        "",
        scope.as_deref().unwrap_or("all"),
        "",
    ));
    tracing::info!(
        actor = %user.0,
        scope = scope.as_deref().unwrap_or("all"),
        "admin reindex triggered"
    );

    // Eager warm-up so the full-storage scan happens off the critical path of the
    // next GUI reader (key for DR, where the operator validates the restore). The
    // index is rebuildable from disk, so losing this task on shutdown is safe —
    // it just rebuilds lazily on the next read after restart.
    let repo_index = state.repo_index.clone();
    let storage = state.storage.clone();
    // `state` is unused past this point, so move the token instead of cloning.
    let cancel = state.cancel_token;
    let targets: Vec<RegistryType> = match target {
        Some(rt) => vec![rt],
        None => RegistryType::all().to_vec(),
    };
    tokio::spawn(async move {
        // CANCEL-SAFETY: both arms are cancel-safe. On shutdown we drop the
        // in-progress rebuild; the index stays dirty and rebuilds on next read.
        tokio::select! {
            _ = cancel.cancelled() => {}
            _ = async {
                for rt in targets {
                    let _ = repo_index.get(rt.as_str(), &storage).await;
                }
            } => {}
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(ReindexResponse {
            status: "reindexing",
            scope: scope.unwrap_or_else(|| "all".to_string()),
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AdminCreateTokenRequest {
    /// Subject the token is minted for (a service/user identity, not necessarily
    /// an htpasswd account — this route does not check a password).
    username: String,
    #[serde(default = "default_admin_token_ttl")]
    ttl_days: u64,
    description: Option<String>,
    #[serde(default = "default_admin_token_role")]
    role: String,
}

fn default_admin_token_ttl() -> u64 {
    30
}

fn default_admin_token_role() -> String {
    "read".to_string()
}

#[derive(Serialize)]
struct AdminCreateTokenResponse {
    token: String,
    expires_in_days: u64,
}

/// Mint an API token of any role — including `admin` — WITHOUT the
/// `auth.admin_users` self-service check.
///
/// Safe because this route lives under `/api/v1/admin/` and is therefore only
/// reachable by a caller already holding an `Admin`-role token (enforced in the
/// auth middleware, `auth::is_admin_path`): anonymous and Basic-auth are denied
/// fail-closed, and a Read/Write token gets 403 before reaching this handler. So
/// the admin privilege is proven by the gate, not re-derived from an allowlist —
/// `auth.admin_users` becomes a bootstrap-only fallback on the public
/// `POST /api/tokens` route (#746, follow-up to GHSA-78cx-cfhm-rgmx).
async fn admin_create_token(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthenticatedUser>,
    Json(req): Json<AdminCreateTokenRequest>,
) -> Response {
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

    if req.ttl_days == 0 {
        return (StatusCode::BAD_REQUEST, "ttl_days must be > 0").into_response();
    }

    let Some(token_store) = &state.tokens else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Token storage not configured",
        )
            .into_response();
    };

    let role_label = role.to_string();
    match token_store.create_token(&req.username, req.ttl_days, req.description, role) {
        Ok(token) => {
            // Audit the mint with actor + target + role + ttl (never the token itself).
            let detail = format!("role={} ttl_days={}", role_label, req.ttl_days);
            state.audit.log(AuditEntry::new(
                "admin_token_mint",
                &caller.0,
                &req.username,
                "admin",
                &detail,
            ));
            Json(AdminCreateTokenResponse {
                token,
                expires_in_days: req.ttl_days,
            })
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::{
        create_test_context_with_auth, send, send_with_headers, TestContext,
    };
    use crate::tokens::Role;
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const URI: &str = "/api/v1/admin/reindex";

    fn mint(ctx: &TestContext, role: Role) -> String {
        ctx.state
            .tokens
            .as_ref()
            .expect("token store enabled")
            .create_token("tester", 30, None, role)
            .expect("create token")
    }

    async fn post_bearer(ctx: &TestContext, uri: &str, token: &str) -> StatusCode {
        let auth = format!("Bearer {token}");
        send_with_headers(
            &ctx.app,
            Method::POST,
            uri,
            vec![("Authorization", &auth)],
            "",
        )
        .await
        .status()
    }

    async fn post_basic(ctx: &TestContext, uri: &str, cred: &str) -> StatusCode {
        let auth = format!("Basic {}", STANDARD.encode(cred));
        send_with_headers(
            &ctx.app,
            Method::POST,
            uri,
            vec![("Authorization", &auth)],
            "",
        )
        .await
        .status()
    }

    #[tokio::test]
    async fn admin_token_accepted() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        assert_eq!(post_bearer(&ctx, URI, &tok).await, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn write_token_forbidden() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Write);
        assert_eq!(post_bearer(&ctx, URI, &tok).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn read_token_forbidden() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Read);
        assert_eq!(post_bearer(&ctx, URI, &tok).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_auth_unauthorized() {
        let ctx = create_test_context_with_auth(&[]);
        let status = send(&ctx.app, Method::POST, URI, "").await.status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn basic_auth_forbidden_fail_closed() {
        // htpasswd Basic-auth carries no role -> can never be admin.
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);
        let cred = STANDARD.encode("alice:pw");
        let auth = format!("Basic {cred}");
        let status = send_with_headers(
            &ctx.app,
            Method::POST,
            URI,
            vec![("Authorization", &auth)],
            "",
        )
        .await
        .status();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn basic_password_write_token_forbidden() {
        // #737 lets an API token ride in as the Basic password; a write token via
        // Basic must still be blocked on admin paths, not just on Bearer.
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);
        let tok = mint(&ctx, Role::Write);
        assert_eq!(
            post_basic(&ctx, URI, &format!("x:{tok}")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn basic_password_admin_token_accepted() {
        // A genuine admin token via the Basic password (Docker/twine/Maven style)
        // must still reach the admin endpoint.
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);
        let tok = mint(&ctx, Role::Admin);
        assert_eq!(
            post_basic(&ctx, URI, &format!("x:{tok}")).await,
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn unknown_registry_bad_request() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        let status = post_bearer(&ctx, "/api/v1/admin/reindex?registry=crago", &tok).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn scoped_registry_accepted() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        let status = post_bearer(&ctx, "/api/v1/admin/reindex?registry=cargo", &tok).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn second_call_debounced() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        assert_eq!(post_bearer(&ctx, URI, &tok).await, StatusCode::ACCEPTED);
        // Immediate second call lands inside the debounce window.
        assert_eq!(
            post_bearer(&ctx, URI, &tok).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn raw_reindex_stays_write_gated() {
        // Regression pin: the legacy /raw/-/reindex must NOT be swept into the
        // admin gate — a write token still works there.
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Write);
        let status = post_bearer(&ctx, "/raw/-/reindex", &tok).await;
        assert_eq!(status, StatusCode::OK);
    }

    // ── #746: dedicated admin-gated token mint (POST /api/v1/admin/tokens) ──

    const TOK_URI: &str = "/api/v1/admin/tokens";

    async fn post_json_bearer(
        ctx: &TestContext,
        token: &str,
        body: &str,
    ) -> axum::http::StatusCode {
        let auth = format!("Bearer {token}");
        send_with_headers(
            &ctx.app,
            Method::POST,
            TOK_URI,
            vec![
                ("Authorization", &auth),
                ("Content-Type", "application/json"),
            ],
            body.to_string(),
        )
        .await
        .status()
    }

    /// An admin token mints an admin token here WITHOUT auth.admin_users, and the
    /// minted token is a genuine admin (works on an admin path).
    #[tokio::test]
    async fn admin_mint_admin_token_end_to_end() {
        use crate::test_helpers::body_bytes;
        let ctx = create_test_context_with_auth(&[]);
        let admin = mint(&ctx, Role::Admin);
        let auth = format!("Bearer {admin}");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            TOK_URI,
            vec![
                ("Authorization", &auth),
                ("Content-Type", "application/json"),
            ],
            r#"{"username":"svc","role":"admin"}"#.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let minted = json["token"].as_str().expect("token in response");
        // The freshly minted admin token satisfies the admin gate.
        assert_eq!(
            post_bearer(&ctx, "/api/v1/admin/reindex?registry=cargo", minted).await,
            StatusCode::ACCEPTED
        );
    }

    /// The admin gate protects the mint route: a write/read token, Basic-auth, and
    /// no-auth are all rejected BEFORE minting anything.
    #[tokio::test]
    async fn admin_mint_write_token_forbidden() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Write);
        assert_eq!(
            post_json_bearer(&ctx, &tok, r#"{"username":"svc","role":"admin"}"#).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn admin_mint_read_token_forbidden() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Read);
        assert_eq!(
            post_json_bearer(&ctx, &tok, r#"{"username":"svc","role":"admin"}"#).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn admin_mint_basic_no_role_forbidden() {
        // htpasswd Basic carries no role → can never reach the mint handler.
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);
        assert_eq!(
            post_basic(&ctx, TOK_URI, "alice:pw").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn admin_mint_no_auth_unauthorized() {
        let ctx = create_test_context_with_auth(&[]);
        let status = send(&ctx.app, Method::POST, TOK_URI, "").await.status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// An admin caller with a bad role string gets 400 (reaches the handler).
    #[tokio::test]
    async fn admin_mint_invalid_role_bad_request() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        assert_eq!(
            post_json_bearer(&ctx, &tok, r#"{"username":"svc","role":"superuser"}"#).await,
            StatusCode::BAD_REQUEST
        );
    }

    /// ttl_days=0 (an instantly-expired token) is rejected.
    #[tokio::test]
    async fn admin_mint_zero_ttl_bad_request() {
        let ctx = create_test_context_with_auth(&[]);
        let tok = mint(&ctx, Role::Admin);
        assert_eq!(
            post_json_bearer(
                &ctx,
                &tok,
                r#"{"username":"svc","role":"admin","ttl_days":0}"#
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }
}
