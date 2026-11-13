// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Docker token service for `docker_anon_pull` (#1226).
//!
//! With anonymous pull on, the `/v2/` ping cannot answer 200: docker then never sends the
//! credentials `docker login` stored, so a push fails and a login with any password succeeds.
//! A Basic challenge on the ping keeps push but stops anonymous pull and `registry-mirrors`
//! (docker refuses to send a request after a Basic challenge it has no credentials for).
//! Registries that serve both answer the ping with a Bearer challenge naming a token service,
//! as Docker Hub does: a client with no credentials gets a token that pulls, a client with
//! credentials gets a token carrying its identity, a wrong password gets 401.
//!
//! Measured on docker 29, dockerd 27 as a registry mirror, skopeo 1.4, podman 6.1 and
//! containerd 1.7: docker, skopeo and podman ask with `GET` and Basic credentials, containerd
//! with a `POST` OAuth2 form (`grant_type=password`).
//!
//! A token is `nrd_<claims>.<mac>`: the claims as base64url JSON and their HMAC-SHA256 under a
//! key kept beside the API tokens (`token_storage`), so replicas sharing that directory share
//! it. Not a JWT: production code issues no JWT (`oidc-rsa-verify-only-no-decrypt`, the
//! precondition of accepting RUSTSEC-2023-0071), and a client never reads the token anyway. It names the identity
//! (user and role, or anonymous), not a repository scope: what it may do is decided per request
//! as for any other credential, and it is honoured on the Docker paths only.

use super::{authenticate_basic, too_many_failed_attempts, BasicDecision};
use crate::tokens::Role;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use hmac_sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// Where the token service answers.
pub(crate) const TOKEN_PATH: &str = "/api/docker/token";
/// The `service` the challenge names and a token is issued for.
const SERVICE: &str = "nora";
/// What marks a NORA Docker token among Bearer credentials.
const PREFIX: &str = "nrd_";
const ISSUER: &str = "nora";
const AUDIENCE: &str = "nora-docker";
/// Seconds a token lives; clients ask again when it runs out, as with Docker Hub's 300.
const TTL_SECS: u64 = 300;
/// The key file, beside the API tokens.
const KEY_FILE: &str = "docker-token.key";
const KEY_LEN: usize = 32;

/// Who a Docker token speaks for.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Grant {
    /// No credentials were presented: what anonymous pull serves, nothing more.
    Anonymous,
    /// Credentials were presented and checked: this user with this role.
    User { user: String, role: Role },
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<Role>,
    iat: u64,
    exp: u64,
}

/// The signing key of Docker tokens.
pub(crate) struct DockerTokens {
    key: [u8; KEY_LEN],
}

impl std::fmt::Debug for DockerTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DockerTokens")
    }
}

impl DockerTokens {
    fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    /// The MAC over the prefix and the encoded claims.
    fn mac(&self, claims: &str) -> Hmac<Sha256> {
        // HMAC takes a key of any length.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key");
        mac.update(PREFIX.as_bytes());
        mac.update(claims.as_bytes());
        mac
    }

    /// The key kept in `dir`, created on first use. Created under a temporary name and
    /// hard-linked into place, so a reader never sees a partial key and two replicas starting
    /// together on one directory end up with the same one.
    pub(crate) fn load_or_create(dir: &Path) -> std::io::Result<Self> {
        let path = dir.join(KEY_FILE);
        if let Some(tokens) = Self::read(&path)? {
            return Ok(tokens);
        }
        let mut key = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let tmp = dir.join(format!("{KEY_FILE}.{}.tmp", uuid::Uuid::new_v4().simple()));
        write_private(&tmp, &key)?;
        let linked = std::fs::hard_link(&tmp, &path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(Self::from_key(key)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::read(&path)?
                .ok_or_else(|| std::io::Error::other("docker token key vanished after a race")),
            Err(e) => Err(e),
        }
    }

    fn read(path: &Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(key) => match <[u8; KEY_LEN]>::try_from(key.as_slice()) {
                Ok(key) => Ok(Some(Self::from_key(key))),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} holds {} bytes, not {KEY_LEN}",
                        path.display(),
                        key.len()
                    ),
                )),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A token for `grant`, issued at `now` (Unix seconds).
    pub(crate) fn mint(&self, grant: &Grant, now: u64) -> String {
        let (sub, role) = match grant {
            Grant::Anonymous => (String::new(), None),
            Grant::User { user, role } => (user.clone(), Some(role.clone())),
        };
        let claims = Claims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            sub,
            role,
            iat: now,
            exp: now + TTL_SECS,
        };
        // Serializing a struct of strings and numbers cannot fail.
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap_or_default());
        let mac = URL_SAFE_NO_PAD.encode(self.mac(&claims).finalize().into_bytes());
        format!("{PREFIX}{claims}.{mac}")
    }

    /// What a token presented at `now` speaks for; `None` when NORA did not sign it, it is
    /// not a Docker token or it has expired.
    pub(crate) fn verify(&self, token: &str, now: u64) -> Option<Grant> {
        let (claims, mac) = token.strip_prefix(PREFIX)?.split_once('.')?;
        // `verify_slice` compares in constant time; the claims are read only once it passes.
        self.mac(claims)
            .verify_slice(&URL_SAFE_NO_PAD.decode(mac).ok()?)
            .ok()?;
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).ok()?).ok()?;
        if claims.iss != ISSUER || claims.aud != AUDIENCE || now >= claims.exp {
            return None;
        }
        Some(match claims.role {
            None => Grant::Anonymous,
            Some(role) => Grant::User {
                user: claims.sub,
                role,
            },
        })
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Whether a Bearer credential is a NORA Docker token (whatever its validity).
pub(crate) fn is_docker_token(token: &str) -> bool {
    token.starts_with(PREFIX)
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The `WWW-Authenticate` value sending a client to the token service, with the scope a
/// request on `path` needs (`push` for a write) when it names a repository.
pub(crate) fn challenge(state: &AppState, path: &str, write: bool) -> String {
    // The base URL NORA advertises everywhere: public_url, else the bind address, which the
    // configuration refuses to be a wildcard without a public_url.
    let mut c = format!(
        "Bearer realm=\"{}{TOKEN_PATH}\",service=\"{SERVICE}\"",
        state.config.server.public_base_url()
    );
    if let Some(name) = repository(path) {
        let actions = if write { "pull,push" } else { "pull" };
        c.push_str(&format!(",scope=\"repository:{name}:{actions}\""));
    }
    c
}

/// The repository a Docker path names: `/v2/<name>/(manifests|blobs|tags)/…`.
fn repository(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/v2/")?;
    ["/manifests/", "/blobs/", "/tags/"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .map(|end| &rest[..end])
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        })
}

/// A 401 on a Docker path carrying `challenge` (from [`challenge`]).
pub(crate) fn unauthorized_with(challenge: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, challenge.to_string()),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        serde_json::json!({
            "errors": [{ "code": "UNAUTHORIZED", "message": message }]
        })
        .to_string(),
    )
        .into_response()
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    access_token: String,
    expires_in: u64,
    issued_at: String,
}

/// The credentials a token request carries: Basic (docker, skopeo, podman) or an OAuth2
/// password grant in a POST form (containerd). `None` for an anonymous request.
fn presented(headers: &HeaderMap, method: &Method, body: &[u8]) -> Option<String> {
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
    {
        return Some(basic.to_string());
    }
    if *method != Method::POST {
        return None;
    }
    let form = form_fields(body);
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if field("grant_type") != Some("password") {
        return None;
    }
    let (user, password) = (field("username")?, field("password")?);
    Some(base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}")))
}

/// The fields of an `application/x-www-form-urlencoded` body (`+` is a space).
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(&s.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned()
    };
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// `GET|POST /api/docker/token`: a token for whoever asks, only under `docker_anon_pull`.
async fn issue(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(tokens) = state.docker_tokens.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let grant = match presented(&headers, &method, &body) {
        None => Grant::Anonymous,
        Some(encoded) => {
            let client_ip =
                super::resolve_client_ip(addr.ip(), &headers, &state.config.auth.trusted_proxies);
            // Decided as a read: the token carries the role, and a read-only credential is
            // refused when it writes, as on the Basic path.
            match authenticate_basic(&state, Some(client_ip), &encoded, &Method::GET, false).await {
                BasicDecision::Authenticated { user, role } => Grant::User { user, role },
                BasicDecision::LockedOut(retry_after) => {
                    return too_many_failed_attempts(retry_after)
                }
                BasicDecision::ServiceUnavailable(e) => {
                    tracing::error!(error = %e, "token store read failed during docker token request");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Token verification unavailable",
                    )
                        .into_response();
                }
                BasicDecision::Forbidden(reason) => {
                    return (StatusCode::FORBIDDEN, reason).into_response()
                }
                BasicDecision::Unauthorized { message, .. } => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "details": message })),
                    )
                        .into_response()
                }
                BasicDecision::NotConfigured => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "details": "Basic auth not configured" })),
                    )
                        .into_response()
                }
            }
        }
    };
    let now = now_secs();
    let token = tokens.mint(&grant, now);
    let issued_at = chrono::DateTime::from_timestamp(now as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(TokenResponse {
            access_token: token.clone(),
            token,
            expires_in: TTL_SECS,
            issued_at,
        }),
    )
        .into_response()
}

/// The token service route. It is merged with the Docker registry routes, under their read
/// and write quotas: docker, skopeo and podman ask for a token on nearly every repository
/// operation, and the auth quota (1/s, burst 5) answered a push or a pull 429 on the polygon.
pub(crate) fn routes() -> Router<AppState> {
    Router::new().route(TOKEN_PATH, get(issue).post(issue))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_auth, create_test_context_with_docker_anon_pull, send,
        send_with_headers, TestContext,
    };
    use axum::http::{header, Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const TOKEN: &str = "/api/docker/token?service=nora&scope=repository:alpine:pull,push";
    const UPLOAD: &str = "/v2/alpine/blobs/uploads/";

    fn ctx() -> TestContext {
        create_test_context_with_docker_anon_pull(&[("alice", "secret")])
    }

    fn basic(user: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
    }

    fn challenge(resp: &axum::response::Response) -> String {
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// GET the token service with these headers; the token on 200.
    async fn token(ctx: &TestContext, headers: Vec<(&str, &str)>) -> (StatusCode, Option<String>) {
        let resp = send_with_headers(&ctx.app, Method::GET, TOKEN, headers, "").await;
        let status = resp.status();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
        if status == StatusCode::OK {
            assert_eq!(body["token"], body["access_token"], "{body}");
            assert!(body["expires_in"].as_u64().unwrap_or(0) > 0, "{body}");
        }
        (status, body["token"].as_str().map(str::to_owned))
    }

    async fn with_bearer(
        ctx: &TestContext,
        method: Method,
        path: &str,
        token: &str,
    ) -> axum::response::Response {
        let auth = format!("Bearer {token}");
        send_with_headers(&ctx.app, method, path, vec![("authorization", &auth)], "").await
    }

    /// The ping sends the client to the token service, so docker asks it for a token and,
    /// once logged in, presents its credentials there (#1226). Before, the ping was 200 and
    /// docker never sent them: `docker push` failed and `docker login` with any password
    /// succeeded.
    #[tokio::test]
    async fn the_ping_points_at_the_token_service() {
        let ctx = ctx();
        for method in [Method::GET, Method::HEAD] {
            let resp = send(&ctx.app, method.clone(), "/v2/", "").await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method}");
            let c = challenge(&resp);
            assert!(c.starts_with("Bearer realm=\"http"), "{method}: {c}");
            assert!(c.contains("/api/docker/token\""), "{method}: {c}");
            assert!(c.contains("service=\"nora\""), "{method}: {c}");
        }
    }

    /// No credentials: a token that pulls. The ping takes it, reads pass, a write is sent back
    /// to the token service with the scope it needs, and the catalog stays closed.
    #[tokio::test]
    async fn an_anonymous_token_pulls_and_does_not_push() {
        let ctx = ctx();
        let (status, token) = token(&ctx, vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let token = token.unwrap();
        assert_eq!(
            with_bearer(&ctx, Method::GET, "/v2/", &token)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            with_bearer(&ctx, Method::GET, "/v2/alpine/manifests/latest", &token)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let resp = with_bearer(&ctx, Method::POST, UPLOAD, &token).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let c = challenge(&resp);
        assert!(c.starts_with("Bearer realm="), "{c}");
        assert!(c.contains("scope=\"repository:alpine:pull,push\""), "{c}");
        assert_eq!(
            with_bearer(&ctx, Method::GET, "/v2/_catalog", &token)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// The credentials `docker login` stored get a token that pushes.
    #[tokio::test]
    async fn credentials_get_a_token_that_pushes() {
        let ctx = ctx();
        let auth = basic("alice", "secret");
        let (status, token) = token(&ctx, vec![("authorization", &auth)]).await;
        assert_eq!(status, StatusCode::OK);
        let token = token.unwrap();
        assert_eq!(
            with_bearer(&ctx, Method::POST, UPLOAD, &token)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            with_bearer(&ctx, Method::GET, "/v2/_catalog", &token)
                .await
                .status(),
            StatusCode::OK
        );
    }

    /// containerd asks with an OAuth2 form (`grant_type=password`) in a POST, measured with
    /// ctr 1.7 (#1226): the same credentials, the same token.
    #[tokio::test]
    async fn containerd_posts_a_password_grant() {
        let ctx = ctx();
        let form = |password: &str| {
            format!(
                "grant_type=password&username=alice&password={password}&service=nora\
                 &scope=repository%3Aalpine%3Apull%2Cpush&client_id=containerd-client"
            )
        };
        let post = |body: String| {
            let app = ctx.app.clone();
            async move {
                send_with_headers(
                    &app,
                    Method::POST,
                    "/api/docker/token",
                    vec![("content-type", "application/x-www-form-urlencoded")],
                    body,
                )
                .await
            }
        };
        let resp = post(form("secret")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let token = body["access_token"].as_str().unwrap().to_owned();
        assert_eq!(
            with_bearer(&ctx, Method::POST, UPLOAD, &token)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(post(form("wrong")).await.status(), StatusCode::UNAUTHORIZED);
    }

    /// A wrong password gets no token (so `docker login` fails), and counts toward the
    /// lockout as on any Basic request.
    #[tokio::test]
    async fn a_wrong_password_gets_no_token_and_counts() {
        let ctx = ctx();
        let right = basic("alice", "secret");
        let (status, issued) = token(&ctx, vec![("authorization", &right)]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(issued.is_some());
        let wrong = basic("alice", "wrong");
        for _ in 0..5 {
            let (status, issued) = token(&ctx, vec![("authorization", &wrong)]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(issued, None);
        }
        let (status, _) = token(&ctx, vec![("authorization", &right)]).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// An API token sent as the password, as `docker login -p nra_…` does, keeps its role: a
    /// read token pulls and may not push.
    #[tokio::test]
    async fn an_api_token_as_the_password_keeps_its_role() {
        let ctx = ctx();
        let minted = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .mint_token(
                "bob",
                crate::tokens::MintLifetime::days(1, None),
                None,
                crate::tokens::Role::Read,
            )
            .unwrap();
        let auth = basic("bob", &minted.token);
        let (status, token) = token(&ctx, vec![("authorization", &auth)]).await;
        assert_eq!(status, StatusCode::OK);
        let token = token.unwrap();
        assert_eq!(
            with_bearer(&ctx, Method::GET, "/v2/_catalog", &token)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            with_bearer(&ctx, Method::POST, UPLOAD, &token)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    /// A Docker token opens the Docker paths and nothing else: not a raw upload, not the API
    /// token routes.
    #[tokio::test]
    async fn a_docker_token_opens_only_docker_paths() {
        let ctx = ctx();
        let auth = basic("alice", "secret");
        let token = token(&ctx, vec![("authorization", &auth)]).await.1.unwrap();
        for (method, path) in [
            (Method::PUT, "/raw/team/file.txt"),
            (Method::GET, "/raw/team/file.txt"),
            (Method::GET, "/npm/left-pad"),
        ] {
            assert_eq!(
                with_bearer(&ctx, method.clone(), path, &token)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
    }

    /// A token NORA did not sign is refused, and the client is sent back for another.
    #[tokio::test]
    async fn a_forged_token_is_refused() {
        let ctx = ctx();
        let auth = basic("alice", "secret");
        let token = token(&ctx, vec![("authorization", &auth)]).await.1.unwrap();
        let mut forged = token.clone();
        let last = forged.pop().unwrap();
        forged.push(if last == 'A' { 'B' } else { 'A' });
        let resp = with_bearer(&ctx, Method::POST, UPLOAD, &forged).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(challenge(&resp).starts_with("Bearer realm="));
        let resp = with_bearer(&ctx, Method::POST, UPLOAD, "nrd_not-a-token").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A token lives its TTL and no longer, and only under the key that signed it.
    #[test]
    fn a_token_expires_and_needs_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = super::DockerTokens::load_or_create(dir.path()).unwrap();
        let grant = super::Grant::User {
            user: "alice".into(),
            role: crate::tokens::Role::Write,
        };
        let token = tokens.mint(&grant, 1_000);
        assert_eq!(tokens.verify(&token, 1_000), Some(grant.clone()));
        assert_eq!(
            tokens.verify(&token, 1_000 + super::TTL_SECS - 1),
            Some(grant)
        );
        assert_eq!(tokens.verify(&token, 1_000 + super::TTL_SECS), None);
        let other = tempfile::tempdir().unwrap();
        let foreign = super::DockerTokens::load_or_create(other.path()).unwrap();
        assert_eq!(foreign.verify(&token, 1_000), None);
        let anonymous = tokens.mint(&super::Grant::Anonymous, 1_000);
        assert_eq!(
            tokens.verify(&anonymous, 1_000),
            Some(super::Grant::Anonymous)
        );
        assert_eq!(
            tokens.verify(&anonymous[super::PREFIX.len()..], 1_000),
            None
        );
    }

    /// A token's claims are bound by its MAC: an anonymous token rewritten to name a writer,
    /// with the MAC it came with, is refused, as is one whose MAC is cut short.
    #[test]
    fn a_claim_changed_after_signing_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = super::DockerTokens::load_or_create(dir.path()).unwrap();
        let anonymous = tokens.mint(&super::Grant::Anonymous, 1_000);
        let (claims, mac) = anonymous[super::PREFIX.len()..].split_once('.').unwrap();
        let mut forged: serde_json::Value =
            serde_json::from_slice(&super::URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
        forged["sub"] = "mallory".into();
        forged["role"] = serde_json::to_value(crate::tokens::Role::Write).unwrap();
        let forged = super::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let token = format!("{}{forged}.{mac}", super::PREFIX);
        assert_eq!(tokens.verify(&token, 1_000), None);
        let short = &anonymous[..anonymous.len() - 4];
        assert_eq!(tokens.verify(short, 1_000), None);
        assert_eq!(
            tokens.verify(&anonymous, 1_000),
            Some(super::Grant::Anonymous)
        );
    }

    /// The key is made once and kept: a restart, or a second replica on the same directory,
    /// verifies what the first one signed. It is private to the owner, and a key file of the
    /// wrong length is an error, not a fresh key.
    #[test]
    fn the_key_is_kept_beside_the_api_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let first = super::DockerTokens::load_or_create(dir.path()).unwrap();
        let token = first.mint(&super::Grant::Anonymous, 1_000);
        let again = super::DockerTokens::load_or_create(dir.path()).unwrap();
        assert_eq!(again.verify(&token, 1_000), Some(super::Grant::Anonymous));
        let path = dir.path().join(super::KEY_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from(super::KEY_FILE)]);
        std::fs::write(&path, b"short").unwrap();
        assert!(super::DockerTokens::load_or_create(dir.path()).is_err());
    }

    #[test]
    fn the_scope_names_the_repository() {
        for (path, name) in [
            ("/v2/alpine/blobs/uploads/", Some("alpine")),
            ("/v2/team/app/manifests/1.0", Some("team/app")),
            ("/v2/a/manifests/x/blobs/y", Some("a")),
            ("/v2/team/app/tags/list", Some("team/app")),
            ("/v2/", None),
            ("/v2/_catalog", None),
            ("/v2/bad\"name/manifests/1", None),
        ] {
            assert_eq!(super::repository(path), name, "{path}");
        }
    }

    #[test]
    fn a_password_grant_form_is_decoded() {
        let fields = super::form_fields(b"grant_type=password&username=al%40ce&password=a+b%26c=");
        assert_eq!(
            fields,
            [
                ("grant_type".to_string(), "password".to_string()),
                ("username".to_string(), "al@ce".to_string()),
                ("password".to_string(), "a b&c=".to_string()),
            ]
        );
    }

    /// The realm is the base URL NORA advertises everywhere, `public_url` (else the bind
    /// address): never the Host a client sent, which it controls.
    #[tokio::test]
    async fn the_realm_is_the_public_url() {
        let public = crate::test_helpers::create_test_context_with_auth_and_config(
            &[("alice", "secret")],
            |cfg| {
                cfg.auth.docker_anon_pull = true;
                cfg.server.public_url = Some("https://registry.example.com/".to_string());
            },
        );
        let resp = send_with_headers(
            &public.app,
            Method::GET,
            "/v2/",
            vec![("host", "attacker.example")],
            "",
        )
        .await;
        assert_eq!(
            challenge(&resp),
            "Bearer realm=\"https://registry.example.com/api/docker/token\",service=\"nora\""
        );
        let resp = send(&public.app, Method::POST, UPLOAD, "").await;
        assert_eq!(
            challenge(&resp),
            "Bearer realm=\"https://registry.example.com/api/docker/token\",service=\"nora\",\
             scope=\"repository:alpine:pull,push\""
        );
        let plain = ctx();
        let resp = send(&plain.app, Method::GET, "/v2/", "").await;
        assert_eq!(
            challenge(&resp),
            format!(
                "Bearer realm=\"{}/api/docker/token\",service=\"nora\"",
                plain.state.config.server.public_base_url()
            )
        );
    }

    /// The token service is a registry route, not an auth route: the auth routes take the auth
    /// quota (1/s, burst 5 by default), and a docker push or pull asks for several tokens, so
    /// under it the polygon answered 429 (#1226).
    #[tokio::test]
    async fn the_token_service_rides_with_the_docker_routes() {
        use std::collections::HashSet;
        let ctx = ctx();
        let get =
            |app: axum::Router| async move { send(&app, Method::GET, TOKEN, "").await.status() };
        let docker = crate::registry_routes(&HashSet::from([crate::RegistryType::Docker]))
            .with_state(ctx.state.clone());
        assert_eq!(get(docker).await, StatusCode::OK);
        let auth = crate::auth::token_routes().with_state(ctx.state.clone());
        assert_eq!(get(auth).await, StatusCode::NOT_FOUND);
    }

    /// Without `docker_anon_pull` nothing changes: the ping challenges with Basic and there
    /// is no token service.
    #[tokio::test]
    async fn without_anonymous_pull_nothing_changes() {
        let ctx = create_test_context_with_auth(&[("alice", "secret")]);
        let resp = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            challenge(&resp).starts_with("Basic "),
            "{}",
            challenge(&resp)
        );
        let auth = basic("alice", "secret");
        let (status, _) = token(&ctx, vec![("authorization", &auth)]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
