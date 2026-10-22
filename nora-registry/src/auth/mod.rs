// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Authentication module — middleware, providers, and token routes.
//!
//! Supports:
//! - Basic auth via htpasswd files
//! - Bearer token auth (opaque tokens with Argon2 verification)
//! - Brute-force protection with exponential backoff

mod htpasswd;
mod namespace;
pub mod oidc;
mod token_routes;

pub use htpasswd::HtpasswdAuth;
pub use namespace::{enforce_namespace_scope, NamespaceAuthority};
pub use oidc::OidcValidator;
pub use token_routes::{token_routes, TokenListItem, TokenListResponse};

/// Authenticated username carried in request extensions after successful auth.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser(pub String);

/// The verified role carried in request extensions after successful auth.
/// Basic-auth (htpasswd) identities have no role concept and are recorded as
/// `Write` (never admin), so role-gated owner-scope treats them as non-admin.
#[derive(Clone, Debug)]
pub struct AuthenticatedRole(pub crate::tokens::Role);

/// The lifetime ceiling (seconds) the caller's own credential imposes on any
/// token it mints. Inserted ONLY for OIDC identities: the shorter of the
/// provider's `max_token_lifetime_secs` and what is left of the JWT until its
/// `exp`, so a minted token never outlives the JWT that minted it (0 once the
/// JWT has expired, inside the validator's leeway). Absent for Basic and opaque
/// (`nra_`) callers, which carry no such ceiling. A UI mint reads it to cap the
/// new token so a short-lived federated identity cannot bootstrap a long-lived
/// static one (#1094).
#[derive(Clone, Copy, Debug)]
pub struct MintLifetimeCeiling(pub u64);

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::AppState;

/// Resolve the audit actor for a request-driven event (#985): the authenticated
/// username, or `anonymous` when the request carries no identity. Write handlers
/// take `user: Option<axum::Extension<AuthenticatedUser>>` (which never fails to
/// extract) and pass this to `AuditEntry::new` instead of a hardcoded actor.
pub fn audit_actor(user: &Option<axum::Extension<AuthenticatedUser>>) -> &str {
    match user {
        Some(axum::Extension(AuthenticatedUser(name))) => name,
        None => "anonymous",
    }
}

/// Tracks wrong passwords for brute-force protection, per account and per
/// address.
///
/// An account is a username at a client address. After `max_failures`
/// consecutive failures it is locked out of password authentication with
/// exponential backoff: 2^(failures - max_failures) seconds, capped at
/// `max_lockout_secs`. Guesses at one account do not lock out another behind
/// the same address, and only a login as that username clears its count.
///
/// An address is also held, whatever the username, once it has sent
/// [`ADDRESS_FAILURES_PER_ACCOUNT`] times `max_failures` wrong passwords, with
/// the same backoff, so guessing across usernames gains nothing. A login does
/// not clear the address count, which ends after `2 * max_lockout_secs`
/// without a failure ([`AuthFailureTracker::cleanup`]).
///
/// Bearer credentials (API tokens, OIDC JWTs) cannot be guessed and are
/// neither counted nor refused.
pub struct AuthFailureTracker {
    entries: parking_lot::Mutex<FailureCounts>,
    /// Number of failures before lockout kicks in (default: 5)
    max_failures: u32,
    /// Maximum lockout duration in seconds (default: 900 = 15 minutes)
    max_lockout_secs: u64,
}

/// How many accounts' worth of failures an address may send before it is held
/// whatever the username. An account adds at most `max_failures` failures
/// before its own lockout stops counting it, so the address ceiling is reached
/// only by failing many accounts, which is guessing across usernames rather
/// than a mistyped password; ten accounts (50 failures at the default 5) keep
/// an office of mistyping users clear of it.
pub const ADDRESS_FAILURES_PER_ACCOUNT: u32 = 10;

/// Failure counts: (consecutive failures, last failure).
#[derive(Default)]
struct FailureCounts {
    /// By address and SHA-256 of the username: a fixed-size key whatever the
    /// username a client sends.
    accounts: HashMap<(IpAddr, [u8; 32]), (u32, Instant)>,
    /// By address, for every username.
    addresses: HashMap<IpAddr, (u32, Instant)>,
}

fn account_key(ip: IpAddr, username: &str) -> (IpAddr, [u8; 32]) {
    use sha2::{Digest, Sha256};
    (ip, Sha256::digest(username.as_bytes()).into())
}

impl AuthFailureTracker {
    pub fn new(max_failures: u32, max_lockout_secs: u64) -> Self {
        Self {
            entries: parking_lot::Mutex::new(FailureCounts::default()),
            max_failures,
            max_lockout_secs,
        }
    }

    /// Seconds left of a lockout at `threshold` failures, if one is running.
    fn lockout_left(&self, count: Option<&(u32, Instant)>, threshold: u32) -> Option<u64> {
        let (failures, last_failure) = count?;
        if *failures < threshold {
            return None;
        }
        let exponent = (*failures - threshold).min(20);
        let lockout_secs = (1u64 << exponent).min(self.max_lockout_secs);
        let elapsed = last_failure.elapsed().as_secs();
        (elapsed < lockout_secs).then(|| lockout_secs - elapsed)
    }

    /// Seconds left until `username` at `ip` may try a password again, if it
    /// is locked out: the account itself, or the address for every username.
    pub fn check_blocked(&self, ip: &IpAddr, username: &str) -> Option<u64> {
        let entries = self.entries.lock();
        let account = self.lockout_left(
            entries.accounts.get(&account_key(*ip, username)),
            self.max_failures,
        );
        let address = self.lockout_left(
            entries.addresses.get(ip),
            self.max_failures
                .saturating_mul(ADDRESS_FAILURES_PER_ACCOUNT),
        );
        account.max(address)
    }

    /// Record a wrong password for `username` at `ip`.
    pub fn record_failure(&self, ip: IpAddr, username: &str) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let account = entries
            .accounts
            .entry(account_key(ip, username))
            .or_insert((0, now));
        *account = (account.0.saturating_add(1), now);
        let address = entries.addresses.entry(ip).or_insert((0, now));
        *address = (address.0.saturating_add(1), now);
    }

    /// A login as `username` from `ip`: clears that account's failures, not
    /// the address's.
    pub fn record_success(&self, ip: &IpAddr, username: &str) {
        let mut entries = self.entries.lock();
        entries.accounts.remove(&account_key(*ip, username));
    }

    /// Remove entries older than 2 x max_lockout_secs (call periodically).
    pub fn cleanup(&self) {
        let keep =
            |(_, last): &(u32, Instant)| last.elapsed().as_secs() < self.max_lockout_secs * 2;
        let mut entries = self.entries.lock();
        entries.accounts.retain(|_, count| keep(count));
        entries.addresses.retain(|_, count| keep(count));
    }
}

/// Check if path is public (no auth required)
/// Paths that are public UNCONDITIONALLY: probes (a gated /health takes the
/// whole deployment down behind an LB) and the token endpoints, which do
/// their own credential handling.
fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/health" | "/ready" | "/api/tokens" | "/api/tokens/list" | "/api/tokens/revoke"
    )
}

/// The browse web surface: UI pages, their JSON API, and the API docs. All
/// of it enumerates repositories and packages, so under an auth-enabled
/// deployment it is gated unless `anonymous_read` or `public_web_ui` opens
/// it (token-management pages stay ALWAYS gated — they were before, too).
fn is_web_surface(path: &str) -> bool {
    if path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens") {
        return false;
    }
    path.starts_with("/ui") || path.starts_with("/api/ui") || path.starts_with("/api-docs")
}

/// Check if a path belongs to the Docker/OCI registry (`/v2`, `/v2/…`).
///
/// Docker anonymous access is governed by `docker_anon_pull` (separate from
/// the general `anonymous_read`), so all `/v2` paths are matched as one group:
/// the `/v2/` auth-challenge ping and every manifest/blob/tag endpoint. Per the
/// Docker Registry V2 spec, an unauthenticated `GET /v2/` returns 401 with a
/// WWW-Authenticate header (so clients send credentials) UNLESS anonymous Docker
/// pull is explicitly enabled.
fn is_docker_path(path: &str) -> bool {
    path == "/v2" || path.starts_with("/v2/")
}

/// Check if path is an admin-only control-plane endpoint.
///
/// Admin paths require a token whose role satisfies `can_admin()` regardless of
/// HTTP method, and are never served anonymously (not even under
/// `anonymous_read`). Basic-auth has no role concept, so it can never satisfy
/// an admin path — it is denied fail-closed. Scoped strictly to `/api/v1/admin/`
/// so it never widens the privilege bar of existing routes (e.g. `/raw/-/reindex`
/// stays at write-level).
fn is_admin_path(path: &str) -> bool {
    path.starts_with("/api/v1/admin/")
}

/// Extract client IP from request, honoring XFF/X-Real-IP only from trusted proxies.
///
/// If the direct peer IP is not in `trusted_proxies`, XFF/X-Real-IP headers are
/// ignored (with one warning per setting) and the peer IP is returned. This
/// prevents attackers from spoofing their IP to bypass `AuthFailureTracker`
/// lockout. Every address is canonical: an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`, an IPv4 peer of a dual-stack socket) is its IPv4
/// address, so one client is one key whichever socket or proxy it came by.
pub(crate) fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted_proxies.contains(peer) {
        if headers.contains_key("x-forwarded-for") || headers.contains_key("x-real-ip") {
            trusted_proxies.warn_untrusted_forwarding(peer);
        }
        return peer;
    }

    if let Some(ip) = forwarded_for_client(headers, trusted_proxies) {
        return ip;
    }
    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return ip.to_canonical();
            }
        }
    }
    // No forwarding headers — use peer IP
    peer
}

/// The client X-Forwarded-For names, read from the right. Each proxy appends the address it
/// received the request from, so the left part of the header is whatever the client sent: the
/// client is the rightmost address that is not a trusted proxy, or the leftmost when every
/// address is one. An entry that is not an address ends the walk at the hop that wrote it. Every
/// header line counts, in order; `None` when no entry is readable.
fn forwarded_for_client(
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> Option<IpAddr> {
    let entries: Vec<&[u8]> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|line| line.as_bytes().split(|b| *b == b','))
        .collect();
    let mut nearest = None;
    for entry in entries.into_iter().rev() {
        let Some(ip) = std::str::from_utf8(entry)
            .ok()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
        else {
            break;
        };
        if !trusted_proxies.contains(ip) {
            return Some(ip);
        }
        nearest = Some(ip);
    }
    nearest
}

fn extract_client_ip(
    request: &Request<Body>,
    trusted_proxies: &crate::config::TrustedProxies,
) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())?;
    Some(resolve_client_ip(peer, request.headers(), trusted_proxies))
}

/// Insert the anonymous identity (read-only role, unrestricted namespace) and
/// run the downstream handler. Shared by the `anonymous_read` (non-Docker) and
/// `docker_anon_pull` (Docker `/v2`) bypass paths.
async fn anonymous_read_passthrough(mut request: Request<Body>, next: Next) -> Response {
    request
        .extensions_mut()
        .insert(NamespaceAuthority::Unrestricted);
    request
        .extensions_mut()
        .insert(AuthenticatedUser("anonymous".to_string()));
    request
        .extensions_mut()
        .insert(AuthenticatedRole(crate::tokens::Role::Read));
    next.run(request).await
}

/// Auth middleware - supports Basic auth, Bearer tokens, and OIDC JWT
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth if disabled (neither htpasswd nor OIDC configured)
    if !state.config.auth.enabled {
        request
            .extensions_mut()
            .insert(NamespaceAuthority::Unrestricted);
        request
            .extensions_mut()
            .insert(AuthenticatedUser("anonymous".to_string()));
        return next.run(request).await;
    }

    // Skip auth for public endpoints
    {
        let path = request.uri().path();
        // Unconditional publics (probes, token endpoints), plus the web
        // surface and /metrics when the config opens them. The web surface
        // enumerates every repository, so it follows `anonymous_read` (the
        // registry read APIs would expose the same names) or the explicit
        // `public_web_ui` escape; /metrics has its own default-open switch —
        // labels carry registry formats, not repository names.
        let config = &state.config.auth;
        let open = is_public_path(path)
            || (is_web_surface(path) && (config.anonymous_read || config.public_web_ui))
            || (path == "/metrics" && config.public_metrics);
        if open {
            // Opportunistic auth: if the caller provided credentials on an
            // open path, try to validate them so downstream handlers can
            // distinguish "anonymous browse" from "authenticated browse"
            // (e.g. to gate proxy_upstreams disclosure). If validation fails
            // we fall through to anonymous — the path is open regardless.
            if let Some(auth_val) = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
            {
                if let Some(encoded) = auth_val.strip_prefix("Basic ") {
                    if let Some(username) = try_basic_auth(encoded, state.auth.as_deref()) {
                        request
                            .extensions_mut()
                            .insert(NamespaceAuthority::Unrestricted);
                        request.extensions_mut().insert(AuthenticatedUser(username));
                        request
                            .extensions_mut()
                            .insert(AuthenticatedRole(crate::tokens::Role::Write));
                        return next.run(request).await;
                    }
                } else if let Some(token) = auth_val.strip_prefix("Bearer ") {
                    if let Some(ref token_store) = state.tokens {
                        if let Ok((user, role)) = token_store.verify_token(token) {
                            request
                                .extensions_mut()
                                .insert(NamespaceAuthority::Unrestricted);
                            request.extensions_mut().insert(AuthenticatedUser(user));
                            request.extensions_mut().insert(AuthenticatedRole(role));
                            return next.run(request).await;
                        }
                    }
                }
            }
            // No credentials or validation failed — anonymous browse
            let mut request = request;
            request
                .extensions_mut()
                .insert(NamespaceAuthority::Unrestricted);
            request
                .extensions_mut()
                .insert(AuthenticatedUser("anonymous".to_string()));
            return next.run(request).await;
        }
        // A gated web-surface request without credentials gets a Basic
        // challenge so browsers prompt instead of rendering a bare 401.
        if (is_web_surface(path) || path == "/metrics")
            && request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .is_none()
        {
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"nora\"")
                .body(axum::body::Body::from("Authentication required"))
                .expect("valid response");
        }
    }

    let path = request.uri().path();

    // Docker/OCI paths (`/v2`, `/v2/…`) are governed by `docker_anon_pull`,
    // NOT the general `anonymous_read`: anonymous Docker pull changes the `/v2/`
    // auth-challenge handshake, so it is opted into explicitly and enabling
    // anonymous Maven/raw/npm never silently exposes container images.
    let is_docker = is_docker_path(path);

    // `/v2/_catalog` enumerates every repository — never served anonymously, even
    // under docker_anon_pull (anonymous pull-by-name is not list-all-repos).
    let is_docker_catalog = path == "/v2/_catalog";

    // Token management always requires auth, even with anonymous_read
    let is_token_management = path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens");

    // npm whoami always requires auth (otherwise it returns "anonymous" for every user)
    let is_whoami = path.ends_with("/-/whoami");

    // Admin control-plane paths always require an admin token — never anonymous,
    // even under anonymous_read, and method-independent (covers a future GET).
    let is_admin = is_admin_path(path);

    let is_read_method = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    );

    // npm audit (#597) is a read-semantics query that npm sends as a POST (npm7
    // `advisories/bulk`, npm6 `audits/quick`). Treat it as read-eligible under
    // `anonymous_read` so anonymous `npm audit` works wherever anonymous install
    // works. Safe: the handler (registry/npm.rs) mutates nothing (forwards to the
    // configured upstream, returns advisories), caps the body, strips internal
    // package names under a filter, and never forwards the client credential.
    let is_npm_audit = *request.method() == axum::http::Method::POST
        && (path == "/npm/-/npm/v1/security/advisories/bulk"
            || path == "/npm/-/npm/v1/security/audits/quick");

    // A request that presents credentials is always validated below (honest
    // `docker login`, correct audit attribution) — never short-circuited to
    // anonymous. Anonymous Docker bypass applies only when no Authorization sent.
    let has_auth_header = request.headers().contains_key(header::AUTHORIZATION);

    // Anonymous read for non-Docker registries (Maven/raw/npm/…) if configured.
    // Token management, whoami, admin, and all Docker `/v2` paths are excluded.
    if state.config.auth.anonymous_read
        && (is_read_method || is_npm_audit)
        && !is_docker
        && !is_token_management
        && !is_whoami
        && !is_admin
    {
        return anonymous_read_passthrough(request, next).await;
    }

    // Anonymous Docker/OCI pull, when explicitly enabled. The `/v2/` ping then
    // returns 200 (so the client proceeds without a Basic challenge) and
    // manifest/blob/tag reads are served without auth; writes (POST/PUT/PATCH/
    // DELETE) are not read methods, so they fall through and still require auth.
    // With the flag off (default), `/v2/` returns 401 + WWW-Authenticate: Basic
    // so `docker login` works and the basic-auth-accepts-api-token contract holds.
    if state.config.auth.docker_anon_pull
        && is_read_method
        && is_docker
        && !is_docker_catalog
        && !has_auth_header
    {
        return anonymous_read_passthrough(request, next).await;
    }

    // Compute realm from public_url for WWW-Authenticate header
    let realm = state.config.server.public_url.as_deref().unwrap_or("Nora");

    // The client address the password lockout counts by.
    let client_ip = extract_client_ip(&request, &state.config.auth.trusted_proxies);

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => return unauthorized_response("Authentication required", realm),
    };

    // Try Bearer token first (opaque nra_ tokens, then OIDC JWT)
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        // 1. Try opaque token (nra_ prefix)
        if let Some(ref token_store) = state.tokens {
            match token_store.verify_token(token) {
                Ok((user, role)) => {
                    if is_write_method(request.method()) && !role.can_write() {
                        return (StatusCode::FORBIDDEN, "Read-only token").into_response();
                    }
                    if is_admin && !role.can_admin() {
                        return (StatusCode::FORBIDDEN, "Admin role required").into_response();
                    }
                    // Opaque (nra_) tokens are not namespace-scoped (#583 is OIDC-only).
                    request
                        .extensions_mut()
                        .insert(NamespaceAuthority::Unrestricted);
                    request.extensions_mut().insert(AuthenticatedUser(user));
                    request.extensions_mut().insert(AuthenticatedRole(role));
                    return next.run(request).await;
                }
                // A store I/O/parse failure is not a credential verdict. Only an
                // `nra_`-prefixed token reaches disk (anything else returns
                // `InvalidFormat` first), so there is no OIDC identity to fall
                // through to: answer 503 so the client retries, instead of a 401
                // that makes valid creds flap during a storage blip.
                Err(crate::tokens::TokenError::Storage(e)) => {
                    tracing::error!(error = %e, "token store read failed during Bearer auth");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Token verification unavailable",
                    )
                        .into_response();
                }
                Err(_) => {
                    // Token verification failed — fall through to OIDC
                }
            }
        }

        // 2. Try OIDC JWT validation
        if let Some(ref oidc_validator) = state.oidc {
            if oidc_validator.is_active() {
                match oidc_validator.validate_token(token).await {
                    Ok(identity) => {
                        tracing::debug!(
                            provider = %identity.provider,
                            subject = %identity.subject,
                            role = ?identity.role,
                            "OIDC authentication successful"
                        );
                        if is_write_method(request.method()) && !identity.role.can_write() {
                            return (StatusCode::FORBIDDEN, "Read-only OIDC identity")
                                .into_response();
                        }
                        if is_admin && !identity.role.can_admin() {
                            return (StatusCode::FORBIDDEN, "Admin role required").into_response();
                        }
                        // Carry the namespace scopes into the request so write
                        // handlers can enforce them on the artifact coordinate
                        // (#583). Provider scope and rule scope are a conjunction:
                        // the provider scope is a ceiling a rule cannot widen.
                        let authority = NamespaceAuthority::from_oidc_scopes(
                            &identity.provider,
                            std::iter::once(identity.namespace_scope.as_slice())
                                .chain(identity.rule_namespace_scope.as_deref()),
                            identity.namespace_scope_enforcement,
                        );
                        request.extensions_mut().insert(authority);
                        // Carry the provider's lifetime ceiling so a token minted
                        // by this identity cannot outlive it (#1094). Taken from
                        // the identity — i.e. the provider that actually validated
                        // this JWT — never re-looked-up by name, since provider
                        // names are not unique (#1094 N2).
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        request.extensions_mut().insert(MintLifetimeCeiling(
                            identity
                                .max_token_lifetime_secs
                                .min(identity.expires_at.saturating_sub(now)),
                        ));
                        request
                            .extensions_mut()
                            .insert(AuthenticatedUser(identity.subject.clone()));
                        request
                            .extensions_mut()
                            .insert(AuthenticatedRole(identity.role));
                        return next.run(request).await;
                    }
                    Err(reason) => {
                        // #994 — surface *why* OIDC rejected the token: a bounded
                        // metric bucket for alerting plus the full reason in a warn
                        // log (never the token). Without this a lifetime ceiling, a
                        // wrong audience and a missing role rule are indistinguishable.
                        crate::metrics::record_oidc_rejection(
                            crate::auth::oidc::classify_rejection(&reason),
                        );
                        tracing::warn!(reason = %reason, "OIDC authentication rejected");
                    }
                }
            }
        }

        // Both token and OIDC failed. A Bearer credential cannot be guessed
        // (a random API token or a signed JWT), so a wrong one does not count
        // toward the password lockout: a client replaying an expired token
        // must not lock everyone behind its address out of their passwords.
        return unauthorized_response("Invalid or expired token", realm);
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return unauthorized_response("Basic or Bearer authentication required", realm);
    }

    // The account the password lockout counts by: the username at the client
    // address. A header that does not decode to `user:password` is refused
    // below without being counted.
    let encoded = &auth_header[6..];
    let account = client_ip.zip(basic_credentials(encoded).ok().map(|(user, _)| user));
    let locked_out = account
        .as_ref()
        .and_then(|(ip, user)| state.auth_failures.check_blocked(ip, user));

    // Verify credentials: htpasswd first, then the token store (#736, #1094);
    // `decide_basic_auth` has the rules, this applies its decision. The htpasswd check is
    // async (bcrypt runs off the async workers), so it runs here, on the credentials
    // `decide_basic_auth` reads, and hands it the verdict.
    let tokens = state
        .tokens
        .as_ref()
        .map(|store| move |password: &str| store.verify_token(password));
    let decision = match locked_out {
        None => {
            let htpasswd_match = match (state.auth.as_deref(), basic_credentials(encoded)) {
                (Some(htpasswd), Ok((user, password))) => htpasswd.verify(&user, &password).await,
                _ => false,
            };
            let htpasswd = state
                .auth
                .as_deref()
                .map(|_| move |_: &str, _: &str| htpasswd_match);
            decide_basic_auth(encoded, htpasswd, tokens, request.method(), is_admin)
        }
        // A locked-out account gets no password checked, so no bcrypt runs for it. An API
        // token sent as the password cannot be guessed, so it is still verified, as over
        // Bearer: Docker has no other way to present one.
        Some(retry_after) => match decide_basic_auth(
            encoded,
            None::<fn(&str, &str) -> bool>,
            tokens,
            request.method(),
            is_admin,
        ) {
            decision @ (BasicDecision::Authenticated { .. }
            | BasicDecision::Forbidden(_)
            | BasicDecision::ServiceUnavailable(_)) => decision,
            _ => return too_many_failed_attempts(retry_after),
        },
    };
    match decision {
        BasicDecision::Authenticated { user, role } => {
            // A login as the username clears its failures. An API token of
            // another owner sent under that username does not: it says nothing
            // about the username's password.
            if let Some((ip, username)) = &account {
                if *username == user {
                    state.auth_failures.record_success(ip, username);
                }
            }
            // Basic-auth identities and opaque (nra_) tokens are not
            // namespace-scoped (#583 is OIDC-only).
            request
                .extensions_mut()
                .insert(NamespaceAuthority::Unrestricted);
            request.extensions_mut().insert(AuthenticatedUser(user));
            request.extensions_mut().insert(AuthenticatedRole(role));
            next.run(request).await
        }
        // Valid credentials, not authorized: not a wrong password, so not
        // counted.
        BasicDecision::Forbidden(reason) => (StatusCode::FORBIDDEN, reason).into_response(),
        BasicDecision::Unauthorized {
            message,
            record_failure,
        } => {
            if record_failure {
                if let Some((ip, username)) = &account {
                    state.auth_failures.record_failure(*ip, username);
                }
            }
            unauthorized_response(message, realm)
        }
        BasicDecision::ServiceUnavailable(e) => {
            tracing::error!(error = %e, "token store read failed during Basic auth fallback");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Token verification unavailable",
            )
                .into_response()
        }
        BasicDecision::NotConfigured => unauthorized_response("Basic auth not configured", realm),
    }
}

/// What the Basic branch of [`auth_middleware`] does with a request, as
/// decided by [`decide_basic_auth`].
#[derive(Clone, Debug, PartialEq)]
enum BasicDecision {
    /// Valid credentials, authorized: run the request as `user` with `role`.
    Authenticated {
        user: String,
        role: crate::tokens::Role,
    },
    /// Valid credentials, not authorized for this request (403). The
    /// credentials still count as a success for the failure tracker.
    Forbidden(&'static str),
    /// Credentials malformed or wrong (401). Only a wrong credential counts
    /// toward the per-IP lockout (`record_failure`), a malformed header does not.
    Unauthorized {
        message: &'static str,
        record_failure: bool,
    },
    /// The token store could not be read (503): an outage, not a credential
    /// verdict, so it is not counted (#912).
    ServiceUnavailable(String),
    /// Neither htpasswd nor a token store to check a Basic password against (401).
    NotConfigured,
}

/// Decide a Basic-auth request from its credentials (`encoded`, the header
/// value after `Basic `), the method and whether the path is an admin one.
///
/// `htpasswd` and `tokens` check a username/password and a password against
/// the htpasswd file and the token store; `None` when the deployment has no
/// such store. The function does no I/O of its own and decides whether each
/// check runs at all:
/// - Basic needs htpasswd or the token store; with neither the answer is
///   [`BasicDecision::NotConfigured`] whatever the header. An OIDC-only setup
///   (#996) has no htpasswd, but API tokens sent as the Basic password must
///   still work there: Docker, twine and Maven have no other way to present
///   one (#1094).
/// - htpasswd first. A match is that user with the `Write` role, never admin,
///   and the token store is not read — not even for a password shaped like an
///   API token, so a store failure cannot turn a valid login into a 503 and a
///   colliding token cannot lend its owner or role.
/// - Otherwise the password may be an API token (`nra_…`): Docker, twine and
///   Maven send the token as the Basic-auth password and never use Bearer (the
///   `/v2/` challenge is Basic) (#736). A valid token is its owner with its
///   role, never the Basic username, and is gated like on the Bearer path: a
///   read token may not write ([`is_write_method`]), an admin path needs an
///   admin token. A store I/O/parse failure is not "wrong password": a 401
///   would make valid token creds flap and feed the failure tracker toward
///   lockout for the duration of a storage blip.
fn decide_basic_auth<H, T>(
    encoded: &str,
    htpasswd: Option<H>,
    tokens: Option<T>,
    method: &Method,
    is_admin: bool,
) -> BasicDecision
where
    H: FnOnce(&str, &str) -> bool,
    T: FnOnce(&str) -> Result<(String, crate::tokens::Role), crate::tokens::TokenError>,
{
    if htpasswd.is_none() && tokens.is_none() {
        return BasicDecision::NotConfigured;
    }
    let (username, password) = match basic_credentials(encoded) {
        Ok(credentials) => credentials,
        Err(message) => {
            return BasicDecision::Unauthorized {
                message,
                record_failure: false,
            }
        }
    };
    let (username, password) = (username.as_str(), password.as_str());

    if htpasswd.is_some_and(|check| check(username, password)) {
        // Basic-auth carries no role, so it can never satisfy an admin path:
        // deny fail-closed (403 — authenticated but not authorized).
        if is_admin {
            return BasicDecision::Forbidden("Admin role required");
        }
        return BasicDecision::Authenticated {
            user: username.to_string(),
            role: crate::tokens::Role::Write,
        };
    }

    match tokens.map(|verify| verify(password)) {
        Some(Ok((user, role))) => {
            if is_write_method(method) && !role.can_write() {
                BasicDecision::Forbidden("Read-only token")
            } else if is_admin && !role.can_admin() {
                // An API token sent as the Basic password is a full bearer
                // identity (#737), so it must clear the admin gate too.
                BasicDecision::Forbidden("Admin role required")
            } else {
                BasicDecision::Authenticated { user, role }
            }
        }
        Some(Err(crate::tokens::TokenError::Storage(e))) => BasicDecision::ServiceUnavailable(e),
        Some(Err(_)) | None => BasicDecision::Unauthorized {
            message: "Invalid username or password",
            record_failure: true,
        },
    }
}

/// The username and password of a Basic credential (`encoded`, the header
/// value after `Basic `), or why it is malformed.
fn basic_credentials(encoded: &str) -> Result<(String, String), &'static str> {
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return Err("Invalid credentials encoding");
    };
    let Ok(credentials) = String::from_utf8(decoded) else {
        return Err("Invalid credentials encoding");
    };
    let Some((username, password)) = credentials.split_once(':') else {
        return Err("Invalid credentials format");
    };
    Ok((username.to_string(), password.to_string()))
}

/// The answer to a password from a locked-out account.
fn too_many_failed_attempts(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after.to_string()),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        format!(
            r#"{{"error":"Too many failed attempts. Retry after {} seconds."}}"#,
            retry_after
        ),
    )
        .into_response()
}

/// The methods a read-only identity may not use: exactly PUT, POST, DELETE and
/// PATCH. Every other method is a read — HEAD included, which is how
/// `docker pull` starts.
fn is_write_method(method: &Method) -> bool {
    [Method::PUT, Method::POST, Method::DELETE, Method::PATCH].contains(method)
}

/// The username of a Base64-encoded Basic credential that htpasswd has already accepted,
/// `None` otherwise. Used by the opportunistic-auth path on open web surfaces so that
/// authenticated users get their real identity even on publicly browsable pages. It runs
/// no bcrypt: an open path has no lockout and no limiter, so a flood of Basic
/// headers there would cost a bcrypt each. Credentials count once a gated path (where the
/// browser is challenged) has checked them.
fn try_basic_auth(encoded: &str, auth: Option<&HtpasswdAuth>) -> Option<String> {
    let (username, password) = basic_credentials(encoded).ok()?;
    (auth?.verified(&username, &password) == Some(true)).then_some(username)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn audit_actor_resolves_user_or_anonymous() {
        // #985 — the audit actor is the authenticated username (whatever auth
        // transport set AuthenticatedUser: API token or Basic-auth), or
        // `anonymous` when the request carries no identity.
        let token_user = Some(axum::Extension(AuthenticatedUser("ci-bot".to_string())));
        assert_eq!(audit_actor(&token_user), "ci-bot");

        let basic_user = Some(axum::Extension(AuthenticatedUser("alice".to_string())));
        assert_eq!(audit_actor(&basic_user), "alice");

        let anonymous: Option<axum::Extension<AuthenticatedUser>> = None;
        assert_eq!(audit_actor(&anonymous), "anonymous");
    }

    #[test]
    fn test_public_path_classification() {
        // Unconditional publics: probes + token endpoints only.
        for p in [
            "/",
            "/health",
            "/ready",
            "/api/tokens",
            "/api/tokens/list",
            "/api/tokens/revoke",
        ] {
            assert!(is_public_path(p), "{p}");
        }
        // The web surface is NOT unconditionally public any more — it is
        // config-gated in the middleware (repository enumeration).
        for p in [
            "/ui",
            "/ui/dashboard",
            "/api-docs",
            "/api-docs/openapi.json",
            "/api/ui/stats",
            "/metrics",
        ] {
            assert!(!is_public_path(p), "{p}");
        }
        for p in ["/ui", "/ui/rpm", "/api/ui/stats", "/api-docs"] {
            assert!(is_web_surface(p), "{p}");
        }
        // Token pages are part of the always-gated set, not the web surface.
        assert!(!is_web_surface("/ui/tokens"));
        assert!(!is_web_surface("/api/ui/tokens"));
        // Docker /v2/ is neither.
        assert!(!is_public_path("/v2/"));
        assert!(!is_web_surface("/v2/"));
    }

    #[test]
    fn test_is_public_path_health() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/ready"));
        // /metrics is config-gated now (auth.public_metrics), not unconditional.
        assert!(!is_public_path("/metrics"));
    }

    #[test]
    fn test_v2_is_not_public_path() {
        // Docker /v2/ must NOT be public — it needs auth challenge per V2 spec
        assert!(!is_public_path("/v2/"));
        assert!(!is_public_path("/v2"));
        // The /v2/ ping and all sub-paths are Docker registry paths, gated as a
        // group by docker_anon_pull.
        assert!(is_docker_path("/v2/"));
        assert!(is_docker_path("/v2"));
        assert!(is_docker_path("/v2/alpine/manifests/latest"));
        // Non-Docker paths are not.
        assert!(!is_docker_path("/raw/file.txt"));
        assert!(!is_docker_path("/v2x/sneaky"));
    }

    #[test]
    fn test_is_public_path_ui() {
        // The UI is the config-gated web surface, not unconditionally public.
        for p in ["/ui", "/ui/dashboard", "/ui/repos"] {
            assert!(!is_public_path(p), "{p}");
            assert!(is_web_surface(p), "{p}");
        }
    }

    #[test]
    fn test_is_public_path_api_docs() {
        for p in ["/api-docs", "/api-docs/openapi.json", "/api/ui"] {
            assert!(!is_public_path(p), "{p}");
            assert!(is_web_surface(p), "{p}");
        }
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
    fn test_token_ui_paths_not_public() {
        // Token management UI must require authentication
        assert!(!is_public_path("/ui/tokens"));
        assert!(!is_public_path("/ui/tokens/"));
        assert!(!is_public_path("/api/ui/tokens/create"));
        assert!(!is_public_path("/api/ui/tokens/list"));
        assert!(!is_public_path("/api/ui/tokens/abcd1234abcd1234/revoke"));
    }

    #[test]
    fn test_xff_trusted_proxy_uses_forwarded_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4, 127.0.0.1")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    /// A reverse proxy appends the address it received the request from to whatever
    /// X-Forwarded-For the client sent, so the left part of the header is the client's to choose.
    /// The client is the rightmost address that is not a trusted proxy.
    #[test]
    fn a_client_behind_a_trusted_proxy_cannot_choose_its_address() {
        use crate::config::TrustedProxies;
        let loopback = TrustedProxies::default_loopback();
        let hops = TrustedProxies::parse("127.0.0.1,10.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let resolve = |lines: &[&str], real_ip: Option<&str>, trusted: &TrustedProxies| {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append("x-forwarded-for", line.parse().unwrap());
            }
            if let Some(ip) = real_ip {
                headers.insert("x-real-ip", ip.parse().unwrap());
            }
            resolve_client_ip(peer, &headers, trusted).to_string()
        };
        let cases: [(&[&str], Option<&str>, &TrustedProxies, &str); 9] = [
            // nginx `$proxy_add_x_forwarded_for`: the client's header, then the real address
            (&["6.6.6.6, 203.0.113.9"], None, &loopback, "203.0.113.9"),
            (&["6.6.6.6,203.0.113.9"], None, &loopback, "203.0.113.9"),
            // a proxy that adds its own header line after the client's
            (&["6.6.6.6", "203.0.113.9"], None, &loopback, "203.0.113.9"),
            // a chain of trusted hops is walked past
            (
                &["6.6.6.6, 198.51.100.7, 10.0.0.5"],
                None,
                &hops,
                "198.51.100.7",
            ),
            // every address a trusted proxy: the leftmost
            (&["10.0.0.7, 10.0.0.5"], None, &hops, "10.0.0.7"),
            // a proxy that replaces the header: its one address
            (&["203.0.113.9"], None, &loopback, "203.0.113.9"),
            // an entry that is not an address ends the walk at the hop that wrote it
            (&["6.6.6.6, unknown, 10.0.0.5"], None, &hops, "10.0.0.5"),
            // nothing readable in X-Forwarded-For: X-Real-IP, as before
            (&["unknown"], Some("203.0.113.9"), &loopback, "203.0.113.9"),
            (&[], None, &loopback, "127.0.0.1"),
        ];
        for (lines, real_ip, trusted, want) in cases {
            assert_eq!(resolve(lines, real_ip, trusted), want, "{lines:?}");
        }
    }

    #[test]
    fn test_xff_untrusted_proxy_uses_peer_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        // Peer is NOT in trusted list
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "5.6.7.8".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn test_xff_no_header_uses_peer_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("127.0.0.1,::1");
        let mut request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            1234,
        )));
        let ip = extract_client_ip(&request, &proxies);
        assert_eq!(ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_parse_cidr() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert!(proxies.contains("10.1.2.3".parse().unwrap()));
        assert!(proxies.contains("10.255.255.255".parse().unwrap()));
        assert!(!proxies.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_parse_single_ip() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::parse("192.168.1.1");
        assert!(proxies.contains("192.168.1.1".parse().unwrap()));
        assert!(!proxies.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_trusted_proxies_default_loopback() {
        use crate::config::TrustedProxies;
        let proxies = TrustedProxies::default_loopback();
        assert!(proxies.contains("127.0.0.1".parse().unwrap()));
        assert!(proxies.contains("::1".parse().unwrap()));
        assert!(!proxies.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_auth_failure_tracker_allows_under_threshold() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..4 {
            tracker.record_failure(ip, "alice");
        }
        assert!(tracker.check_blocked(&ip, "alice").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_blocks_at_threshold() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip, "alice");
        }
        assert!(tracker.check_blocked(&ip, "alice").is_some());
    }

    #[test]
    fn test_auth_failure_tracker_success_clears() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10 {
            tracker.record_failure(ip, "alice");
        }
        assert!(tracker.check_blocked(&ip, "alice").is_some());
        tracker.record_success(&ip, "alice");
        assert!(tracker.check_blocked(&ip, "alice").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_independent_ips() {
        let tracker = AuthFailureTracker::new(3, 900);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            tracker.record_failure(ip1, "alice");
        }
        assert!(tracker.check_blocked(&ip1, "alice").is_some());
        assert!(tracker.check_blocked(&ip2, "alice").is_none());
    }

    /// The lockout counts by the whole username: a name sharing a prefix or
    /// a suffix with a locked-out one, differing in case or in one trailing
    /// byte of a long name, is another account and is not held.
    #[test]
    fn the_lockout_keys_the_whole_username() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let long = "ci-deploy-production-runner-01";
        for (locked, others) in [
            (
                "alice",
                &["alicia", "ali", "alice2", "Alice", "alice ", "", "xalice"][..],
            ),
            (
                long,
                &[
                    "ci-deploy-production-runner-02",
                    "ci-deploy-production-runner-0",
                ][..],
            ),
        ] {
            let tracker = AuthFailureTracker::new(5, 900);
            for _ in 0..5 {
                tracker.record_failure(ip, locked);
            }
            assert!(tracker.check_blocked(&ip, locked).is_some(), "{locked}");
            for other in others {
                assert!(
                    tracker.check_blocked(&ip, other).is_none(),
                    "locking out {locked:?} held {other:?}"
                );
            }
        }
    }

    #[test]
    fn test_auth_failure_tracker_cleanup() {
        let tracker = AuthFailureTracker::new(3, 1); // 1 sec max lockout
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip, "alice");
        }
        // Cleanup should remove entries older than 2x max_lockout_secs
        std::thread::sleep(std::time::Duration::from_secs(3));
        tracker.cleanup();
        assert!(tracker.check_blocked(&ip, "alice").is_none());
    }

    #[test]
    fn test_auth_failure_tracker_exponential_backoff() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // 5 failures = threshold, lockout = 2^0 = 1 sec
        for _ in 0..5 {
            tracker.record_failure(ip, "alice");
        }
        let retry1 = tracker.check_blocked(&ip, "alice").unwrap();
        assert!(
            retry1 <= 1,
            "first lockout should be ~1 sec, got {}",
            retry1
        );

        // 6 failures = 2^1 = 2 sec
        tracker.record_failure(ip, "alice");
        let retry2 = tracker.check_blocked(&ip, "alice").unwrap();
        assert!(
            retry2 <= 2,
            "second lockout should be ~2 sec, got {}",
            retry2
        );

        // 7 failures = 2^2 = 4 sec
        tracker.record_failure(ip, "alice");
        let retry3 = tracker.check_blocked(&ip, "alice").unwrap();
        assert!(
            retry3 <= 4,
            "third lockout should be ~4 sec, got {}",
            retry3
        );
    }
}

/// #1094 — the Basic branch of `auth_middleware` as a table: every row runs
/// `decide_basic_auth` on one input and compares the decision, plus whether the
/// token store was read at all. The router and binary tests cover the wiring
/// around it (`state.auth`/`state.tokens` into the verifiers, the decision into
/// the response and the failure tracker).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod basic_decision_tests {
    use super::{decide_basic_auth, BasicDecision};
    use crate::tokens::Role::{Admin, Read, Write};
    use crate::tokens::{Role, TokenError};
    use axum::http::Method;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::cell::Cell;

    /// The htpasswd users of the table. `svc`'s password is a live admin token
    /// of another owner, `ops`'s one the token store fails to read: htpasswd
    /// matching first must keep both away from the store.
    const HTPASSWD: &[(&str, &str)] = &[
        ("alice", "secret"),
        ("svc", "nra_collides"),
        ("ops", "nra_broken"),
    ];

    /// Owner of the table's tokens; no Basic username of the table is it.
    const OWNER: &str = "ci-bot";

    /// The token store of the table, by password.
    fn token_store(password: &str) -> Result<(String, Role), TokenError> {
        match password {
            "nra_read" => Ok((OWNER.into(), Read)),
            "nra_write" => Ok((OWNER.into(), Write)),
            "nra_admin" => Ok((OWNER.into(), Admin)),
            "nra_collides" => Ok(("token-owner".into(), Admin)),
            "nra_broken" => Err(TokenError::Storage("torn token file".into())),
            "nra_expired" => Err(TokenError::Expired),
            p if p.starts_with("nra_") => Err(TokenError::NotFound),
            _ => Err(TokenError::InvalidFormat),
        }
    }

    /// Which credential stores the deployment has.
    #[derive(Clone, Copy, Debug)]
    enum Setup {
        Both,
        HtpasswdOnly,
        TokensOnly,
        Neither,
    }
    use Setup::{Both, HtpasswdOnly, Neither, TokensOnly};

    /// The decision for one request, and whether the token store was read.
    fn decide(
        setup: Setup,
        encoded: &str,
        method: &Method,
        is_admin: bool,
    ) -> (BasicDecision, bool) {
        let read = Cell::new(false);
        let htpasswd = |user: &str, password: &str| HTPASSWD.contains(&(user, password));
        let tokens = |password: &str| {
            read.set(true);
            token_store(password)
        };
        let (htpasswd, tokens) = match setup {
            Both => (Some(htpasswd), Some(tokens)),
            HtpasswdOnly => (Some(htpasswd), None),
            TokensOnly => (None, Some(tokens)),
            Neither => (None, None),
        };
        let decision = decide_basic_auth(encoded, htpasswd, tokens, method, is_admin);
        (decision, read.get())
    }

    fn ok(user: &str, role: Role) -> BasicDecision {
        BasicDecision::Authenticated {
            user: user.into(),
            role,
        }
    }

    fn wrong() -> BasicDecision {
        BasicDecision::Unauthorized {
            message: "Invalid username or password",
            record_failure: true,
        }
    }

    fn malformed(message: &'static str) -> BasicDecision {
        BasicDecision::Unauthorized {
            message,
            record_failure: false,
        }
    }

    fn unavailable() -> BasicDecision {
        BasicDecision::ServiceUnavailable("torn token file".into())
    }

    const READ_ONLY: BasicDecision = BasicDecision::Forbidden("Read-only token");
    const NOT_ADMIN: BasicDecision = BasicDecision::Forbidden("Admin role required");
    const GET: Method = Method::GET;
    const PUT: Method = Method::PUT;
    const POST: Method = Method::POST;
    const DELETE: Method = Method::DELETE;

    /// Every method the table sweeps: the standard ones and an extension one.
    fn methods() -> Vec<Method> {
        vec![
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::CONNECT,
            Method::PUT,
            Method::POST,
            Method::DELETE,
            Method::PATCH,
            Method::from_bytes(b"PROPFIND").unwrap(),
        ]
    }

    /// The invariant's write set, spelled out: exactly these four.
    fn is_write(method: &Method) -> bool {
        [Method::PUT, Method::POST, Method::DELETE, Method::PATCH].contains(method)
    }

    struct Row {
        setup: Setup,
        encoded: String,
        method: Method,
        is_admin: bool,
        want: BasicDecision,
        token_store_read: bool,
    }

    impl Row {
        /// The same request on an admin path (`/api/v1/admin/*`).
        fn admin(self) -> Self {
            Row {
                is_admin: true,
                ..self
            }
        }
    }

    /// One row: the Basic credentials `user:password` sent with `method` to a
    /// non-admin path; the decision wanted and whether the store is read.
    fn row(
        setup: Setup,
        credentials: &str,
        method: Method,
        want: BasicDecision,
        read: bool,
    ) -> Row {
        Row {
            setup,
            encoded: STANDARD.encode(credentials),
            method,
            is_admin: false,
            want,
            token_store_read: read,
        }
    }

    fn rows() -> Vec<Row> {
        let mut rows = vec![
            // htpasswd matched → its identity (Write, never admin); the token
            // store is not read, even for an `nra_` password that is a live
            // admin token of someone else (H3/H4) or one the store fails on.
            row(Both, "alice:secret", GET, ok("alice", Write), false),
            row(Both, "alice:secret", PUT, ok("alice", Write), false),
            row(Both, "alice:secret", GET, NOT_ADMIN, false).admin(),
            row(
                HtpasswdOnly,
                "alice:secret",
                DELETE,
                ok("alice", Write),
                false,
            ),
            row(Both, "svc:nra_collides", GET, ok("svc", Write), false),
            row(Both, "svc:nra_collides", POST, ok("svc", Write), false),
            row(Both, "svc:nra_collides", POST, NOT_ADMIN, false).admin(),
            row(Both, "ops:nra_broken", GET, ok("ops", Write), false),
            // htpasswd missed → the password may be a token (#736): identity and
            // role are the token's, never the Basic username's (H3).
            row(Both, "alice:nra_write", PUT, ok(OWNER, Write), true),
            row(Both, "svc:nra_read", GET, ok(OWNER, Read), true),
            row(Both, "alice:nra_read", PUT, READ_ONLY, true),
            row(Both, "alice:nra_admin", POST, ok(OWNER, Admin), true).admin(),
            row(Both, "alice:wrong", GET, wrong(), true),
            row(Both, "alice:nra_broken", GET, unavailable(), true),
            // No htpasswd (OIDC-only, #1094): the token is the credential.
            row(TokensOnly, "docker:nra_write", GET, ok(OWNER, Write), true),
            row(TokensOnly, "docker:nra_write", PUT, ok(OWNER, Write), true),
            row(TokensOnly, ":nra_write", GET, ok(OWNER, Write), true),
            row(TokensOnly, "alice:nra_admin", GET, ok(OWNER, Admin), true),
            // Admin paths need an admin token; the write gate is checked first.
            row(TokensOnly, "docker:nra_admin", POST, ok(OWNER, Admin), true).admin(),
            row(TokensOnly, "docker:nra_write", POST, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_write", GET, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_read", GET, NOT_ADMIN, true).admin(),
            row(TokensOnly, "docker:nra_read", POST, READ_ONLY, true).admin(),
            // A wrong token is a credential verdict: 401, counted.
            row(TokensOnly, "docker:nra_00000000", GET, wrong(), true),
            row(TokensOnly, "docker:nra_expired", GET, wrong(), true),
            row(TokensOnly, "docker:secret", GET, wrong(), true),
            row(TokensOnly, "alice:secret", GET, wrong(), true),
            row(TokensOnly, "docker:", GET, wrong(), true),
            // A store failure is an outage: 503 before any role gate, uncounted.
            row(TokensOnly, "docker:nra_broken", GET, unavailable(), true),
            row(TokensOnly, "docker:nra_broken", PUT, unavailable(), true).admin(),
            // htpasswd only: no token fallback to reach.
            row(HtpasswdOnly, "alice:wrong", GET, wrong(), false),
            row(HtpasswdOnly, "docker:nra_write", GET, wrong(), false),
            row(
                HtpasswdOnly,
                "svc:nra_collides",
                GET,
                ok("svc", Write),
                false,
            ),
        ];

        // Write = exactly {PUT, POST, DELETE, PATCH} (H8): a read token passes
        // every other method — HEAD is how `docker pull` starts — and is refused
        // those four; a write token and an htpasswd user pass all of them.
        for method in methods() {
            for setup in [Both, TokensOnly] {
                let read_want = if is_write(&method) {
                    READ_ONLY
                } else {
                    ok(OWNER, Read)
                };
                rows.push(row(
                    setup,
                    "docker:nra_read",
                    method.clone(),
                    read_want,
                    true,
                ));
                let write_want = ok(OWNER, Write);
                rows.push(row(
                    setup,
                    "docker:nra_write",
                    method.clone(),
                    write_want,
                    true,
                ));
            }
            rows.push(row(Both, "alice:secret", method, ok("alice", Write), false));
        }

        // "Not configured" exactly when there is neither htpasswd nor a token
        // store, both ways (H6/H7) — and it is decided before the header is
        // parsed, so malformed credentials get it too.
        let malformed_headers = [
            ("!!!".to_string(), "Invalid credentials encoding"),
            (
                STANDARD.encode([0xff, 0xfe, b':']),
                "Invalid credentials encoding",
            ),
            (STANDARD.encode("nra_write"), "Invalid credentials format"),
        ];
        for setup in [Both, HtpasswdOnly, TokensOnly, Neither] {
            let has_tokens = matches!(setup, Both | TokensOnly);
            let token_want = match setup {
                Both | TokensOnly => ok(OWNER, Write),
                HtpasswdOnly => wrong(),
                Neither => BasicDecision::NotConfigured,
            };
            rows.push(row(setup, "docker:nra_write", GET, token_want, has_tokens));
            for (encoded, message) in &malformed_headers {
                let want = match setup {
                    Neither => BasicDecision::NotConfigured,
                    _ => malformed(message),
                };
                rows.push(Row {
                    encoded: encoded.clone(),
                    ..row(setup, "", GET, want, false)
                });
            }
        }
        rows
    }

    #[test]
    fn basic_auth_decision_table() {
        let rows = rows();
        assert_eq!(rows.len(), 99);
        for (i, row) in rows.iter().enumerate() {
            let (got, read) = decide(row.setup, &row.encoded, &row.method, row.is_admin);
            let credentials = STANDARD
                .decode(&row.encoded)
                .map(|d| String::from_utf8_lossy(&d).into_owned());
            let context = format!(
                "row {i}: {:?} {credentials:?} {} admin={}",
                row.setup, row.method, row.is_admin
            );
            assert_eq!(got, row.want, "{context}");
            assert_eq!(read, row.token_store_read, "token store read? {context}");
        }
    }

    /// The table's verifiers answer as the rows assume — a control that a
    /// green table is not a vacuous one.
    #[test]
    fn basic_auth_decision_table_verifiers() {
        assert!(HTPASSWD.contains(&("svc", "nra_collides")));
        assert!(token_store("nra_collides").unwrap().1.can_admin());
        assert!(matches!(
            token_store("nra_broken"),
            Err(TokenError::Storage(_))
        ));
        assert_eq!(methods().iter().filter(|m| is_write(m)).count(), 4);
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
        assert_eq!(response.status(), StatusCode::OK);
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
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- #778: anonymous Docker pull via the `docker_anon_pull` opt-in ---

    /// docker_anon_pull=true: the `GET /v2/` ping is served anonymously
    /// (200, no challenge) so the Docker client proceeds without credentials.
    #[tokio::test]
    async fn test_docker_anon_pull_allows_v2_ping() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// docker_anon_pull=true: an anonymous manifest read passes the auth
    /// gate and reaches the handler (404 for a missing tag, NOT 401).
    #[tokio::test]
    async fn test_docker_anon_pull_allows_manifest_read() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "anonymous manifest read must pass the auth gate under docker_anon_pull"
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// docker_anon_pull=true: writes are not read methods → still require
    /// auth. The Docker handler does not self-check role, so the middleware is
    /// the only write-stop — anonymous push/delete MUST be rejected.
    #[tokio::test]
    async fn test_docker_anon_pull_blocks_anonymous_writes() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        // Start a blob upload (push) anonymously -> 401.
        let response = send(&ctx.app, Method::POST, "/v2/alpine/blobs/uploads/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Push a manifest anonymously -> 401.
        let response = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Delete a manifest anonymously -> 401.
        let response = send(
            &ctx.app,
            Method::DELETE,
            "/v2/alpine/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// docker_anon_pull=true must NOT break authenticated push: a write with
    /// valid credentials starts the upload (202), exactly as without the flag.
    #[tokio::test]
    async fn test_docker_anon_pull_authenticated_push_still_works() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    /// docker_anon_pull=true: `/v2/_catalog` stays authenticated — anonymous
    /// repository enumeration is not part of anonymous pull-by-name.
    #[tokio::test]
    async fn test_docker_anon_pull_catalog_requires_auth() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        let response = send(&ctx.app, Method::GET, "/v2/_catalog", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/_catalog",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// docker_anon_pull=true: presented credentials are still validated —
    /// the anonymous bypass applies only when no Authorization header is sent.
    /// Wrong creds on the `/v2/` ping return 401 (honest `docker login`).
    #[tokio::test]
    async fn test_docker_anon_pull_validates_presented_credentials() {
        let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

        let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &bad)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let good = format!("Basic {}", STANDARD.encode("admin:secret"));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &good)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The general `anonymous_read` switch must NOT open Docker (#778): with
    /// anonymous_read=true but docker_anon_pull=false, Docker `/v2` paths
    /// still require auth, so exposing Maven/raw never exposes images.
    #[tokio::test]
    async fn test_anonymous_read_does_not_open_docker() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // /v2/ ping still challenges.
        let response = send(&ctx.app, Method::GET, "/v2/", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Manifest read still requires auth — the general flag does not open Docker.
        let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
        assert_eq!(response.status(), StatusCode::OK);
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

    /// #736: an API token presented as the Basic-auth password (any username) must
    /// authenticate — Docker/twine/Maven send the token as the Basic password and never
    /// use Bearer, so without this the documented `docker login -u token -p nra_…` fails.
    #[tokio::test]
    async fn test_basic_auth_accepts_api_token() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .unwrap();
        // Docker sends Basic base64("<user>:<token>"); the username is ignored.
        let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// #736: a read-only API token as the Basic-auth password must be rejected for writes,
    /// matching the Bearer path's role gate.
    #[tokio::test]
    async fn test_basic_auth_read_only_token_cannot_write() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Read)
            .unwrap();
        let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Path of a stored token's on-disk file inside a test context.
    fn token_file_path(ctx: &crate::test_helpers::TestContext, token: &str) -> std::path::PathBuf {
        use sha2::Digest;
        let prefix = hex::encode(sha2::Sha256::digest(token.as_bytes()));
        ctx._tempdir
            .path()
            .join("tokens")
            .join(format!("{}.json", &prefix[..16]))
    }

    /// A token-store read failure (torn/corrupt file, I/O error) is an outage,
    /// not a credential verdict: Basic auth with a valid-format token must
    /// answer 503 (retryable), never 401 — a 401 makes valid creds flap and
    /// walks the per-IP failure tracker toward lockout for the duration of a
    /// storage blip. Regression for the 2026-08 same-creds 200↔401 flap.
    #[tokio::test]
    async fn test_basic_auth_token_store_error_returns_503_not_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Read)
            .unwrap();
        // Corrupt the file the way a torn in-place rewrite would. The token was
        // never verified, so the in-memory cache is cold and the disk is read.
        std::fs::write(token_file_path(&ctx, &token), "{\"token_ha").unwrap();

        let header_val = format!("Basic {}", STANDARD.encode(format!("ci:{token}")));
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Same rule on the Bearer path: an `nra_` token that cannot be verified
    /// because the store read failed must 503, not fall through to OIDC and 401.
    #[tokio::test]
    async fn test_bearer_token_store_error_returns_503_not_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Read)
            .unwrap();
        std::fs::write(token_file_path(&ctx, &token), "{\"token_ha").unwrap();

        let header_val = format!("Bearer {token}");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// htpasswd is verified BEFORE the token store: when both exist, a password
    /// that merely *looks* like an API token (`nra_…`) authenticates against
    /// htpasswd and never reaches token verification. The order has held since
    /// #736 (htpasswd first, token on fallback), but no test pinned it — an
    /// acceptance mutant that tried the token store first survived the #1094 net
    /// (M12). Without the order a token-store blip would turn a valid htpasswd
    /// login into a 503, and an htpasswd password that collided with a live token
    /// would borrow the token's role and owner instead of the htpasswd identity.
    /// Correct order: htpasswd matches, store never read → 200. Token-first: the
    /// corrupt token file is read → Storage error → 503.
    #[tokio::test]
    async fn test_basic_auth_htpasswd_checked_before_token_store() {
        // htpasswd user whose password is shaped like an `nra_` token, so a
        // token-first order would try to verify it against the store.
        let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
        assert!(ctx.state.auth.is_some(), "htpasswd provider present");
        assert!(ctx.state.tokens.is_some(), "token store present");
        // Corrupt the file the store would read for this password: reaching it at
        // all yields a Storage error (→503). htpasswd-first never reads it.
        std::fs::write(token_file_path(&ctx, "nra_witness"), "{\"token_ha").unwrap();

        let header_val = basic_header("svc", "nra_witness");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        // htpasswd matched first → authenticated; the token store was never
        // consulted, so the corrupt file never mattered.
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Write a legacy token file (unsalted SHA-256 hash) for `token`: the first
    /// time the store reads it, it rewrites the file with an Argon2 hash.
    fn write_legacy_token(ctx: &crate::test_helpers::TestContext, token: &str, owner: &str) {
        use sha2::Digest;
        let info = serde_json::json!({
            "token_hash": hex::encode(sha2::Sha256::digest(token.as_bytes())),
            "user": owner,
            "created_at": 0,
            "expires_at": u64::MAX,
            "last_used": null,
            "description": null,
            "role": "admin",
        });
        std::fs::write(token_file_path(ctx, token), info.to_string()).unwrap();
    }

    fn token_file_migrated(ctx: &crate::test_helpers::TestContext, token: &str) -> bool {
        std::fs::read_to_string(token_file_path(ctx, token))
            .unwrap()
            .contains("$argon2")
    }

    /// htpasswd matched → the token store is not read at all, not even for a
    /// result that is then thrown away (H4), and the identity is the htpasswd
    /// user (H3). The password is a live admin token of another owner, kept as a
    /// legacy file: any store read migrates it to Argon2, so a file still legacy
    /// after the requests was never read. The control token proves the witness:
    /// one store read migrates its file.
    #[tokio::test]
    async fn test_basic_auth_htpasswd_match_never_reads_token_store() {
        let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
        write_legacy_token(&ctx, "nra_witness", "token-owner");
        write_legacy_token(&ctx, "nra_control", "token-owner");
        let store = ctx.state.tokens.as_ref().unwrap();
        assert_eq!(store.verify_token("nra_control").unwrap().0, "token-owner");
        assert!(token_file_migrated(&ctx, "nra_control"), "witness control");

        let header_val = basic_header("svc", "nra_witness");
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["username"], "svc");

        // The token is admin; the htpasswd identity is not.
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/json"),
            ],
            br#"{"username":"x","ttl_days":1,"role":"read"}"#.to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        assert!(
            !token_file_migrated(&ctx, "nra_witness"),
            "htpasswd matched, yet the token store read the password's token file"
        );
    }

    /// bcrypt verifications the context's htpasswd provider has run.
    fn bcrypt_runs(ctx: &crate::test_helpers::TestContext) -> usize {
        ctx.state
            .auth
            .as_ref()
            .unwrap()
            .bcrypt_runs
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A probe or another open path never pays bcrypt for the Basic header it
    /// carries, right or wrong; only the gated paths check htpasswd credentials.
    #[tokio::test]
    async fn an_open_path_never_runs_bcrypt() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        for creds in ["admin:wrong", "admin:secret"] {
            for path in ["/health", "/ready", "/"] {
                let header_val = format!("Basic {}", STANDARD.encode(creds));
                let response = send_with_headers(
                    &ctx.app,
                    Method::GET,
                    path,
                    vec![("authorization", &header_val)],
                    Vec::new(),
                )
                .await;
                assert_ne!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            }
        }
        assert_eq!(bcrypt_runs(&ctx), 0, "an open path ran bcrypt");
    }

    /// A CI job whose Basic username is an htpasswd user and whose password is an
    /// API token pays bcrypt once, not on every request; it still authenticates as the
    /// token's owner each time.
    #[tokio::test]
    async fn basic_with_an_api_token_pays_bcrypt_once() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let token = mint(&ctx, crate::tokens::Role::Read);
        let header_val = basic_header("alice", &token);
        for _ in 0..5 {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/-/whoami",
                vec![("authorization", &header_val)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let json: serde_json::Value =
                serde_json::from_slice(&body_bytes(response).await).unwrap();
            assert_eq!(json["username"], TOKEN_OWNER);
        }
        assert_eq!(bcrypt_runs(&ctx), 1);
    }

    /// The same for a valid htpasswd login: one bcrypt, then the verdict is remembered.
    #[tokio::test]
    async fn a_valid_htpasswd_login_pays_bcrypt_once() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let header_val = basic_header("alice", "alicepw");
        for _ in 0..5 {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/-/whoami",
                vec![("authorization", &header_val)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(bcrypt_runs(&ctx), 1);
    }

    /// Bcrypt does not run on an async worker. On a one-thread runtime a probe sent
    /// while a Basic login is being checked against a slow hash answers at once, instead
    /// of after the hash.
    #[tokio::test]
    async fn a_probe_is_not_held_up_by_a_bcrypt_check() {
        use std::time::{Duration, Instant};
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("htpasswd");
        let hash = bcrypt::hash("slowpw", 10).unwrap();
        std::fs::write(&path, format!("slow:{hash}\n")).unwrap();
        let started = Instant::now();
        assert!(!bcrypt::verify("wrong", &hash).unwrap());
        let one_check = started.elapsed();
        assert!(one_check >= Duration::from_millis(20), "{one_check:?}");

        let mut state = ctx.state.clone();
        state.auth = Some(std::sync::Arc::new(
            super::HtpasswdAuth::from_file(&path).unwrap(),
        ));
        // The probe is the open path `/` with no I/O of its own (`/health` fsyncs a probe
        // file, which under a loaded disk takes long enough to blur the measure).
        let routes = axum::Router::new()
            .route("/raw/x", axum::routing::get(|| async { "x" }))
            .route("/", axum::routing::get(|| async { "probe" }));
        let app = crate::request_layers(routes, &state).with_state(state);

        // One thread: the login is polled first. Checked on this thread, its bcrypt runs
        // before the probe is polled at all, and the probe's time since t0 includes it.
        let header_val = basic_header("slow", "wrong");
        let t0 = Instant::now();
        let (login, (probe, probe_took)) = tokio::join!(
            send_with_headers(
                &app,
                Method::GET,
                "/raw/x",
                vec![("authorization", &header_val)],
                Vec::new(),
            ),
            async {
                let response = send_with_headers(&app, Method::GET, "/", vec![], Vec::new()).await;
                (response.status(), t0.elapsed())
            }
        );
        assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(probe, StatusCode::OK);
        assert!(
            probe_took < one_check / 2,
            "the probe waited for bcrypt: {probe_took:?} (one check {one_check:?})"
        );
    }

    /// Auth enabled with no htpasswd file — the OIDC-only setup (#996). The
    /// token store is there, as main.rs always creates it when auth is enabled.
    fn create_test_context_without_htpasswd() -> crate::test_helpers::TestContext {
        let ctx = create_test_context_with_auth(&[]);
        assert!(ctx.state.auth.is_none(), "no htpasswd provider");
        assert!(ctx.state.tokens.is_some(), "token store present");
        ctx
    }

    /// Owner of the tokens `mint` creates. The Basic username the tests send
    /// (`docker`) differs, so a request attributed to the Basic username
    /// instead of the token's owner shows.
    const TOKEN_OWNER: &str = "ci-bot";

    fn mint(ctx: &crate::test_helpers::TestContext, role: crate::tokens::Role) -> String {
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .create_token(TOKEN_OWNER, 30, None, role)
            .unwrap()
    }

    fn basic_header(user: &str, pass: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
    }

    /// The test client's address (`send_with_headers` connects from it).
    const CLIENT_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// The Basic username these tests send with an API token as the password.
    const BASIC_USER: &str = "docker";

    /// Record failures for the test client's `BASIC_USER` up to one short of
    /// lockout: the test tracker locks out at its 5th, so whether the next
    /// request counts as a failure decides whether the account ends up blocked.
    fn one_failure_from_lockout(tracker: &super::AuthFailureTracker) {
        for _ in 0..4 {
            tracker.record_failure(CLIENT_IP, BASIC_USER);
        }
        assert!(tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none());
    }

    /// #1094: without htpasswd, an API token sent as the Basic password is
    /// still a credential — `docker login` (the `/v2/` ping) and a write with a
    /// write token pass, as they do with htpasswd (#736).
    #[tokio::test]
    async fn test_basic_auth_api_token_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Write);
        let header_val = basic_header("docker", &token);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"data");
    }

    /// #1094: a write identity may not mint an ADMIN token through the
    /// UI create path, even over a Basic-token credential in OIDC-only — the
    /// caller's role gates the request, not the form. Without the gate any write
    /// token escalates to admin (GHSA-78cx-cfhm-rgmx class, the UI create path
    /// had missed it).
    #[tokio::test]
    async fn test_ui_token_create_write_caller_cannot_mint_admin() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write);
        let header_val = basic_header("victim-admin", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=admin".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a write identity minted an admin token via the UI"
        );
        // Nothing was minted: only the original write token remains.
        assert_eq!(
            ctx.state.tokens.as_ref().unwrap().list_all_tokens().len(),
            1,
            "a token was created despite the 403"
        );
    }

    /// #1094: the UI create path owns the new token to the AUTHENTICATED
    /// caller (the token owner), never to the forgeable Basic-header username (H3).
    #[tokio::test]
    async fn test_ui_token_create_owner_is_the_caller_not_the_basic_username() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write);
        let header_val = basic_header("not-the-owner", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let owners: Vec<String> = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .into_iter()
            .map(|t| t.user)
            .collect();
        assert!(
            !owners.iter().any(|u| u == "not-the-owner"),
            "the new token was owned by the forged Basic username: {owners:?}"
        );
    }

    /// #1094: the new token is owned by EXACTLY the authenticated
    /// token owner — not merely "not the forged Basic username" (F2). A mutant
    /// that sets the owner to any other constant source (`"admin"`,
    /// `x-remote-user`, a form field) passes F2 but fails here.
    #[tokio::test]
    async fn ui_token_create_owner_is_exactly_the_token_owner() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = mint(&ctx, crate::tokens::Role::Write);
        let header_val = basic_header("not-the-owner", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let owners: Vec<String> = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .into_iter()
            .map(|t| t.user)
            .collect();
        assert_eq!(
            owners,
            vec![TOKEN_OWNER.to_string(), TOKEN_OWNER.to_string()],
            "the minted token's owner is not exactly the authenticated caller"
        );
    }

    /// #1094: the admin gate is by ROLE, not by name. A write
    /// identity whose name happens to be `admin` (an htpasswd user, an OIDC
    /// subject, or a token owner called `admin`) still cannot mint an admin
    /// token. A mutant that gates on `user != "admin"` passes F1 (which only
    /// exercises the `ci-bot` caller) but fails here.
    #[tokio::test]
    async fn ui_token_create_admin_named_write_caller_cannot_mint_admin() {
        let ctx = create_test_context_without_htpasswd();
        let write_token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .unwrap();
        let header_val = basic_header("docker", &write_token);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &header_val),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=admin".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a write identity named 'admin' minted an admin token via the UI"
        );
        assert_eq!(
            ctx.state.tokens.as_ref().unwrap().list_all_tokens().len(),
            1,
            "a token was created despite the 403"
        );
    }

    /// #1094: the role gate holds on the htpasswd-less Basic path — a read
    /// token reads but cannot write (403), as over Bearer and with htpasswd.
    /// The 403 is about the request, not the credential: it is not counted as
    /// a failure, so a client with a valid read token is never locked out for
    /// trying to write.
    #[tokio::test]
    async fn test_basic_auth_read_only_token_cannot_write_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Read);
        let header_val = basic_header("docker", &token);
        let tracker = &ctx.state.auth_failures;

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        one_failure_from_lockout(tracker);
        for method in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH] {
            let response = send_with_headers(
                &ctx.app,
                method.clone(),
                "/raw/test.txt",
                vec![("authorization", &header_val)],
                b"data".to_vec(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
            assert!(
                tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none(),
                "{method}: a valid read token's 403 counted as a failure"
            );
        }
    }

    /// #1094: a token over Basic without htpasswd authenticates as the token's
    /// owner with the token's role, not as the Basic username: npm whoami
    /// names the owner, and the token list shows a write token only its
    /// owner's tokens while an admin token sees every user's (GHSA-78cx).
    #[tokio::test]
    async fn test_basic_auth_token_identity_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let store = ctx.state.tokens.as_ref().unwrap();
        store
            .create_token(
                "other",
                30,
                Some("theirs".into()),
                crate::tokens::Role::Read,
            )
            .unwrap();
        let write = basic_header("docker", &mint(&ctx, crate::tokens::Role::Write));
        let admin = basic_header("docker", &mint(&ctx, crate::tokens::Role::Admin));

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &write)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["username"], TOKEN_OWNER);

        for (header_val, sees_theirs) in [(&write, false), (&admin, true)] {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/api/ui/tokens/list",
                vec![("authorization", header_val)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
            assert!(body.contains(TOKEN_OWNER), "{body}");
            assert_eq!(body.contains("theirs"), sees_theirs, "{body}");
        }
    }

    /// #1094: the admin gate holds too — a write token over Basic cannot reach
    /// /api/v1/admin/*, an admin token can (an OIDC-only admin mints tokens
    /// there, #808, and hands them to Basic-only clients).
    #[tokio::test]
    async fn test_basic_auth_token_admin_gate_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let body = br#"{"username":"svc","ttl_days":1,"role":"read"}"#;
        for (role, want) in [
            (crate::tokens::Role::Write, StatusCode::FORBIDDEN),
            (crate::tokens::Role::Admin, StatusCode::OK),
        ] {
            let header_val = basic_header("docker", &mint(&ctx, role.clone()));
            let response = send_with_headers(
                &ctx.app,
                Method::POST,
                "/api/v1/admin/tokens",
                vec![
                    ("authorization", &header_val),
                    ("content-type", "application/json"),
                ],
                body.to_vec(),
            )
            .await;
            assert_eq!(response.status(), want, "{role:?}");
        }
    }

    /// #1094: a token-store failure on the htpasswd-less Basic path is an
    /// outage (503), not a credential verdict (401), and is not counted.
    #[tokio::test]
    async fn test_basic_auth_token_store_error_returns_503_without_htpasswd() {
        let ctx = create_test_context_without_htpasswd();
        let token = mint(&ctx, crate::tokens::Role::Read);
        std::fs::write(token_file_path(&ctx, &token), "{\"token_ha").unwrap();

        one_failure_from_lockout(&ctx.state.auth_failures);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("docker", &token))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(ctx
            .state
            .auth_failures
            .check_blocked(&CLIENT_IP, BASIC_USER)
            .is_none());
    }

    /// #1094: an unknown, malformed or expired token over Basic without
    /// htpasswd answers 401 and counts toward the lockout of the Basic
    /// username; a valid token of another owner is served but does not clear
    /// that count (it says nothing about the username's password).
    #[tokio::test]
    async fn test_basic_auth_bad_token_without_htpasswd_is_401_and_counted() {
        let ctx = create_test_context_without_htpasswd();
        let tracker = &ctx.state.auth_failures;
        let expired = mint(&ctx, crate::tokens::Role::Write);
        let path = token_file_path(&ctx, &expired);
        let mut info: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        info["expires_at"] = 0.into();
        std::fs::write(&path, info.to_string()).unwrap();

        let bad = [
            "nra_00000000000000000000000000000000".to_string(),
            "secret".to_string(),
            expired,
        ];
        for password in &bad {
            one_failure_from_lockout(tracker);
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/v2/",
                vec![("authorization", &basic_header("docker", password))],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{password}");
            assert!(response.headers().contains_key("www-authenticate"));
            assert!(
                tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_some(),
                "{password}: not counted as a failure"
            );
            tracker.record_success(&CLIENT_IP, BASIC_USER);
        }

        // A valid token is served, but it is another owner's credential, not
        // the Basic username's password: the username's failures stay.
        one_failure_from_lockout(tracker);
        let token = mint(&ctx, crate::tokens::Role::Read);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("docker", &token))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        tracker.record_failure(CLIENT_IP, BASIC_USER);
        assert!(
            tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_some(),
            "a token of another owner cleared the username's failures"
        );
    }

    /// With neither htpasswd nor a token store, Basic has nothing to check
    /// against: the answer stays 401 "Basic auth not configured", uncounted.
    #[tokio::test]
    async fn test_basic_auth_without_htpasswd_or_token_store_not_configured() {
        let ctx = create_test_context_without_htpasswd();
        let mut state = ctx.state.clone();
        state.tokens = None;
        let app = crate::request_layers(crate::registry::docker_routes(), &state)
            .with_state(state.clone());

        one_failure_from_lockout(&state.auth_failures);
        let response = send_with_headers(
            &app,
            Method::GET,
            "/v2/",
            vec![(
                "authorization",
                &basic_header("docker", "nra_00000000000000000000000000000000"),
            )],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_bytes(response).await.as_ref(),
            br#"{"error":"Basic auth not configured"}"#
        );
        assert!(state
            .auth_failures
            .check_blocked(&CLIENT_IP, BASIC_USER)
            .is_none());
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
        assert_eq!(response.status(), StatusCode::OK);
        // Read without auth should work
        let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        // Write without auth should fail
        let response = send(&ctx.app, Method::PUT, "/raw/test2.txt", b"data".to_vec()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Token management must require auth even with anonymous_read=true (#221)
    #[tokio::test]
    async fn test_token_ui_requires_auth_with_anonymous_read() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        // GET /ui/tokens without auth must return 401 even with anonymous_read
        let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // GET /api/ui/tokens/list without auth must also return 401
        let response = send(&ctx.app, Method::GET, "/api/ui/tokens/list", "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // With auth, token UI should work
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

        // Other read endpoints should still work anonymously
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
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

    /// Token API endpoints are public (in is_public_path) because they validate
    /// credentials in the handler body. Verify that empty/missing credentials
    /// are properly rejected with 401 — defense-in-depth against any future
    /// refactor that might accidentally remove body-level auth checks.
    #[tokio::test]
    async fn test_token_create_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        // Empty JSON body has no username/password — serde fails or handler rejects
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_token_list_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens/list",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_token_revoke_without_credentials_returns_401() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens/revoke",
            vec![("content-type", "application/json")],
            r#"{}"#,
        )
        .await;
        assert!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::BAD_REQUEST,
            "Expected 401/422/400, got {}",
            response.status()
        );
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

// ---------------------------------------------------------------------------
// OIDC Integration Tests — full middleware flow with mock JWKS server
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod oidc_integration_tests {
    use crate::auth::oidc::OidcValidator;
    use crate::config::{OidcConfig, OidcProvider, OidcRoleRule};
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test RSA private key (2048-bit, for test JWT signing only)
    pub(crate) const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7657FVL7gwmjj
PEfl4A+ajG3DFj6YHmS9gargHMChpdLMbt8ybqu1hHPUNKQyndUvFJ6q+xJFEds3
eBtjB5GLLtlj9lScvGPsV7386rypeHq30IErgm2beQJyF9ldtrVHBBPbz7eAo4+i
wCJ/m5IsuoLCYZPQrDUdpax0dUEa/eP6badqjZ2r0recnHw1+zGyozzSHNvPtK9I
PsKwBcbGjt5n5+9nWN322/mISAuLNwtv7l3Lja8U7m0ixH0ZLwFSgTLtzEfJISux
+ngGR4k2PBVeo+yDOZtuatx7Aixa1FerOwiq2xsoGOs2dhXagwFGdwbs8x/MvEj0
67Mm3OrLAgMBAAECggEAHXZkjyWpQ43XagESeKz3ZVCtCNAdAjaJrth8lOSNIwrf
kOO1JLALRcs9acDTGYh7WwVNlxsEE0Yoa3ruOEmAfSTcOnrtayFyPSTIibW33I4i
F12eUtcBHkYLpx2sG7BAnaC7CFR5vbZnF6ot/nnCojaft6Aaz7WgIkTOU/fqPDPb
WOSn4PQmgZS34non7y0NWmxxeIwqJk3aBeeEKisO2AS0YCHOgx2uBTIt2lcIzjK8
RHwQjLRRfhzxuhHuQtz/hMVQ17W3l7ehYTnW0D+UJJTXBjPgElICmWdGm9NMX9YH
HzVSBdH+tzTZ/hUhKe+nEZ5vrWT2wqx/h0med2P3eQKBgQDYNURqK7dfo2QBsy/F
pdUg7UaXfWe+c6guu32aZhnxYsHUE68cuV7Bz/awjMJYvF9VKhoJ+iuHI0myo9In
HITzbSDwFrWCme7DAIPbfbQU9nQqJLK/g3nUpYSpjFQEnIPJSr1aS/fVpUURAoBg
RSktyRTY3ak7+6x1I54HLxPk3QKBgQDegZEqK6B28fQklCPgdimwnNr92oJe5hoY
9cHUDz3A1Uyek40LQ1yR7W/imDCJMcQXqM7Lo54+55eHEkBvh6H/TTmnGMzj5L7t
HoKYMjYdBK7waFYGM6ULfVXqs6JqVmKFU7LX+ZVmOB5kgcQMQrAhio0GrG97iDqz
aKHqOthfxwKBgQDKa+SnulIumlzRMqAxXfdSopOK1YBB0SrOxf7shVcYpitukRdL
v0m2DyyZUs/KIGLo60gBu1TxatpfA/2HXK4k8jD6V2iM4+2kaGELKH9neO59Xmpz
33Y63tR7oMQwpRDFbtIlLibUwa0OJddnSpkpIq//8le1rwVhjn0voKXxiQKBgQDS
2qPO+6LHtQewdjX9atydAjfAooYzGgkXKCTzKTJS/47pI1hgmQgrPX9uktxD1sZF
yXGWpsm6QMtmc5ReXIDWp77/q0/WkpmfqO8G/WYsX5jMN4N1wxEfbzmw/WPnM0+P
mz56zoiWYo3intpC6Bty3ZJBBb1rqjA+feQaTINpVwKBgF/M0Lj9Sq9G2Ec7yBnm
xhBlLwCNzAk33Fy+6w6ANXTsGRwMm0zGdTjC3e6LHMrD0ZtF0M2blWAUh3sZ6ItQ
2Ak5ScO0q3MRQvo4HZkFK2wuZvNLYExq6gGy3P6l8xXbvQTzg5nl9UWDKfY1gifz
Jd74nq6dNCjpWG4drIsyhqX+
-----END PRIVATE KEY-----"#;

    // Corresponding JWKS (public key in JWK format)
    pub(crate) const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"u-uexVS-4MJo4zxH5eAPmoxtwxY-mB5kvYGq4BzAoaXSzG7fMm6rtYRz1DSkMp3VLxSeqvsSRRHbN3gbYweRiy7ZY_ZUnLxj7Fe9_Oq8qXh6t9CBK4Jtm3kCchfZXba1RwQT28-3gKOPosAif5uSLLqCwmGT0Kw1HaWsdHVBGv3j-m2nao2dq9K3nJx8NfsxsqM80hzbz7SvSD7CsAXGxo7eZ-fvZ1jd9tv5iEgLizcLb-5dy42vFO5tIsR9GS8BUoEy7cxHySErsfp4BkeJNjwVXqPsgzmbbmrcewIsWtRXqzsIqtsbKBjrNnYV2oMBRncG7PMfzLxI9OuzJtzqyw","e":"AQAB"}]}"#;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create a signed JWT with given claims.
    fn make_jwt(issuer: &str, subject: &str, audience: &str, iat: u64, exp: u64) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());

        let claims = json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": iat,
            "exp": exp,
        });

        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    /// Build a TestContext with OIDC enabled, pointing at the given mock JWKS URL.
    fn create_oidc_test_context(mock_issuer_url: &str) -> TestContext {
        create_oidc_test_context_scoped(mock_issuer_url, &["*"], None)
    }

    /// Like [`create_oidc_test_context`], with the provider `namespace_scope`
    /// and the main-branch rule's `namespace_scope` injectable.
    fn create_oidc_test_context_scoped(
        mock_issuer_url: &str,
        provider_scope: &[&str],
        main_rule_scope: Option<Vec<String>>,
    ) -> TestContext {
        create_oidc_test_context_with(mock_issuer_url, provider_scope, main_rule_scope, |_| {})
    }

    /// Like [`create_oidc_test_context`], with `tweak` applied to the provider.
    fn create_oidc_test_context_tweaked(
        mock_issuer_url: &str,
        tweak: impl FnOnce(&mut OidcProvider),
    ) -> TestContext {
        create_oidc_test_context_with(mock_issuer_url, &["*"], None, tweak)
    }

    fn create_oidc_test_context_with(
        mock_issuer_url: &str,
        provider_scope: &[&str],
        main_rule_scope: Option<Vec<String>>,
        tweak: impl FnOnce(&mut OidcProvider),
    ) -> TestContext {
        let issuer = mock_issuer_url.to_string();
        let provider_scope: Vec<String> = provider_scope.iter().map(|s| s.to_string()).collect();
        let mut ctx = create_test_context_with_config(move |cfg| {
            cfg.auth.enabled = true;
            cfg.auth.anonymous_read = false;
            cfg.auth.oidc = OidcConfig {
                enabled: true,
                leeway_secs: 60,
                jwks_cache_secs: 300,
                providers: vec![OidcProvider {
                    name: "test-ci".to_string(),
                    issuer: issuer.clone(),
                    jwks_uri: None,
                    audience: "nora".to_string(),
                    any_audience: false,
                    algorithms: vec!["RS256".to_string()],
                    max_token_lifetime_secs: 900,
                    namespace_scope: provider_scope.clone(),
                    namespace_scope_enforcement: crate::config::ScopeEnforcement::Enforce,
                    enabled: true,
                    role_rules: vec![
                        // Admin ROLE with a RESTRICTED scope, and admin role with
                        // no rule scope (unrestricted under provider `["*"]`).
                        // Distinct `admin-scoped`/`admin-free` segments so these
                        // never match the `repo:myorg/app:*` subjects other OIDC
                        // tests mint (first-match-wins). Used by the admin-mint
                        // scope-escape test.
                        OidcRoleRule {
                            pattern: "repo:myorg/admin-scoped:*".to_string(),
                            role: "admin".to_string(),
                            namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/admin-free:*".to_string(),
                            role: "admin".to_string(),
                            namespace_scope: None,
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*:ref:refs/heads/main".to_string(),
                            role: "write".to_string(),
                            namespace_scope: main_rule_scope.clone(),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*:pull_request".to_string(),
                            role: "write".to_string(),
                            namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*".to_string(),
                            role: "read".to_string(),
                            namespace_scope: None,
                        },
                    ],
                }],
            };
            tweak(&mut cfg.auth.oidc.providers[0]);
        });

        // Wire up the OidcValidator on the existing state
        let oidc_validator =
            OidcValidator::new(ctx.state.config.auth.oidc.clone(), reqwest::Client::new());
        // We need to rebuild the state with oidc set — use Arc::get_mut or rebuild
        let state = crate::AppState {
            storage: ctx.state.storage.clone(),
            config: ctx.state.config.clone(),
            enabled_registries: ctx.state.enabled_registries.clone(),
            start_time: ctx.state.start_time,
            startup_duration_ms: ctx.state.startup_duration_ms,
            auth: ctx.state.auth.clone(),
            // Prod builds a token store whenever `auth.enabled` (main.rs:1782);
            // the base builder keyed it off its `auth_enabled` arg (false here,
            // the `enabled` tweak comes from `customize`), leaving OIDC
            // identities' token operations untested. Mirror prod so the store is
            // present for an OIDC caller that reaches a token handler.
            tokens: Some(crate::tokens::TokenStore::new(
                ctx._tempdir.path().join("tokens").as_path(),
            )),
            metrics: Arc::new(crate::dashboard_metrics::DashboardMetrics::new()),
            activity: Arc::new(crate::activity_log::ActivityLog::new(50)),
            audit: ctx.state.audit.clone(),
            docker_auth: Arc::new(crate::registry::DockerAuth::new(reqwest::Client::new(), 5)),
            repo_index: Arc::new(crate::repo_index::RepoIndex::new()),
            http_client: reqwest::Client::new(),
            http_client_no_redirect: reqwest::Client::new(),
            hf_canonical_ids: Arc::default(),
            upload_sessions: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            publish_locks: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            reloadable: Arc::new(arc_swap::ArcSwap::from_pointee(crate::ReloadableConfig {
                curation_engine: crate::curation::CurationEngine::new(
                    crate::config::CurationConfig::default(),
                ),
                bypass_token: None,
            })),
            auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
            oidc: Some(Arc::new(oidc_validator)),
            circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
                ctx.state.config.circuit_breaker.clone(),
            )),
            proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
            blob_flights: crate::proxy_coalesce::InflightMap::new(),
            digest_store: ctx.state.digest_store.clone(),
            signer: ctx.state.signer.clone(),
            leak_finders: ctx.state.leak_finders.clone(),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            pull_stats: std::sync::Arc::new(
                crate::registry::docker::PullStatsAccumulator::default(),
            ),
            tasks: ctx.state.tasks.clone(),
            maintenance: ctx.state.maintenance.clone(),
        };

        // Rebuild router with new state
        use axum::{extract::DefaultBodyLimit, middleware, Router};
        let mut registry_routes = Router::new();
        for reg in state.enabled_registries.iter() {
            match reg {
                crate::registry_type::RegistryType::Raw => {
                    registry_routes = registry_routes.merge(crate::registry::raw_routes());
                }
                _ => {}
            }
        }
        let public_routes = Router::new().merge(crate::health::routes());
        let app_routes = Router::new()
            .merge(crate::auth::token_routes())
            .merge(crate::ui::routes())
            .merge(crate::admin::routes())
            .merge(registry_routes);
        let app = Router::new()
            .merge(public_routes)
            .merge(app_routes)
            .layer(DefaultBodyLimit::max(
                state.config.server.body_limit_mb * 1024 * 1024,
            ))
            .layer(middleware::from_fn(
                crate::request_id::request_id_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::auth_middleware,
            ))
            .with_state(state.clone());

        ctx.state = state;
        ctx.app = app;
        ctx
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_write_access() {
        let mock_server = MockServer::start().await;

        // Serve JWKS at /.well-known/jwks.json
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/oidc-test.txt",
            vec![("authorization", &bearer)],
            b"hello from ci".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Write with main-branch OIDC token should succeed"
        );
    }

    #[tokio::test]
    async fn test_oidc_rule_scope_narrows_writes() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // pull_request rule: role=write, namespace_scope=["ci-transport/**"]
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:pull_request",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", token);

        // In-scope write is allowed…
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/ci-transport/run-1/artifact.txt",
            vec![("authorization", &bearer)],
            b"transport".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "PR token should write inside its rule scope"
        );

        // …but the same identity cannot write outside the rule's scope, even
        // though the provider scope is ["*"].
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/prod/artifact.txt",
            vec![("authorization", &bearer)],
            b"escape".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "PR token must not write outside its rule scope"
        );
    }

    /// #1094: a namespace-scoped OIDC identity must not escalate by
    /// minting an unrestricted opaque token through the UI create path. The
    /// write handlers enforce the scope (the control below), and the UI mint
    /// now refuses a scoped caller (`decide_ui_token_mint`) instead of handing
    /// it an `nra_` token that writes anywhere. Before the fix the mint returned
    /// 200 and that token wrote to `prod/`; on `github/main` the UI path
    /// required Basic auth and returned 400.
    #[tokio::test]
    async fn test_oidc_scoped_identity_cannot_mint_unrestricted_token_via_ui() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // pull_request rule: role=write, namespace_scope=["ci-transport/**"].
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:pull_request",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", jwt);

        // Control: the identity cannot write to prod/ directly — scope enforced.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/prod/a.txt",
            vec![("authorization", &bearer)],
            b"x".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "control: a ci-transport-scoped identity must not write to prod/"
        );

        // The UI mint refuses the scoped caller: nothing is handed out.
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &bearer),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=3650".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a namespace-scoped identity minted an unrestricted token via the UI"
        );
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .is_empty(),
            "a token was minted for a scoped caller despite the 403"
        );
    }

    /// #1094 (admin sibling): the admin-gated mint route `POST
    /// /api/v1/admin/tokens` is reachable by every identity the admin gate
    /// admits — including an OIDC identity assigned the `admin` ROLE with a
    /// RESTRICTED `namespace_scope`. Admin role is not admin authority: the
    /// opaque token minted here is always namespace-unrestricted, so a scoped
    /// admin must be refused (403, nothing minted) or it escalates past its own
    /// `ci-transport/**` scope through the token. The non-vacuous pair: an
    /// UNRESTRICTED admin (rule scope `None`, provider `["*"]`) is NOT refused —
    /// the refusal keys on the caller's scope, not on the route.
    #[tokio::test]
    async fn test_oidc_scoped_admin_cannot_mint_unrestricted_token_via_admin_route() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();

        // Scoped admin: role=admin WITH namespace_scope=["ci-transport/**"].
        let scoped = make_jwt(
            &mock_server.uri(),
            "repo:myorg/admin-scoped:deploy",
            "nora",
            now,
            now + 600,
        );
        let scoped_bearer = format!("Bearer {}", scoped);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &scoped_bearer),
                ("content-type", "application/json"),
            ],
            br#"{"username":"svc","role":"write","ttl_days":36500}"#.to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a namespace-scoped admin minted an unrestricted token via the admin route"
        );
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .is_empty(),
            "a token was minted for a scoped admin despite the 403"
        );

        // Non-vacuous pair: an unrestricted admin (rule scope None, provider
        // ["*"]) IS allowed — the refusal keys on scope, not on the route.
        let free = make_jwt(
            &mock_server.uri(),
            "repo:myorg/admin-free:deploy",
            "nora",
            now,
            now + 600,
        );
        let free_bearer = format!("Bearer {}", free);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &free_bearer),
                ("content-type", "application/json"),
            ],
            br#"{"username":"svc","role":"write","ttl_days":30}"#.to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an unrestricted admin must still be able to mint via the admin route"
        );
        assert_eq!(
            ctx.state.tokens.as_ref().unwrap().list_all_tokens().len(),
            1,
            "exactly one token minted by the unrestricted admin"
        );
    }

    /// #1094: a token minted by an OIDC identity through the UI must not outlive
    /// the provider's `max_token_lifetime_secs` (900s here). An unrestricted
    /// write identity (main-ref rule, provider `["*"]`) may mint — it is not
    /// scope-refused — but the 3650-day request is capped to the ceiling itself,
    /// not rounded up to a day, and never outlives the JWT that minted
    /// it: here the JWT expires in 600s, under the ceiling.
    #[tokio::test]
    async fn test_oidc_minted_token_lifetime_capped_at_provider_ceiling() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // main-ref rule: role=write, no rule scope, provider scope ["*"] -> an
        // UNRESTRICTED identity (not refused by the scope gate).
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", jwt);

        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &bearer),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=3650".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an unrestricted OIDC identity may mint a token"
        );

        let entries = ctx.state.tokens.as_ref().unwrap().list_all_tokens();
        assert_eq!(entries.len(), 1, "exactly one token minted");
        let lifetime = entries[0].expires_at - entries[0].created_at;
        assert!(
            (590..=600).contains(&lifetime),
            "an OIDC-minted token outlived the JWT that minted it: {lifetime}s (JWT 600s, ceiling 900s)"
        );
    }

    /// A JWT the validator still accepts inside its leeway, though its `exp`
    /// has passed, mints nothing: the token would outlive the credential that
    /// minted it from its first second. Fail closed: 403, no token.
    #[tokio::test]
    async fn test_oidc_identity_already_expired_cannot_mint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Lifetime 600s (under the 900s ceiling), expired 30s ago, inside the
        // 60s leeway: authentication still accepts it.
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now - 630,
            now - 30,
        );
        let bearer = format!("Bearer {jwt}");
        let read = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/none.txt",
            vec![("authorization", &bearer)],
            Vec::new(),
        )
        .await;
        assert_eq!(
            read.status(),
            StatusCode::NOT_FOUND,
            "the JWT authenticates"
        );
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &bearer),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=1".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            ctx.state
                .tokens
                .as_ref()
                .unwrap()
                .list_all_tokens()
                .is_empty(),
            "an expired JWT minted a token"
        );
    }

    /// A JWT without `exp` is refused at authentication (the validator
    /// requires it), so it never reaches the mint.
    #[tokio::test]
    async fn test_oidc_jwt_without_exp_cannot_mint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context(&mock_server.uri());
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let claims = json!({
            "iss": mock_server.uri(),
            "sub": "repo:myorg/app:ref:refs/heads/main",
            "aud": "nora",
            "iat": now_secs(),
        });
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        let jwt = encode(&header, &claims, &key).unwrap();
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                ("authorization", &format!("Bearer {jwt}")),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=test&role=write&ttl_days=1".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .is_empty());
    }

    #[tokio::test]
    async fn test_oidc_rule_scope_cannot_widen_provider_ceiling() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        // Narrow provider ceiling, rule that tries to widen to ["*"].
        let ctx = create_oidc_test_context_scoped(
            &mock_server.uri(),
            &["myorg/**"],
            Some(vec!["*".to_string()]),
        );
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {}", token);

        // Inside the provider ceiling: allowed.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/myorg/repo/artifact.txt",
            vec![("authorization", &bearer)],
            b"inside".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // The rule's ["*"] must not lift the provider ceiling.
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/other/artifact.txt",
            vec![("authorization", &bearer)],
            b"escape".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a rule namespace_scope of [\"*\"] must not widen past the provider scope"
        );
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_read_only_blocks_write() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // dev branch → read-only role
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/dev",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/oidc-test.txt",
            vec![("authorization", &bearer)],
            b"hello".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Write with read-only OIDC token should be forbidden"
        );
    }

    #[tokio::test]
    async fn test_oidc_valid_jwt_read_only_allows_get() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/dev",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        // GET should succeed (even if file doesn't exist — 404 not 401/403)
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/nonexistent.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Read with valid OIDC token should not be 401"
        );
        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Read with read-only OIDC token should not be 403"
        );
    }

    #[tokio::test]
    async fn test_oidc_expired_token_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        // Token expired 2 minutes ago (beyond 60s leeway)
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now - 600,
            now - 120,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Expired OIDC token should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_wrong_issuer_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token has a different issuer than configured
        let token = make_jwt(
            "https://evil-issuer.example.com",
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with wrong issuer should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_wrong_audience_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token has wrong audience
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "wrong-audience",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with wrong audience should be rejected"
        );
    }

    /// The router answer to a write-role token with `aud`, against a mock
    /// issuer whose provider gets `tweak`.
    async fn oidc_status_for_aud(aud: &str, tweak: impl FnOnce(&mut OidcProvider)) -> StatusCode {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context_tweaked(&mock_server.uri(), tweak);
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            aud,
            now,
            now + 600,
        );
        let bearer = format!("Bearer {token}");
        send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/aud/file.txt",
            vec![("authorization", &bearer)],
            "data",
        )
        .await
        .status()
    }

    /// With an audience set, a token minted for that audience writes and one
    /// minted for another service is refused.
    #[tokio::test]
    async fn test_oidc_audience_admits_only_its_own_aud() {
        assert!(oidc_status_for_aud("nora", |_| {}).await.is_success());
        assert_eq!(
            oidc_status_for_aud("another-service", |_| {}).await,
            StatusCode::UNAUTHORIZED
        );
    }

    /// `any_audience = true` turns the `aud` check off: a token minted for
    /// another service writes.
    #[tokio::test]
    async fn test_oidc_any_audience_admits_any_aud() {
        let any = |p: &mut OidcProvider| {
            p.audience = String::new();
            p.any_audience = true;
        };
        assert!(oidc_status_for_aud("another-service", any)
            .await
            .is_success());
        assert!(oidc_status_for_aud("nora", any).await.is_success());
    }

    /// Beside an audience, `any_audience = true` changes nothing: the audience
    /// is still checked.
    #[tokio::test]
    async fn test_oidc_audience_wins_over_any_audience() {
        let both = |p: &mut OidcProvider| p.any_audience = true;
        assert_eq!(
            oidc_status_for_aud("another-service", both).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(oidc_status_for_aud("nora", both).await.is_success());
    }

    /// A provider with neither an audience nor `any_audience` admits no token,
    /// even if it reaches the validator without passing config validation.
    #[tokio::test]
    async fn test_oidc_provider_without_audience_admits_no_token() {
        let none = |p: &mut OidcProvider| p.audience = String::new();
        assert_eq!(
            oidc_status_for_aud("another-service", none).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            oidc_status_for_aud("nora", none).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_oidc_no_matching_role_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Subject from a different org → no role_rules match
        let token = make_jwt(
            &mock_server.uri(),
            "repo:otherorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token with no matching role should be rejected"
        );
    }

    /// A valid OIDC JWT is served while the client address is locked out for
    /// wrong passwords: the lockout counts passwords, not signed tokens.
    #[tokio::test]
    async fn test_oidc_valid_jwt_served_while_passwords_locked_out() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let ctx = create_oidc_test_context(&mock_server.uri());
        // Lock the address out for every username.
        for n in 0..60 {
            ctx.state
                .auth_failures
                .record_failure("127.0.0.1".parse().unwrap(), &format!("u{n}"));
        }
        let now = now_secs();
        let jwt = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );
        let bearer = format!("Bearer {jwt}");
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/locked-out/a.txt",
            vec![("authorization", &bearer)],
            b"data".to_vec(),
        )
        .await;
        assert!(
            response.status().is_success(),
            "a valid OIDC JWT from a locked-out address is refused: {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn test_oidc_token_lifetime_exceeded() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        // Token lifetime = 2000s, exceeds max_token_lifetime_secs = 900
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 2000,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Token exceeding max lifetime should be rejected"
        );
    }

    #[tokio::test]
    async fn test_oidc_jwks_fetch_failure_returns_401() {
        let mock_server = MockServer::start().await;

        // Don't mount any mock → JWKS fetch will 404
        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();
        let token = make_jwt(
            &mock_server.uri(),
            "repo:myorg/app:ref:refs/heads/main",
            "nora",
            now,
            now + 600,
        );

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Should fail gracefully when JWKS cannot be fetched"
        );
    }

    #[tokio::test]
    async fn test_oidc_symmetric_algorithm_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let ctx = create_oidc_test_context(&mock_server.uri());
        let now = now_secs();

        // Create token signed with HS256 (symmetric) — should be rejected
        // even before JWKS fetch because of algorithm whitelist
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".to_string());
        let claims = json!({
            "iss": mock_server.uri(),
            "sub": "repo:myorg/app:ref:refs/heads/main",
            "aud": "nora",
            "iat": now,
            "exp": now + 600,
        });
        let key = EncodingKey::from_secret(b"fake-secret");
        let token = encode(&header, &claims, &key).unwrap();

        let bearer = format!("Bearer {}", token);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/test.txt",
            vec![("authorization", &bearer)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "HS256 tokens must be rejected for OIDC"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod web_surface_gating_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_anonymous_read,
        create_test_context_with_anonymous_read_and_config, create_test_context_with_auth, send,
        send_with_headers,
    };
    use axum::http::{Method, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn basic(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    /// With auth on and no anonymous read, the whole web surface requires
    /// credentials — it enumerates every repository — while probes stay open.
    #[tokio::test]
    async fn test_web_surface_gated_when_private() {
        let ctx = create_test_context_with_auth(&[("alice", "pw")]);

        for p in [
            "/ui/",
            "/ui/rpm",
            "/api/ui/stats",
            "/api/ui/dashboard",
            "/api-docs/openapi.json",
        ] {
            let resp = send(&ctx.app, Method::GET, p, "").await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{p}");
            assert!(
                resp.headers().get("www-authenticate").is_some(),
                "{p} must challenge so browsers prompt"
            );
        }
        // Probes stay unconditionally open (LB/liveness would break).
        for p in ["/health", "/ready"] {
            let resp = send(&ctx.app, Method::GET, p, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{p}");
        }
        // /metrics defaults to open for scrapers.
        let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Valid credentials open the web surface.
        let cred = basic("alice", "pw");
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/stats",
            vec![("authorization", cred.as_str())],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// anonymous_read (which already exposes repo names through the registry
    /// read APIs) or the explicit public_web_ui switch reopen the surface;
    /// public_metrics=false closes /metrics.
    #[tokio::test]
    async fn test_gating_switches() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.anonymous_read = true;
        });
        let resp = send(&ctx.app, Method::GET, "/ui/", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "anonymous_read opens the UI");

        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_web_ui = true;
        });
        let resp = send(&ctx.app, Method::GET, "/api/ui/stats", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "public_web_ui opens the UI");

        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_metrics = false;
        });
        let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "public_metrics=false gates metrics"
        );
    }

    /// Token management pages stay gated even when the web surface is open.
    #[tokio::test]
    async fn test_token_pages_stay_gated() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.auth.enabled = true;
            c.auth.public_web_ui = true;
        });
        let resp = send(&ctx.app, Method::GET, "/api/ui/tokens", "").await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    // -- #934: opportunistic auth on open web surfaces --

    /// try_basic_auth returns the username for valid htpasswd credentials once htpasswd
    /// has checked them, and runs no bcrypt itself: before the check, the caller is
    /// anonymous.
    #[tokio::test]
    async fn test_try_basic_auth_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("htpasswd");
        let hash = bcrypt::hash("secret", 4).unwrap();
        std::fs::write(&path, format!("admin:{hash}\n")).unwrap();
        let htpasswd = super::HtpasswdAuth::from_file(&path).unwrap();
        let encoded = STANDARD.encode("admin:secret");
        assert_eq!(super::try_basic_auth(&encoded, Some(&htpasswd)), None);
        assert!(htpasswd.verify("admin", "secret").await);
        assert_eq!(
            super::try_basic_auth(&encoded, Some(&htpasswd)),
            Some("admin".to_string())
        );
        assert_eq!(
            htpasswd
                .bcrypt_runs
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the check ran bcrypt"
        );
    }

    /// try_basic_auth returns None for wrong password.
    #[test]
    fn test_try_basic_auth_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("htpasswd");
        let hash = bcrypt::hash("secret", 4).unwrap();
        std::fs::write(&path, format!("admin:{hash}\n")).unwrap();
        let htpasswd = super::HtpasswdAuth::from_file(&path).unwrap();
        let encoded = STANDARD.encode("admin:wrong");
        assert_eq!(super::try_basic_auth(&encoded, Some(&htpasswd)), None);
    }

    /// try_basic_auth returns None when no htpasswd store is available.
    #[test]
    fn test_try_basic_auth_no_store() {
        let encoded = STANDARD.encode("admin:secret");
        assert_eq!(super::try_basic_auth(&encoded, None), None);
    }

    /// try_basic_auth returns None for garbage base64.
    #[test]
    fn test_try_basic_auth_invalid_base64() {
        assert_eq!(super::try_basic_auth("%%%not-base64%%%", None), None);
    }

    /// On an open web surface (anonymous_read=true), valid Basic credentials that
    /// htpasswd has checked must produce a real AuthenticatedUser — not "anonymous". Verified via
    /// /api/ui/dashboard: anonymous sees empty proxy_upstreams; authenticated
    /// sees the configured npm upstream.
    #[tokio::test]
    async fn test_opportunistic_basic_auth_on_open_surface() {
        let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
            c.npm.proxy = Some("https://registry.npmjs.org".into());
        });

        // Anonymous: proxy_upstreams redacted
        let resp = send(&ctx.app, Method::GET, "/api/ui/dashboard", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for mp in json["mount_points"].as_array().unwrap() {
            assert!(
                mp["proxy_upstreams"].as_array().unwrap().is_empty(),
                "anonymous must see empty proxy_upstreams"
            );
        }

        // Valid Basic creds htpasswd has not checked yet: the open path runs no bcrypt,
        // so the caller browses as anonymous.
        let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
        let dashboard = || {
            send_with_headers(
                &ctx.app,
                Method::GET,
                "/api/ui/dashboard",
                vec![("authorization", &header_val)],
                "",
            )
        };
        let npm_upstreams = |json: serde_json::Value| {
            json["mount_points"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["registry"].as_str() == Some("npm"))
                .expect("npm mount")["proxy_upstreams"]
                .as_array()
                .unwrap()
                .len()
        };
        let resp = dashboard().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(
            npm_upstreams(json),
            0,
            "unchecked credentials are anonymous"
        );

        // A gated page checks them (a browser sends them after its challenge); from then on
        // the open surface knows the caller: proxy_upstreams populated.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/tokens",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = dashboard().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let npm = json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some("npm"))
            .expect("npm mount");
        assert!(
            !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
            "authenticated must see populated proxy_upstreams for npm"
        );
    }

    /// On an open web surface, invalid Basic credentials fall through to
    /// anonymous (the path is open — no 401).
    #[tokio::test]
    async fn test_opportunistic_bad_creds_fall_through_to_anonymous() {
        let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

        let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &bad)],
            "",
        )
        .await;
        // Open path — no 401 even with bad creds
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// On an open web surface, a valid Bearer token must produce a real
    /// AuthenticatedUser, enabling proxy_upstreams disclosure.
    #[tokio::test]
    async fn test_opportunistic_bearer_auth_on_open_surface() {
        let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
            c.npm.proxy = Some("https://registry.npmjs.org".into());
        });

        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("admin", 30, None, crate::tokens::Role::Write)
            .unwrap();

        let header_val = format!("Bearer {token}");
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let npm = json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some("npm"))
            .expect("npm mount");
        assert!(
            !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
            "bearer-authenticated must see populated proxy_upstreams"
        );
    }
}

// ---------------------------------------------------------------------------
// Client address and lockout: the key the lockout and the limiters count by
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod client_address_tests {
    use super::resolve_client_ip;
    use crate::config::TrustedProxies;
    use crate::test_helpers::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderMap, Method, Request, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, Mutex};

    /// A dual-stack socket (`NORA_HOST=::`, the image default) sees an IPv4
    /// peer as `::ffff:a.b.c.d`.
    const MAPPED_LOOPBACK: &str = "::ffff:127.0.0.1";

    fn resolve(
        peer: &str,
        xff: &[&str],
        real_ip: Option<&str>,
        trusted: &TrustedProxies,
    ) -> IpAddr {
        let mut headers = HeaderMap::new();
        for line in xff {
            headers.append("x-forwarded-for", line.parse().unwrap());
        }
        if let Some(ip) = real_ip {
            headers.insert("x-real-ip", ip.parse().unwrap());
        }
        resolve_client_ip(peer.parse().unwrap(), &headers, trusted)
    }

    /// Measured in kind (ingress behind the image's `::` listener): the peer, the
    /// trusted_proxies entry and the X-Forwarded-For entries meet in IPv4 form.
    #[test]
    fn an_ipv4_peer_on_a_dual_stack_listener_is_the_ipv4_address() {
        let resolve = |peer: &str, xff: Option<&str>, trusted: &str| {
            let mut headers = HeaderMap::new();
            if let Some(xff) = xff {
                headers.insert("x-forwarded-for", xff.parse().unwrap());
            }
            let peer: IpAddr = peer.parse().unwrap();
            resolve_client_ip(peer, &headers, &TrustedProxies::parse(trusted)).to_string()
        };
        // the ingress, trusted by its IPv4 address, seen on a `::` listener
        assert_eq!(
            resolve("::ffff:10.244.0.5", Some("10.244.0.7"), "10.244.0.5/32"),
            "10.244.0.7"
        );
        assert_eq!(
            resolve("::ffff:10.244.0.5", Some("10.244.0.7"), "10.244.0.0/16"),
            "10.244.0.7"
        );
        // a trusted proxy written in the mapped form, seen as IPv4
        assert_eq!(
            resolve("10.244.0.5", Some("10.244.0.7"), "::ffff:10.244.0.5"),
            "10.244.0.7"
        );
        // a hop that writes its peer in the mapped form is walked past
        assert_eq!(
            resolve(
                "::ffff:10.244.0.5",
                Some("10.244.0.7, ::ffff:10.244.0.6"),
                "10.244.0.0/16"
            ),
            "10.244.0.7"
        );
        // an untrusted peer is its IPv4 address, so it shares its limits with itself only
        assert_eq!(
            resolve("::ffff:203.0.113.9", None, "10.0.0.0/8"),
            "203.0.113.9"
        );
        // a proxy that writes the client in the mapped form names it in IPv4
        assert_eq!(
            resolve(
                "::ffff:10.244.0.5",
                Some("::ffff:10.244.0.7"),
                "10.244.0.0/16"
            ),
            "10.244.0.7"
        );
        // the list itself, asked directly
        let ipv4 = TrustedProxies::parse("10.0.0.0/8");
        assert!(ipv4.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!ipv4.contains("::ffff:11.1.2.3".parse().unwrap()));
        // a real IPv6 peer stays IPv6 and is not an IPv4 network's member
        assert_eq!(
            resolve("2001:db8::1", Some("10.244.0.7"), "10.0.0.0/8"),
            "2001:db8::1"
        );
    }

    /// An IPv4 address is one client whether it arrives over an IPv4 or a
    /// dual-stack socket, as the peer, in X-Forwarded-For, in X-Real-IP or in
    /// `trusted_proxies`: the resolved address is the plain IPv4 one.
    #[test]
    fn a_v4_mapped_address_is_its_ipv4_address() {
        let loopback = TrustedProxies::default_loopback();
        let pods = TrustedProxies::parse("10.0.0.0/8");
        let mapped_pods = TrustedProxies::parse("::ffff:10.0.0.0/104");
        let v4 = |s: &str| s.parse::<IpAddr>().unwrap();
        let cases: [(&str, &[&str], Option<&str>, &TrustedProxies, IpAddr); 7] = [
            // the loopback proxy over a dual-stack socket is still trusted
            (
                MAPPED_LOOPBACK,
                &["198.51.100.7"],
                None,
                &loopback,
                v4("198.51.100.7"),
            ),
            // a direct client over a dual-stack socket keys as its IPv4 address
            (
                "::ffff:203.0.113.5",
                &[],
                None,
                &loopback,
                v4("203.0.113.5"),
            ),
            // a mapped address written by a proxy
            (
                "127.0.0.1",
                &["::ffff:198.51.100.7"],
                None,
                &loopback,
                v4("198.51.100.7"),
            ),
            (
                "127.0.0.1",
                &[],
                Some("::ffff:203.0.113.9"),
                &loopback,
                v4("203.0.113.9"),
            ),
            // a mapped trusted hop in the chain is walked past
            (
                "10.1.2.3",
                &["198.51.100.7, ::ffff:10.0.0.5"],
                None,
                &pods,
                v4("198.51.100.7"),
            ),
            // a pod network named in either form trusts the other
            (
                "::ffff:10.1.2.3",
                &["198.51.100.7"],
                None,
                &pods,
                v4("198.51.100.7"),
            ),
            (
                "10.1.2.3",
                &["198.51.100.7"],
                None,
                &mapped_pods,
                v4("198.51.100.7"),
            ),
        ];
        for (peer, xff, real_ip, trusted, want) in cases {
            let got = resolve(peer, xff, real_ip, trusted);
            assert_eq!(got, want, "peer {peer} xff {xff:?} real_ip {real_ip:?}");
            assert!(got.is_ipv4(), "{got} is not canonical");
        }
        // The setting answers for a mapped address as for its IPv4 address.
        assert!(loopback.contains(MAPPED_LOOPBACK.parse().unwrap()));
        assert!(pods.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!pods.contains("::ffff:11.0.0.1".parse().unwrap()));
        // A real IPv6 client stays itself.
        assert_eq!(
            resolve("2001:db8::7", &[], None, &loopback),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The warnings `run` logs.
    fn warnings_of(run: impl FnOnce()) -> Vec<String> {
        use tracing_subscriber::prelude::*;
        let sink = Captured::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(sink.clone()),
        );
        tracing::subscriber::with_default(subscriber, run);
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        out.lines()
            .filter(|l| l.contains("WARN"))
            .map(str::to_string)
            .collect()
    }

    /// X-Forwarded-For from a peer outside `trusted_proxies` is ignored, and
    /// NORA says so once: the warning names the peer and the setting, and
    /// never the header, which the client wrote.
    #[test]
    fn forwarding_from_an_untrusted_peer_is_warned_about_once() {
        let trusted = TrustedProxies::parse("10.9.9.9");
        let warnings = warnings_of(|| {
            for _ in 0..3 {
                let ip = resolve("127.0.0.1", &["203.0.113.10"], None, &trusted);
                assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
            }
            // a clone is the same setting (the limiters hold clones)
            let _ = resolve("127.0.0.1", &["203.0.113.10"], None, &trusted.clone());
        });
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("127.0.0.1"), "{}", warnings[0]);
        assert!(warnings[0].contains("trusted_proxies"), "{}", warnings[0]);
        assert!(!warnings[0].contains("203.0.113.10"), "{}", warnings[0]);

        // No warning when there is nothing to ignore.
        let quiet = warnings_of(|| {
            let loopback = TrustedProxies::default_loopback();
            let _ = resolve("127.0.0.1", &["203.0.113.10"], None, &loopback);
            let _ = resolve(MAPPED_LOOPBACK, &["203.0.113.10"], None, &loopback);
            let _ = resolve("203.0.113.5", &[], None, &TrustedProxies::parse("10.9.9.9"));
        });
        assert!(quiet.is_empty(), "{quiet:#?}");
    }

    /// Each forwarding header NORA reads is ignored from a peer outside
    /// `trusted_proxies`, sent alone or with the other, and NORA says so once
    /// per setting, never with the header's content.
    #[test]
    fn every_forwarding_header_from_an_untrusted_peer_is_warned_about() {
        let sent: [(&[&str], Option<&str>); 3] = [
            (&["203.0.113.10"], None),
            (&[], Some("203.0.113.10")),
            (&["203.0.113.10"], Some("203.0.113.10")),
        ];
        for (xff, real_ip) in sent {
            let trusted = TrustedProxies::parse("10.9.9.9");
            let warnings = warnings_of(|| {
                for _ in 0..2 {
                    let ip = resolve("127.0.0.1", xff, real_ip, &trusted);
                    assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
                }
            });
            assert_eq!(
                warnings.len(),
                1,
                "xff {xff:?} real_ip {real_ip:?}: {warnings:#?}"
            );
            assert!(warnings[0].contains("127.0.0.1"), "{}", warnings[0]);
            assert!(!warnings[0].contains("203.0.113.10"), "{}", warnings[0]);
        }
    }

    /// Send a request from `peer` (the TCP address the server sees).
    async fn send_from(
        app: &axum::Router,
        peer: &str,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> StatusCode {
        use tower::ServiceExt;
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 4000)));
        app.clone().oneshot(request).await.unwrap().status()
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
    }

    /// Behind the loopback proxy on a dual-stack socket, one client's
    /// wrong passwords lock out that client only: the same account from
    /// another client behind the same proxy still gets in.
    #[tokio::test]
    async fn a_v4_mapped_proxy_keeps_its_clients_apart() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
        let wrong = basic("bob", "wrong");
        for _ in 0..6 {
            let status = send_from(
                &ctx.app,
                MAPPED_LOOPBACK,
                Method::GET,
                "/v2/",
                &[
                    ("authorization", &wrong),
                    ("x-forwarded-for", "203.0.113.10"),
                ],
            )
            .await;
            assert!(
                matches!(
                    status,
                    StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
                ),
                "{status}"
            );
        }
        // The same account, from another client behind the same proxy.
        let good = basic("bob", "bobpw");
        let other = send_from(
            &ctx.app,
            MAPPED_LOOPBACK,
            Method::GET,
            "/v2/",
            &[
                ("authorization", &good),
                ("x-forwarded-for", "198.51.100.7"),
            ],
        )
        .await;
        assert_eq!(
            other,
            StatusCode::OK,
            "another client behind the proxy is locked out"
        );
        let same = send_from(
            &ctx.app,
            MAPPED_LOOPBACK,
            Method::GET,
            "/v2/",
            &[
                ("authorization", &good),
                ("x-forwarded-for", "203.0.113.10"),
            ],
        )
        .await;
        assert_eq!(
            same,
            StatusCode::TOO_MANY_REQUESTS,
            "the guessing client is not locked out"
        );
    }

    /// The lockout counts wrong passwords: while an address is locked
    /// out, a valid API token sent as Bearer is served, and wrong Bearer tokens
    /// do not lock an address out at all. A password stays refused.
    #[tokio::test]
    async fn a_valid_bearer_token_is_served_while_passwords_are_locked_out() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Write)
            .unwrap();
        let bearer = format!("Bearer {token}");
        let wrong = basic("alice", "wrong");
        for _ in 0..6 {
            let _ = send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", &wrong)],
            )
            .await;
        }
        let good = basic("alice", "alicepw");
        assert_eq!(
            send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", &good)]
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "passwords from a locked-out address are refused"
        );
        assert_eq!(
            send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", &bearer)]
            )
            .await,
            StatusCode::OK,
            "a valid Bearer token from a locked-out address is refused"
        );
        // The served token did not lift the lockout of passwords.
        assert_eq!(
            send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", &good)]
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "a Bearer token lifted the password lockout"
        );
    }

    #[tokio::test]
    async fn wrong_bearer_tokens_do_not_lock_an_address_out() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let bad = "Bearer nra_00000000000000000000000000000000";
        for _ in 0..8 {
            assert_eq!(
                send_from(
                    &ctx.app,
                    "127.0.0.1",
                    Method::GET,
                    "/v2/",
                    &[("authorization", bad)]
                )
                .await,
                StatusCode::UNAUTHORIZED
            );
        }
        let good = basic("alice", "alicepw");
        assert_eq!(
            send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", &good)]
            )
            .await,
            StatusCode::OK,
            "wrong Bearer tokens locked the address out"
        );
    }

    /// Every client of these tests sits behind one NAT address, as a company
    /// behind its egress does; the loopback proxy in front of NORA is trusted.
    const NAT: &str = "198.51.100.50";

    /// GET /v2/ from a client behind `xff` with Basic `user:pass`.
    async fn login(app: &axum::Router, xff: &str, user: &str, pass: &str) -> StatusCode {
        let auth = basic(user, pass);
        send_from(
            app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &auth), ("x-forwarded-for", xff)],
        )
        .await
    }

    /// Wrong passwords for one account lock out that account on that address,
    /// not another account behind the same NAT.
    #[tokio::test]
    async fn guessing_one_accounts_password_leaves_other_accounts_alone() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
        for _ in 0..6 {
            let _ = login(&ctx.app, NAT, "alice", "wrong").await;
        }
        assert_eq!(
            login(&ctx.app, NAT, "bob", "bobpw").await,
            StatusCode::OK,
            "guesses at alice locked bob out"
        );
        assert_eq!(
            login(&ctx.app, NAT, "alice", "alicepw").await,
            StatusCode::TOO_MANY_REQUESTS,
            "the guessed account is not locked out"
        );
    }

    /// A login by one account does not clear the failures of another.
    #[tokio::test]
    async fn a_login_does_not_clear_another_accounts_failures() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
        for _ in 0..4 {
            assert_eq!(
                login(&ctx.app, NAT, "alice", "wrong").await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(login(&ctx.app, NAT, "bob", "bobpw").await, StatusCode::OK);
        assert_eq!(
            login(&ctx.app, NAT, "alice", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&ctx.app, NAT, "alice", "alicepw").await,
            StatusCode::TOO_MANY_REQUESTS,
            "bob's login cleared alice's failures"
        );
    }

    /// Guessing across many usernames from one address is still held: past a
    /// ceiling of failed passwords per address (ten accounts' worth of the
    /// per-account threshold) the address gets no password checked, whatever
    /// the username. Below it, the address is not held, and another address is
    /// never held by it.
    #[tokio::test]
    async fn guessing_many_usernames_from_one_address_is_capped() {
        let ctx = create_test_context_with_auth(&[("bob", "bobpw")]);
        // 49 failures, never more than 4 for one username: no account is
        // locked out and the address is one below its ceiling of 50.
        for n in 0..49 {
            let user = format!("u{}", n / 4);
            assert_eq!(
                login(&ctx.app, NAT, &user, "wrong").await,
                StatusCode::UNAUTHORIZED,
                "guess {n}"
            );
        }
        assert_eq!(
            login(&ctx.app, NAT, "bob", "bobpw").await,
            StatusCode::OK,
            "the address was held below its ceiling"
        );
        // The 50th failure, for yet another username, reaches the ceiling.
        assert_eq!(
            login(&ctx.app, NAT, "fresh", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&ctx.app, NAT, "bob", "bobpw").await,
            StatusCode::TOO_MANY_REQUESTS,
            "guessing across usernames is not held per address"
        );
        assert_eq!(
            login(&ctx.app, NAT, "other", "wrong").await,
            StatusCode::TOO_MANY_REQUESTS,
            "a new username escapes the address ceiling"
        );
        assert_eq!(
            login(&ctx.app, "192.0.2.77", "bob", "bobpw").await,
            StatusCode::OK,
            "another address is held"
        );
    }

    /// Control: an empty username is an account like any other, and a header
    /// with no username at all (no `:`) is malformed and not counted.
    #[tokio::test]
    async fn an_empty_or_missing_username_is_held_like_any_other() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let mut statuses = Vec::new();
        for _ in 0..6 {
            statuses.push(login(&ctx.app, NAT, "", "wrong").await.as_u16());
        }
        assert_eq!(statuses, [401, 401, 401, 401, 401, 429], "empty username");
        assert_eq!(
            login(&ctx.app, NAT, "alice", "alicepw").await,
            StatusCode::OK
        );

        let no_username = format!("Basic {}", STANDARD.encode("no-colon-here"));
        for _ in 0..8 {
            let status = send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[
                    ("authorization", &no_username),
                    ("x-forwarded-for", "192.0.2.80"),
                ],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "a malformed header is counted"
            );
        }
        assert_eq!(
            login(&ctx.app, "192.0.2.80", "alice", "alicepw").await,
            StatusCode::OK
        );
    }

    /// Docker sends an API token as the Basic password, under a username CI
    /// jobs share ("docker", "token"). A valid token is served while that
    /// username is locked out, as over Bearer; a password is not.
    #[tokio::test]
    async fn a_valid_api_token_as_the_basic_password_is_served_while_locked_out() {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 30, None, crate::tokens::Role::Write)
            .unwrap();
        for _ in 0..6 {
            let _ = login(
                &ctx.app,
                NAT,
                "docker",
                "nra_00000000000000000000000000000000",
            )
            .await;
        }
        assert_eq!(
            login(&ctx.app, NAT, "docker", "not-a-token").await,
            StatusCode::TOO_MANY_REQUESTS,
            "the username is not locked out"
        );
        assert_eq!(
            login(&ctx.app, NAT, "docker", &token).await,
            StatusCode::OK,
            "a valid token as the Basic password is refused while locked out"
        );
    }

    /// The routes that take a username and password in their JSON body, and
    /// the status each answers once the password is accepted (the revoke names
    /// a token alice does not have).
    const TOKEN_ROUTES: [(&str, StatusCode); 3] = [
        ("/api/tokens", StatusCode::OK),
        ("/api/tokens/list", StatusCode::OK),
        ("/api/tokens/revoke", StatusCode::NOT_FOUND),
    ];

    /// POST a token-route body for `alice` with `password` from `peer`.
    async fn token_route_from(
        app: &axum::Router,
        peer: &str,
        uri: &str,
        password: &str,
        headers: &[(&str, &str)],
    ) -> StatusCode {
        use tower::ServiceExt;
        let body = format!(
            r#"{{"username":"alice","password":"{password}","hash_prefix":"0123456789abcdef"}}"#
        );
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut request = builder.body(Body::from(body)).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 4000)));
        app.clone().oneshot(request).await.unwrap().status()
    }

    /// Lock alice out at `ip` for half a minute (ten failures), so no test
    /// step races the end of the lockout.
    fn lock_out_alice(tracker: &super::AuthFailureTracker, ip: &str) {
        for _ in 0..10 {
            tracker.record_failure(ip.parse().unwrap(), "alice");
        }
    }

    /// Every token route keeps the lockout as the middleware does: it counts
    /// a wrong password, a login clears the count, and a locked-out username
    /// gets no password checked, however the lockout was earned. Another
    /// address is not held.
    #[tokio::test]
    async fn every_token_route_keeps_the_lockout() {
        let client = "203.0.113.5";
        let ip: IpAddr = client.parse().unwrap();
        for (uri, served) in TOKEN_ROUTES {
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            let tracker = &ctx.state.auth_failures;

            // The wrong password that reaches the threshold is counted here.
            for _ in 0..4 {
                tracker.record_failure(ip, "alice");
            }
            assert_eq!(
                token_route_from(&ctx.app, client, uri, "wrong", &[]).await,
                StatusCode::UNAUTHORIZED,
                "{uri}"
            );
            assert!(
                tracker.check_blocked(&ip, "alice").is_some(),
                "{uri} does not count a wrong password"
            );

            // A login clears the account's count.
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            let tracker = &ctx.state.auth_failures;
            for _ in 0..4 {
                tracker.record_failure(ip, "alice");
            }
            assert_eq!(
                token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
                served,
                "{uri}"
            );
            tracker.record_failure(ip, "alice");
            assert!(
                tracker.check_blocked(&ip, "alice").is_none(),
                "{uri}: a login did not clear the failures"
            );

            // Locked out: the right password is refused, the address is
            // named in no way the client chooses, another address is served.
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            lock_out_alice(&ctx.state.auth_failures, client);
            assert_eq!(
                token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
                StatusCode::TOO_MANY_REQUESTS,
                "{uri} checks the password of a locked-out username"
            );
            assert_eq!(
                token_route_from(
                    &ctx.app,
                    client,
                    uri,
                    "alicepw",
                    &[
                        ("x-forwarded-for", "198.51.100.7"),
                        ("x-real-ip", "198.51.100.7")
                    ]
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS,
                "{uri}: forwarding headers from an untrusted peer escape the lockout"
            );
            assert_eq!(
                token_route_from(&ctx.app, "192.0.2.77", uri, "alicepw", &[]).await,
                served,
                "{uri}: another address is held"
            );
        }
    }

    /// A lockout earned on one token route holds on every other, and on the
    /// middleware's Basic login: it is one count per account, whichever route
    /// the guesses came by.
    #[tokio::test]
    async fn a_lockout_earned_on_one_token_route_holds_on_every_route() {
        let client = "203.0.113.5";
        for (earned_on, _) in TOKEN_ROUTES {
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            for _ in 0..4 {
                ctx.state
                    .auth_failures
                    .record_failure(client.parse().unwrap(), "alice");
            }
            assert_eq!(
                token_route_from(&ctx.app, client, earned_on, "wrong", &[]).await,
                StatusCode::UNAUTHORIZED
            );
            assert!(
                ctx.state
                    .auth_failures
                    .check_blocked(&client.parse().unwrap(), "alice")
                    .is_some(),
                "{earned_on} does not count a wrong password"
            );
            // Lengthen the lockout so no step below races its end.
            lock_out_alice(&ctx.state.auth_failures, client);
            for (uri, _) in TOKEN_ROUTES {
                assert_eq!(
                    token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
                    StatusCode::TOO_MANY_REQUESTS,
                    "locked out on {earned_on}, served on {uri}"
                );
            }
            let auth = basic("alice", "alicepw");
            assert_eq!(
                send_from(
                    &ctx.app,
                    client,
                    Method::GET,
                    "/v2/",
                    &[("authorization", &auth)]
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS,
                "locked out on {earned_on}, served by the middleware"
            );
        }
    }

    /// The token routes key a client by its canonical address, as the
    /// middleware does: `::ffff:a.b.c.d` from a dual-stack socket is the
    /// client `a.b.c.d`, for the failures it adds and the lockout it meets.
    #[tokio::test]
    async fn the_token_routes_key_a_v4_mapped_peer_as_its_ipv4_address() {
        for (uri, _) in TOKEN_ROUTES {
            // Locked out as 203.0.113.5, refused as ::ffff:203.0.113.5.
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            lock_out_alice(&ctx.state.auth_failures, "203.0.113.5");
            assert_eq!(
                token_route_from(&ctx.app, "::ffff:203.0.113.5", uri, "alicepw", &[]).await,
                StatusCode::TOO_MANY_REQUESTS,
                "{uri}: the mapped peer is another client"
            );

            // A wrong password from ::ffff:198.51.100.9 counts for 198.51.100.9.
            let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
            let ip: IpAddr = "198.51.100.9".parse().unwrap();
            for _ in 0..4 {
                ctx.state.auth_failures.record_failure(ip, "alice");
            }
            assert_eq!(
                token_route_from(&ctx.app, "::ffff:198.51.100.9", uri, "wrong", &[]).await,
                StatusCode::UNAUTHORIZED,
                "{uri}"
            );
            assert!(
                ctx.state
                    .auth_failures
                    .check_blocked(&ip, "alice")
                    .is_some(),
                "{uri}: a failure from the mapped peer is counted elsewhere"
            );
        }
    }
}
