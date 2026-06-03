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

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::AppState;

/// Tracks failed authentication attempts per IP for brute-force protection.
///
/// After `max_failures` consecutive failures, the IP is locked out with
/// exponential backoff: 2^(failures - max_failures) seconds, capped at 15 minutes.
pub struct AuthFailureTracker {
    /// IP -> (consecutive failures, last failure time)
    entries: parking_lot::Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// Number of failures before lockout kicks in (default: 5)
    max_failures: u32,
    /// Maximum lockout duration in seconds (default: 900 = 15 minutes)
    max_lockout_secs: u64,
}

impl AuthFailureTracker {
    pub fn new(max_failures: u32, max_lockout_secs: u64) -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
            max_failures,
            max_lockout_secs,
        }
    }

    /// Check if IP is currently locked out. Returns remaining lockout seconds if blocked.
    pub fn check_blocked(&self, ip: &IpAddr) -> Option<u64> {
        let entries = self.entries.lock();
        let (failures, last_failure) = entries.get(ip)?;
        if *failures < self.max_failures {
            return None;
        }
        let exponent = (*failures - self.max_failures).min(20);
        let lockout_secs = (1u64 << exponent).min(self.max_lockout_secs);
        let elapsed = last_failure.elapsed().as_secs();
        if elapsed < lockout_secs {
            Some(lockout_secs - elapsed)
        } else {
            None
        }
    }

    /// Record a failed auth attempt for an IP.
    pub fn record_failure(&self, ip: IpAddr) {
        let mut entries = self.entries.lock();
        let entry = entries.entry(ip).or_insert_with(|| (0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    /// Clear failure count on successful auth.
    pub fn record_success(&self, ip: &IpAddr) {
        let mut entries = self.entries.lock();
        entries.remove(ip);
    }

    /// Remove entries older than max_lockout_secs (call periodically).
    pub fn cleanup(&self) {
        let mut entries = self.entries.lock();
        entries.retain(|_, (_, last)| last.elapsed().as_secs() < self.max_lockout_secs * 2);
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

/// Extract client IP from request, honoring XFF/X-Real-IP only from trusted proxies.
///
/// If the direct peer IP is not in `trusted_proxies`, XFF/X-Real-IP headers are
/// ignored and the peer IP is returned. This prevents attackers from spoofing
/// their IP to bypass `AuthFailureTracker` lockout.
pub(crate) fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &crate::config::TrustedProxies,
) -> IpAddr {
    if !trusted_proxies.contains(peer) {
        return peer;
    }

    // Try X-Forwarded-For first (first IP in chain is the client)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // No forwarding headers — use peer IP
    peer
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
        return next.run(request).await;
    }

    // Skip auth for public endpoints
    if is_public_path(request.uri().path()) {
        request
            .extensions_mut()
            .insert(NamespaceAuthority::Unrestricted);
        return next.run(request).await;
    }

    // Docker V2 auth challenge: /v2/ must NOT bypass auth via anonymous_read.
    // Per Docker Registry V2 spec, unauthenticated GET /v2/ must return 401
    // with WWW-Authenticate header, so Docker clients send credentials on
    // subsequent requests. If /v2/ returns 200 without auth, Docker assumes
    // the registry is anonymous and never sends Authorization headers.
    let path = request.uri().path();
    let is_docker_challenge = is_docker_auth_challenge_path(path);

    // Token management always requires auth, even with anonymous_read
    let is_token_management = path.starts_with("/ui/tokens") || path.starts_with("/api/ui/tokens");

    // Allow anonymous read if configured (but not for Docker /v2/ or token management)
    let is_read_method = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    );
    if state.config.auth.anonymous_read
        && is_read_method
        && !is_docker_challenge
        && !is_token_management
    {
        // Read requests allowed without auth
        request
            .extensions_mut()
            .insert(NamespaceAuthority::Unrestricted);
        return next.run(request).await;
    }

    // Compute realm from public_url for WWW-Authenticate header
    let realm = state.config.server.public_url.as_deref().unwrap_or("Nora");

    // Check if client IP is blocked due to too many failed attempts
    let client_ip = extract_client_ip(&request, &state.config.auth.trusted_proxies);
    if let Some(ip) = client_ip {
        if let Some(retry_after) = state.auth_failures.check_blocked(&ip) {
            return (
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
                .into_response();
        }
    }

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
                Ok((_user, role)) => {
                    if let Some(ip) = client_ip {
                        state.auth_failures.record_success(&ip);
                    }
                    let method = request.method().clone();
                    if (method == axum::http::Method::PUT
                        || method == axum::http::Method::POST
                        || method == axum::http::Method::DELETE
                        || method == axum::http::Method::PATCH)
                        && !role.can_write()
                    {
                        return (StatusCode::FORBIDDEN, "Read-only token").into_response();
                    }
                    // Opaque (nra_) tokens are not namespace-scoped (#583 is OIDC-only).
                    request
                        .extensions_mut()
                        .insert(NamespaceAuthority::Unrestricted);
                    return next.run(request).await;
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
                        if let Some(ip) = client_ip {
                            state.auth_failures.record_success(&ip);
                        }
                        tracing::debug!(
                            provider = %identity.provider,
                            subject = %identity.subject,
                            role = ?identity.role,
                            "OIDC authentication successful"
                        );
                        let method = request.method().clone();
                        if (method == axum::http::Method::PUT
                            || method == axum::http::Method::POST
                            || method == axum::http::Method::DELETE
                            || method == axum::http::Method::PATCH)
                            && !identity.role.can_write()
                        {
                            return (StatusCode::FORBIDDEN, "Read-only OIDC identity")
                                .into_response();
                        }
                        // Carry the provider's namespace_scope into the request so
                        // write handlers can enforce it on the artifact coordinate (#583).
                        let authority = NamespaceAuthority::from_oidc_scope(
                            &identity.provider,
                            &identity.namespace_scope,
                            identity.namespace_scope_enforcement,
                        );
                        request.extensions_mut().insert(authority);
                        return next.run(request).await;
                    }
                    Err(_) => {
                        // OIDC also failed
                    }
                }
            }
        }

        // Both token and OIDC failed
        if let Some(ip) = client_ip {
            state.auth_failures.record_failure(ip);
        }
        return unauthorized_response("Invalid or expired token", realm);
    }

    // Parse Basic auth
    if !auth_header.starts_with("Basic ") {
        return unauthorized_response("Basic or Bearer authentication required", realm);
    }

    // htpasswd provider required for Basic auth
    let auth = match &state.auth {
        Some(auth) => auth,
        None => return unauthorized_response("Basic auth not configured", realm),
    };

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
        if let Some(ip) = client_ip {
            state.auth_failures.record_failure(ip);
        }
        return unauthorized_response("Invalid username or password", realm);
    }

    // Auth successful — clear failure counter
    if let Some(ip) = client_ip {
        state.auth_failures.record_success(&ip);
    }
    // Basic-auth identities are not namespace-scoped (#583 is OIDC-only).
    request
        .extensions_mut()
        .insert(NamespaceAuthority::Unrestricted);
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
            tracker.record_failure(ip);
        }
        assert!(tracker.check_blocked(&ip).is_none());
    }

    #[test]
    fn test_auth_failure_tracker_blocks_at_threshold() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip);
        }
        assert!(tracker.check_blocked(&ip).is_some());
    }

    #[test]
    fn test_auth_failure_tracker_success_clears() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..10 {
            tracker.record_failure(ip);
        }
        assert!(tracker.check_blocked(&ip).is_some());
        tracker.record_success(&ip);
        assert!(tracker.check_blocked(&ip).is_none());
    }

    #[test]
    fn test_auth_failure_tracker_independent_ips() {
        let tracker = AuthFailureTracker::new(3, 900);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            tracker.record_failure(ip1);
        }
        assert!(tracker.check_blocked(&ip1).is_some());
        assert!(tracker.check_blocked(&ip2).is_none());
    }

    #[test]
    fn test_auth_failure_tracker_cleanup() {
        let tracker = AuthFailureTracker::new(3, 1); // 1 sec max lockout
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            tracker.record_failure(ip);
        }
        // Cleanup should remove entries older than 2x max_lockout_secs
        std::thread::sleep(std::time::Duration::from_secs(3));
        tracker.cleanup();
        assert!(tracker.check_blocked(&ip).is_none());
    }

    #[test]
    fn test_auth_failure_tracker_exponential_backoff() {
        let tracker = AuthFailureTracker::new(5, 900);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // 5 failures = threshold, lockout = 2^0 = 1 sec
        for _ in 0..5 {
            tracker.record_failure(ip);
        }
        let retry1 = tracker.check_blocked(&ip).unwrap();
        assert!(
            retry1 <= 1,
            "first lockout should be ~1 sec, got {}",
            retry1
        );

        // 6 failures = 2^1 = 2 sec
        tracker.record_failure(ip);
        let retry2 = tracker.check_blocked(&ip).unwrap();
        assert!(
            retry2 <= 2,
            "second lockout should be ~2 sec, got {}",
            retry2
        );

        // 7 failures = 2^2 = 4 sec
        tracker.record_failure(ip);
        let retry3 = tracker.check_blocked(&ip).unwrap();
        assert!(
            retry3 <= 4,
            "third lockout should be ~4 sec, got {}",
            retry3
        );
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
mod oidc_integration_tests {
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
    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
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
    const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"u-uexVS-4MJo4zxH5eAPmoxtwxY-mB5kvYGq4BzAoaXSzG7fMm6rtYRz1DSkMp3VLxSeqvsSRRHbN3gbYweRiy7ZY_ZUnLxj7Fe9_Oq8qXh6t9CBK4Jtm3kCchfZXba1RwQT28-3gKOPosAif5uSLLqCwmGT0Kw1HaWsdHVBGv3j-m2nao2dq9K3nJx8NfsxsqM80hzbz7SvSD7CsAXGxo7eZ-fvZ1jd9tv5iEgLizcLb-5dy42vFO5tIsR9GS8BUoEy7cxHySErsfp4BkeJNjwVXqPsgzmbbmrcewIsWtRXqzsIqtsbKBjrNnYV2oMBRncG7PMfzLxI9OuzJtzqyw","e":"AQAB"}]}"#;

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
        let issuer = mock_issuer_url.to_string();
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
                    algorithms: vec!["RS256".to_string()],
                    max_token_lifetime_secs: 900,
                    namespace_scope: vec!["*".to_string()],
                    namespace_scope_enforcement: crate::config::ScopeEnforcement::Enforce,
                    enabled: true,
                    role_rules: vec![
                        OidcRoleRule {
                            pattern: "repo:myorg/*:ref:refs/heads/main".to_string(),
                            role: "write".to_string(),
                        },
                        OidcRoleRule {
                            pattern: "repo:myorg/*".to_string(),
                            role: "read".to_string(),
                        },
                    ],
                }],
            };
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
            tokens: ctx.state.tokens.clone(),
            metrics: Arc::new(crate::dashboard_metrics::DashboardMetrics::new()),
            activity: Arc::new(crate::activity_log::ActivityLog::new(50)),
            audit: ctx.state.audit.clone(),
            docker_auth: Arc::new(crate::registry::DockerAuth::new(reqwest::Client::new(), 5)),
            repo_index: Arc::new(crate::repo_index::RepoIndex::new()),
            http_client: reqwest::Client::new(),
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
            digest_store: ctx.state.digest_store.clone(),
            leak_finders: ctx.state.leak_finders.clone(),
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
            StatusCode::CREATED,
            "Write with main-branch OIDC token should succeed"
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
