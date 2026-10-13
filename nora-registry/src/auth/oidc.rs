// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! OIDC Workload Identity authentication provider.
//!
//! Validates JWT tokens from CI/CD systems (GitHub Actions, GitLab CI)
//! against configured OIDC issuers with JWKS key caching.
//!
//! Security properties:
//! - Algorithm whitelist per provider (only RS256/ES256 by default)
//! - Strict issuer binding (never follows jku/x5u from token)
//! - Per-provider namespace scoping
//! - Token lifetime ceiling enforcement
//! - Stale JWKS cache on fetch failure (availability over freshness)

use jsonwebtoken::{
    dangerous::insecure_decode, decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey,
    TokenData, Validation,
};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::{OidcConfig, OidcProvider, ScopeEnforcement};
use crate::tokens::Role;

/// Result of a successful OIDC authentication.
#[derive(Debug, Clone)]
pub struct OidcIdentity {
    /// Provider name that validated this token
    pub provider: String,
    /// Subject claim from JWT
    pub subject: String,
    /// Issuer claim
    pub issuer: String,
    /// Assigned role based on role_rules
    pub role: Role,
    /// Provider's `namespace_scope` patterns (segment-aware globs). `["*"]` = all
    /// namespaces. Enforced on writes via `auth::enforce_namespace_scope`.
    /// Always the provider's hard ceiling, whatever the matched rule says.
    pub namespace_scope: Vec<String>,
    /// The matched role rule's `namespace_scope`, if it set one. Enforced in
    /// addition to the provider scope — a write must satisfy both, so a rule
    /// can only narrow the provider ceiling, never widen past it.
    pub rule_namespace_scope: Option<Vec<String>>,
    /// Whether `namespace_scope` is enforced (403 on mismatch) or only audited
    /// for this provider.
    pub namespace_scope_enforcement: ScopeEnforcement,
}

/// Standard JWT claims we extract.
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<u64>,
    iat: Option<u64>,
    nbf: Option<u64>,
}

/// Audience can be a string or array of strings.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    #[cfg(test)]
    fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(s) => s == expected,
            Audience::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// Cached JWKS for a provider.
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

/// Minimal OIDC discovery document (only the fields we need).
#[derive(Deserialize)]
struct OidcDiscoveryDoc {
    #[serde(default)]
    jwks_uri: String,
}

/// OIDC validator — thread-safe, holds cached JWKS per issuer.
pub struct OidcValidator {
    config: OidcConfig,
    http_client: Client,
    /// issuer URL → cached JWKS
    jwks_cache: RwLock<HashMap<String, CachedJwks>>,
    /// issuer URL → JWKS URI from a successful discovery (never the fallback)
    discovered_jwks_uri: RwLock<HashMap<String, String>>,
    /// issuer URL → time of the last failed fetch
    jwks_failed_at: RwLock<HashMap<String, Instant>>,
    /// Single-flight for JWKS refreshes: on a cold start under load, one request
    /// fetches and the rest wait for its result instead of each calling the issuer.
    /// One lock for all providers; refreshes are rare and bounded by the request timeout.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Per-request timeout for OIDC HTTP calls (discovery + JWKS fetch).
const OIDC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// After a failed JWKS fetch with no stale keys to serve, requests fail fast for
/// this long instead of each one calling the issuer again.
const JWKS_FAILURE_BACKOFF: Duration = Duration::from_secs(5);

impl OidcValidator {
    /// Create a new validator from config.
    ///
    /// The client should be pre-configured with any required TLS settings
    /// (e.g. custom CA certificates). Per-request timeouts are applied internally.
    pub fn new(config: OidcConfig, http_client: Client) -> Self {
        Self {
            config,
            http_client,
            jwks_cache: RwLock::new(HashMap::new()),
            discovered_jwks_uri: RwLock::new(HashMap::new()),
            jwks_failed_at: RwLock::new(HashMap::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Check if OIDC is enabled and has providers configured.
    pub fn is_active(&self) -> bool {
        self.config.enabled && !self.config.providers.is_empty()
    }

    /// Validate a Bearer token as an OIDC JWT.
    /// Returns the identity on success, or an error string.
    pub async fn validate_token(&self, token: &str) -> Result<OidcIdentity, String> {
        if !self.is_active() {
            return Err("OIDC not enabled".to_string());
        }

        // Decode header WITHOUT validation to determine issuer and kid
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;

        // Security: reject alg=none and symmetric algorithms globally
        match header.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                return Err("Symmetric algorithms not allowed for OIDC".to_string());
            }
            _ => {}
        }

        // Peek at claims to find issuer (unverified — for routing only)
        let unverified: Claims = insecure_decode::<Claims>(token)
            .map_err(|e| format!("Cannot decode claims: {}", e))?
            .claims;

        let issuer = unverified.iss.as_deref().ok_or("Token missing iss claim")?;

        // Find matching provider
        let provider = self
            .config
            .providers
            .iter()
            .find(|p| p.enabled && p.issuer == issuer)
            .ok_or_else(|| format!("No matching OIDC provider for issuer: {}", issuer))?;

        // Verify algorithm is in provider's whitelist
        let alg_str = format!("{:?}", header.alg);
        if !provider.algorithms.iter().any(|a| a == &alg_str) {
            return Err(format!(
                "Algorithm {} not in provider whitelist: {:?}",
                alg_str, provider.algorithms
            ));
        }

        // Get JWKS (cached or fetch)
        let jwks = self.get_jwks(provider).await?;

        // Find the matching key by kid
        let kid = header.kid.as_deref().unwrap_or("");
        let jwk = jwks
            .keys
            .iter()
            .find(|k| {
                k.common.key_id.as_deref() == Some(kid) || (kid.is_empty() && jwks.keys.len() == 1)
            })
            .ok_or_else(|| {
                format!(
                    "No matching key (kid={}) in JWKS for provider {}",
                    kid, provider.name
                )
            })?;

        // Build decoding key from JWK
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|e| format!("Cannot build key from JWK: {}", e))?;

        // Full validation
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&provider.issuer]);
        validation.leeway = self.config.leeway_secs;

        if !provider.audience.is_empty() {
            validation.set_audience(&[&provider.audience]);
        } else {
            validation.validate_aud = false;
        }

        let token_data: TokenData<Claims> = decode(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        let claims = token_data.claims;

        // Enforce token lifetime ceiling
        if let (Some(iat), Some(exp)) = (claims.iat, claims.exp) {
            let lifetime = exp.saturating_sub(iat);
            if lifetime > provider.max_token_lifetime_secs {
                return Err(format!(
                    "Token lifetime {} exceeds max {} for provider {}",
                    lifetime, provider.max_token_lifetime_secs, provider.name
                ));
            }
        }

        // Map claims to role via role_rules
        let subject = claims.sub.unwrap_or_default();
        let (role, rule_scope) = self.match_role(provider, &subject).ok_or_else(|| {
            format!(
                "No role rule matches sub='{}' for provider {}",
                subject, provider.name
            )
        })?;

        Ok(OidcIdentity {
            provider: provider.name.clone(),
            subject,
            issuer: provider.issuer.clone(),
            role,
            namespace_scope: provider.namespace_scope.clone(),
            rule_namespace_scope: rule_scope,
            namespace_scope_enforcement: provider.namespace_scope_enforcement,
        })
    }

    /// Fetch or return cached JWKS for a provider.
    async fn get_jwks(&self, provider: &OidcProvider) -> Result<JwkSet, String> {
        let cache_ttl = Duration::from_secs(self.config.jwks_cache_secs);

        if let Some(jwks) = self.cached_jwks(&provider.issuer, cache_ttl) {
            return Ok(jwks);
        }

        // One refresh at a time; whoever waited re-reads what it fetched.
        let _refresh = self.refresh_lock.lock().await;
        if let Some(jwks) = self.cached_jwks(&provider.issuer, cache_ttl) {
            return Ok(jwks);
        }

        let failed_recently = self
            .jwks_failed_at
            .read()
            .get(&provider.issuer)
            .is_some_and(|t| t.elapsed() < JWKS_FAILURE_BACKOFF);
        let fetched = if failed_recently {
            Err("previous fetch failed, retrying shortly".to_string())
        } else {
            // Resolve JWKS URI: explicit config > OIDC discovery > legacy fallback
            let jwks_uri = self.resolve_jwks_uri(provider).await?;
            self.fetch_jwks(&jwks_uri).await
        };

        match fetched {
            Ok(jwks) => {
                self.jwks_cache.write().insert(
                    provider.issuer.clone(),
                    CachedJwks {
                        jwks: jwks.clone(),
                        fetched_at: Instant::now(),
                    },
                );
                self.jwks_failed_at.write().remove(&provider.issuer);
                Ok(jwks)
            }
            Err(e) => {
                if !failed_recently {
                    self.jwks_failed_at
                        .write()
                        .insert(provider.issuer.clone(), Instant::now());
                }
                // Stale fallback: return expired cache if available
                let cache = self.jwks_cache.read();
                if let Some(cached) = cache.get(&provider.issuer) {
                    if !failed_recently {
                        tracing::warn!(
                            provider = %provider.name,
                            error = %e,
                            stale_age_secs = cached.fetched_at.elapsed().as_secs(),
                            "JWKS fetch failed, serving stale keys"
                        );
                    }
                    return Ok(cached.jwks.clone());
                }
                Err(format!("JWKS fetch failed for {}: {}", provider.name, e))
            }
        }
    }

    /// Cached JWKS for an issuer if younger than `ttl`.
    fn cached_jwks(&self, issuer: &str, ttl: Duration) -> Option<JwkSet> {
        self.jwks_cache
            .read()
            .get(issuer)
            .filter(|c| c.fetched_at.elapsed() < ttl)
            .map(|c| c.jwks.clone())
    }

    /// Resolve the JWKS URI for a provider using (in order):
    /// 1. Explicit `jwks_uri` from config
    /// 2. OIDC discovery via `.well-known/openid-configuration`
    /// 3. Fallback to `{issuer}/.well-known/jwks.json`
    async fn resolve_jwks_uri(&self, provider: &OidcProvider) -> Result<String, String> {
        // 1. Explicit override
        if let Some(ref uri) = provider.jwks_uri {
            return Ok(uri.clone());
        }
        if let Some(uri) = self.discovered_jwks_uri.read().get(&provider.issuer) {
            return Ok(uri.clone());
        }

        // 2. OIDC discovery
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            provider.issuer.trim_end_matches('/')
        );

        if let Ok(resp) = self
            .http_client
            .get(&discovery_url)
            .timeout(OIDC_REQUEST_TIMEOUT)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(config) = resp.json::<OidcDiscoveryDoc>().await {
                    if !config.jwks_uri.is_empty() {
                        tracing::debug!(
                            provider = %provider.name,
                            jwks_uri = %config.jwks_uri,
                            "Discovered JWKS URI via openid-configuration"
                        );
                        self.discovered_jwks_uri
                            .write()
                            .insert(provider.issuer.clone(), config.jwks_uri.clone());
                        return Ok(config.jwks_uri);
                    }
                }
            }
        }

        // 3. Legacy fallback
        Ok(format!(
            "{}/.well-known/jwks.json",
            provider.issuer.trim_end_matches('/')
        ))
    }

    /// HTTP fetch of JWKS from provider.
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet, String> {
        let resp = self
            .http_client
            .get(url)
            .timeout(OIDC_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", resp.status()));
        }

        resp.json::<JwkSet>()
            .await
            .map_err(|e| format!("JWKS parse error: {}", e))
    }

    /// Match subject against provider's role_rules. First match wins.
    /// Returns the role plus the rule's namespace-scope override, if any.
    fn match_role(
        &self,
        provider: &OidcProvider,
        subject: &str,
    ) -> Option<(Role, Option<Vec<String>>)> {
        for rule in &provider.role_rules {
            if glob_match(&rule.pattern, subject) {
                let role = match rule.role.as_str() {
                    "admin" => Role::Admin,
                    "write" => Role::Write,
                    "read" => Role::Read,
                    _ => return None,
                };
                return Some((role, rule.namespace_scope.clone()));
            }
        }
        None
    }
}

/// Simple glob matching: supports `*` (any chars within segment) and `**` is not needed
/// since sub claims use `:` as separator, not `/`.
/// Patterns: "repo:org/*" matches "repo:org/myrepo:ref:refs/heads/main"
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcard — exact match
        return pattern == value;
    }

    // First part must be prefix, last part must be suffix
    let mut remaining = value;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Must start with this
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if i == parts.len() - 1 {
            // Must end with this
            if !remaining.ends_with(part) {
                return false;
            }
            return true;
        } else {
            // Must contain this
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }

    true
}

/// Classify a [`OidcValidator::validate_token`] rejection string into a bounded
/// reason label for metrics/logs (#994). The caller still logs the full string;
/// this only buckets it so `nora_auth_oidc_rejected_total{reason}` stays
/// low-cardinality (no issuer/subject/provider in the label).
pub fn classify_rejection(reason: &str) -> &'static str {
    if reason.starts_with("OIDC not enabled") {
        "disabled"
    } else if reason.starts_with("No matching OIDC provider") {
        "no_provider"
    } else if reason.starts_with("Token lifetime") {
        "lifetime_exceeded"
    } else if reason.starts_with("No role rule matches") {
        "no_role_rule"
    } else if reason.starts_with("Symmetric algorithms") || reason.starts_with("Algorithm ") {
        "algorithm"
    } else if reason.contains("JWK") {
        // JWKS fetch/endpoint/key errors ("...JWK...", "JWKS ..."); checked
        // before jwt_invalid because none of those strings contain "JWK".
        "jwks"
    } else if reason.starts_with("Invalid JWT header")
        || reason.starts_with("Cannot decode claims")
        || reason.starts_with("JWT validation failed")
    {
        "jwt_invalid"
    } else {
        "other"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{OidcProvider, OidcRoleRule};

    #[test]
    fn classify_rejection_buckets_each_real_reason() {
        // #994 — the exact strings validate_token returns must each map to a
        // distinct, bounded reason, not collapse to "other".
        assert_eq!(classify_rejection("OIDC not enabled"), "disabled");
        assert_eq!(
            classify_rejection("No matching OIDC provider for issuer: https://gitlab.example/"),
            "no_provider",
        );
        assert_eq!(
            classify_rejection("Token lifetime 3600 exceeds max 900 for provider gitlab"),
            "lifetime_exceeded",
        );
        assert_eq!(
            classify_rejection(
                "No role rule matches sub='project_path:acme/app' for provider gitlab"
            ),
            "no_role_rule",
        );
        assert_eq!(
            classify_rejection("Symmetric algorithms not allowed for OIDC"),
            "algorithm",
        );
        assert_eq!(
            classify_rejection("Algorithm HS256 not in provider whitelist: [\"RS256\"]"),
            "algorithm",
        );
        assert_eq!(
            classify_rejection("JWT validation failed: InvalidAudience"),
            "jwt_invalid",
        );
        assert_eq!(classify_rejection("Cannot build key from JWK: bad"), "jwks");
        assert_eq!(
            classify_rejection("JWKS fetch failed for gitlab: timeout"),
            "jwks",
        );
        assert_eq!(classify_rejection("an unmapped failure"), "other");
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("repo:org/myrepo", "repo:org/myrepo"));
        assert!(!glob_match("repo:org/myrepo", "repo:org/other"));
    }

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match("repo:org/*", "repo:org/myrepo"));
        assert!(glob_match(
            "repo:org/*",
            "repo:org/myrepo:ref:refs/heads/main"
        ));
        assert!(!glob_match("repo:org/*", "repo:other/myrepo"));
    }

    #[test]
    fn test_glob_match_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_match_middle() {
        assert!(glob_match(
            "repo:*:ref:refs/heads/main",
            "repo:org/myrepo:ref:refs/heads/main"
        ));
        assert!(!glob_match(
            "repo:*:ref:refs/heads/main",
            "repo:org/myrepo:ref:refs/heads/dev"
        ));
    }

    #[test]
    fn test_match_role_first_wins() {
        let config = OidcConfig::default();
        let validator = OidcValidator::new(config, Client::new());

        let provider = OidcProvider {
            name: "test".to_string(),
            issuer: "https://test".to_string(),
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
                    namespace_scope: None,
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
        };

        // main branch → write (first rule), inherits provider scope
        let m = validator.match_role(&provider, "repo:myorg/app:ref:refs/heads/main");
        assert!(matches!(m, Some((Role::Write, None))));

        // pull_request → write narrowed to the rule's scope
        let m = validator.match_role(&provider, "repo:myorg/app:pull_request");
        let (role, scope) = m.unwrap();
        assert_eq!(role, Role::Write);
        assert_eq!(scope.as_deref(), Some(&["ci-transport/**".to_string()][..]));

        // other branch → read (last rule)
        let m = validator.match_role(&provider, "repo:myorg/app:ref:refs/heads/dev");
        assert!(matches!(m, Some((Role::Read, None))));

        // different org → no match
        let m = validator.match_role(&provider, "repo:other/app:ref:refs/heads/main");
        assert!(m.is_none());
    }

    #[test]
    fn test_audience_contains() {
        let single = Audience::Single("nora".to_string());
        assert!(single.contains("nora"));
        assert!(!single.contains("other"));

        let multi = Audience::Multiple(vec!["nora".to_string(), "api".to_string()]);
        assert!(multi.contains("nora"));
        assert!(multi.contains("api"));
        assert!(!multi.contains("other"));
    }

    /// A provider on a mock issuer plus a valid token for it.
    async fn mock_issuer(
        jwks_uri: Option<&str>,
        jwks_cache_secs: u64,
    ) -> (wiremock::MockServer, OidcConfig, String) {
        use crate::auth::oidc_integration_tests::TEST_RSA_PRIVATE_KEY;
        use jsonwebtoken::{encode, EncodingKey, Header};

        let server = wiremock::MockServer::start().await;
        let issuer = server.uri();
        let config = OidcConfig {
            enabled: true,
            leeway_secs: 60,
            jwks_cache_secs,
            providers: vec![OidcProvider {
                name: "ci".to_string(),
                issuer: issuer.clone(),
                jwks_uri: jwks_uri.map(|p| format!("{issuer}{p}")),
                audience: "nora".to_string(),
                algorithms: vec!["RS256".to_string()],
                max_token_lifetime_secs: 900,
                namespace_scope: vec!["*".to_string()],
                namespace_scope_enforcement: crate::config::ScopeEnforcement::Enforce,
                enabled: true,
                role_rules: vec![OidcRoleRule {
                    pattern: "repo:myorg/*".to_string(),
                    role: "read".to_string(),
                    namespace_scope: None,
                }],
            }],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let claims = serde_json::json!({
            "iss": issuer, "sub": "repo:myorg/app", "aud": "nora", "iat": now, "exp": now + 600,
        });
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        (server, config, encode(&header, &claims, &key).unwrap())
    }

    /// Cold start under load: concurrent requests share one JWKS fetch.
    #[tokio::test]
    async fn test_cold_start_fetches_jwks_once() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (server, config, token) = mock_issuer(Some("/jwks"), 300).await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(TEST_JWKS_JSON, "application/json")
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&server)
            .await;
        let v = std::sync::Arc::new(OidcValidator::new(config, Client::new()));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let (v, t) = (v.clone(), token.clone());
            tasks.spawn(async move { v.validate_token(&t).await });
        }
        while let Some(r) = tasks.join_next().await {
            assert!(r.unwrap().is_ok());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// A failed fetch with nothing cached fails the requests behind it fast
    /// instead of each one calling the issuer again.
    #[tokio::test]
    async fn test_failed_fetch_backs_off() {
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (server, config, token) = mock_issuer(Some("/jwks"), 300).await;
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let v = std::sync::Arc::new(OidcValidator::new(config, Client::new()));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let (v, t) = (v.clone(), token.clone());
            tasks.spawn(async move { v.validate_token(&t).await });
        }
        while let Some(r) = tasks.join_next().await {
            let err = r.unwrap().unwrap_err();
            assert_eq!(classify_rejection(&err), "jwks", "{err}");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// The JWKS URI from discovery is kept: a later refresh does not depend on
    /// discovery succeeding again (a failed one falls back to jwks.json).
    #[tokio::test]
    async fn test_discovered_jwks_uri_is_cached() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        // jwks_cache_secs 0: every validation refreshes the JWKS.
        let (server, config, token) = mock_issuer(None, 0).await;
        let discovery = serde_json::json!({ "jwks_uri": format!("{}/keys", server.uri()) });
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/keys"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .expect(3)
            .mount(&server)
            .await;
        let v = OidcValidator::new(config, Client::new());

        for _ in 0..3 {
            assert!(v.validate_token(&token).await.is_ok());
        }
        server.verify().await;
    }

    /// The failure backoff reliably EXPIRES and does not SLIDE: a second failing
    /// request inside the window must not refresh the failure marker (otherwise the
    /// window would never end under continuous load), and once the window passes a
    /// request fetches again. Guards `oidc-jwks-failure-backoff`.
    #[tokio::test]
    async fn test_backoff_window_expires_and_does_not_slide() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (server, config, token) = mock_issuer(Some("/jwks"), 300).await;
        // First JWKS fetch fails; any later fetch succeeds.
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&server)
            .await;
        let v = OidcValidator::new(config, Client::new());
        let issuer = v.config.providers[0].issuer.clone();

        // 1) Cold fetch fails with nothing cached: the failure is recorded.
        assert!(v.validate_token(&token).await.is_err());
        let marked = *v
            .jwks_failed_at
            .read()
            .get(&issuer)
            .expect("failure recorded");

        // 2) Inside the window: a second failing request must NOT move the marker.
        assert!(v.validate_token(&token).await.is_err());
        assert_eq!(
            *v.jwks_failed_at.read().get(&issuer).unwrap(),
            marked,
            "backoff window slid — failure timestamp refreshed inside the window"
        );

        // 3) Past the window: the next request fetches again and now succeeds.
        v.jwks_failed_at.write().insert(
            issuer.clone(),
            marked - (JWKS_FAILURE_BACKOFF + Duration::from_secs(1)),
        );
        assert!(
            v.validate_token(&token).await.is_ok(),
            "backoff did not expire after the window"
        );
    }

    /// A failed discovery must NOT pin the legacy fallback URI as a discovered
    /// one (some issuers 404 the fallback, e.g. GitHub). Guards
    /// `oidc-discovered-uri-sticky-not-fallback`.
    #[tokio::test]
    async fn test_fallback_uri_not_pinned() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (server, config, token) = mock_issuer(None, 300).await;
        let issuer = config.providers[0].issuer.clone();
        // Discovery returns a doc with no jwks_uri -> code must fall back to the legacy URI.
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        // The legacy fallback answers, so the validation succeeds via it.
        Mock::given(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&server)
            .await;
        let v = OidcValidator::new(config, Client::new());

        assert!(v.validate_token(&token).await.is_ok());
        // The fallback URI must not have been cached as a discovered jwks_uri.
        assert!(
            v.discovered_jwks_uri.read().get(&issuer).is_none(),
            "legacy fallback URI was pinned as a discovered jwks_uri"
        );
    }

    /// Build a two-provider config from two single-provider ones (distinct issuers).
    fn two_issuer_config(a: OidcConfig, b: OidcConfig) -> OidcConfig {
        let mut c = a;
        c.providers[0].name = "a".to_string();
        let mut pb = b.providers[0].clone();
        pb.name = "b".to_string();
        c.providers.push(pb);
        c
    }

    /// Within the backoff window, expired-but-present keys are still served and the
    /// issuer is not hammered. Guards `oidc-jwks-failure-backoff` (stale-still-served).
    #[tokio::test]
    async fn test_stale_keys_served_during_backoff() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        // TTL 0: every validation refreshes, so a failing refresh must fall back to stale.
        let (server, config, token) = mock_issuer(Some("/jwks"), 0).await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let v = OidcValidator::new(config, Client::new());

        assert!(v.validate_token(&token).await.is_ok(), "cold fetch");
        assert!(
            v.validate_token(&token).await.is_ok(),
            "first failure must serve stale keys"
        );
        assert!(
            v.validate_token(&token).await.is_ok(),
            "in-backoff must still serve stale keys"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "issuer was hammered while stale keys were available"
        );
    }

    /// A transient non-2xx discovery must NOT pin the legacy fallback: once discovery
    /// recovers, the real jwks_uri is used again. Guards
    /// `oidc-discovered-uri-sticky-not-fallback` (the GitHub-404 scenario).
    #[tokio::test]
    async fn test_transient_discovery_failure_does_not_pin_fallback() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (server, config, token) = mock_issuer(None, 0).await;
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let discovery = serde_json::json!({ "jwks_uri": format!("{}/keys", server.uri()) });
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&server)
            .await;
        // Fallback answers once, then 404s (issuer whose jwks.json is not the real URI).
        Mock::given(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(path("/keys"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&server)
            .await;
        let v = OidcValidator::new(config, Client::new());

        assert!(
            v.validate_token(&token).await.is_ok(),
            "served via fallback"
        );
        // Stale keys mask the outage for the caller; the observable defect of pinning is
        // that the refresh never returns to discovery and so never reaches the real /keys.
        assert!(v.validate_token(&token).await.is_ok());
        let keys_hits = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/keys")
            .count();
        assert_eq!(
            keys_hits, 1,
            "fallback was pinned after a transient discovery failure"
        );
    }

    /// The discovered jwks_uri is kept per issuer: issuer B's keys come from B, never
    /// from A's discovered URI. Guards `oidc-discovered-uri-sticky-not-fallback`.
    #[tokio::test]
    async fn test_discovered_jwks_uri_is_per_issuer() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (sa, ca, ta) = mock_issuer(None, 300).await;
        let (sb, cb, tb) = mock_issuer(None, 300).await;
        for s in [&sa, &sb] {
            let d = serde_json::json!({ "jwks_uri": format!("{}/keys", s.uri()) });
            Mock::given(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(d))
                .mount(s)
                .await;
            Mock::given(path("/keys"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
                )
                .expect(1)
                .mount(s)
                .await;
        }
        let v = OidcValidator::new(two_issuer_config(ca, cb), Client::new());

        assert!(v.validate_token(&ta).await.is_ok());
        assert!(v.validate_token(&tb).await.is_ok());
        sa.verify().await;
        sb.verify().await;
    }

    /// A backoff recorded for issuer A must not fail-fast a healthy issuer B. Guards
    /// `oidc-jwks-failure-backoff` (per-issuer).
    #[tokio::test]
    async fn test_backoff_is_per_issuer() {
        use crate::auth::oidc_integration_tests::TEST_JWKS_JSON;
        use wiremock::{matchers::path, Mock, ResponseTemplate};

        let (sa, ca, ta) = mock_issuer(Some("/jwks"), 300).await;
        let (sb, cb, tb) = mock_issuer(Some("/jwks"), 300).await;
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&sa)
            .await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&sb)
            .await;
        let v = OidcValidator::new(two_issuer_config(ca, cb), Client::new());

        assert!(v.validate_token(&ta).await.is_err());
        assert!(
            v.validate_token(&tb).await.is_ok(),
            "healthy issuer B was blocked by issuer A's backoff"
        );
    }
}
