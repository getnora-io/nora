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

use crate::config::{OidcConfig, OidcProvider};
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

/// OIDC validator — thread-safe, holds cached JWKS per issuer.
pub struct OidcValidator {
    config: OidcConfig,
    http_client: Client,
    /// issuer URL → cached JWKS
    jwks_cache: RwLock<HashMap<String, CachedJwks>>,
}

impl OidcValidator {
    /// Create a new validator from config.
    pub fn new(config: OidcConfig) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("nora-registry/0.8")
            .build()
            .unwrap_or_default();

        Self {
            config,
            http_client,
            jwks_cache: RwLock::new(HashMap::new()),
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
        let role = self.match_role(provider, &subject).ok_or_else(|| {
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
        })
    }

    /// Fetch or return cached JWKS for a provider.
    async fn get_jwks(&self, provider: &OidcProvider) -> Result<JwkSet, String> {
        let cache_ttl = Duration::from_secs(self.config.jwks_cache_secs);

        // Try cache first
        {
            let cache = self.jwks_cache.read();
            if let Some(cached) = cache.get(&provider.issuer) {
                if cached.fetched_at.elapsed() < cache_ttl {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        // Fetch fresh JWKS
        let jwks_uri = format!(
            "{}/.well-known/jwks.json",
            provider.issuer.trim_end_matches('/')
        );

        match self.fetch_jwks(&jwks_uri).await {
            Ok(jwks) => {
                let mut cache = self.jwks_cache.write();
                cache.insert(
                    provider.issuer.clone(),
                    CachedJwks {
                        jwks: jwks.clone(),
                        fetched_at: Instant::now(),
                    },
                );
                Ok(jwks)
            }
            Err(e) => {
                // Stale fallback: return expired cache if available
                let cache = self.jwks_cache.read();
                if let Some(cached) = cache.get(&provider.issuer) {
                    tracing::warn!(
                        provider = %provider.name,
                        error = %e,
                        stale_age_secs = cached.fetched_at.elapsed().as_secs(),
                        "JWKS fetch failed, serving stale keys"
                    );
                    return Ok(cached.jwks.clone());
                }
                Err(format!("JWKS fetch failed for {}: {}", provider.name, e))
            }
        }
    }

    /// HTTP fetch of JWKS from provider.
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet, String> {
        let resp = self
            .http_client
            .get(url)
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
    fn match_role(&self, provider: &OidcProvider, subject: &str) -> Option<Role> {
        for rule in &provider.role_rules {
            if glob_match(&rule.pattern, subject) {
                return match rule.role.as_str() {
                    "admin" => Some(Role::Admin),
                    "write" => Some(Role::Write),
                    "read" => Some(Role::Read),
                    _ => None,
                };
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{OidcProvider, OidcRoleRule};

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
        let validator = OidcValidator::new(config);

        let provider = OidcProvider {
            name: "test".to_string(),
            issuer: "https://test".to_string(),
            audience: "nora".to_string(),
            algorithms: vec!["RS256".to_string()],
            max_token_lifetime_secs: 900,
            namespace_scope: vec!["*".to_string()],
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
        };

        // main branch → write (first rule)
        let role = validator.match_role(&provider, "repo:myorg/app:ref:refs/heads/main");
        assert!(matches!(role, Some(Role::Write)));

        // other branch → read (second rule)
        let role = validator.match_role(&provider, "repo:myorg/app:ref:refs/heads/dev");
        assert!(matches!(role, Some(Role::Read)));

        // different org → no match
        let role = validator.match_role(&provider, "repo:other/app:ref:refs/heads/main");
        assert!(role.is_none());
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
}
