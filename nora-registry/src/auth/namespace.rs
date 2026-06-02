// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! OIDC `namespace_scope` authorization (#583).
//!
//! The auth middleware stamps a [`NamespaceAuthority`] into the request
//! extensions on every path; write handlers call [`enforce_namespace_scope`]
//! with the artifact coordinate they parsed (never the storage key). The
//! segment-aware matcher itself lives in `crate::validation` so it can be fuzzed
//! without pulling in the binary-only metrics/config wired up here.

use std::sync::Arc;

use crate::config::ScopeEnforcement;
use crate::metrics::NAMESPACE_SCOPE_DECISIONS;
use crate::validation::namespace_match;

/// Per-request namespace authorization, derived from the authenticated identity.
///
/// Present on every request (the middleware inserts it on all paths), so write
/// handlers can extract it without a fallback.
#[derive(Clone, Debug)]
pub enum NamespaceAuthority {
    /// No namespace restriction: Basic auth, opaque (`nra_`) tokens, anonymous
    /// reads, auth disabled, or an OIDC provider scoped to `["*"]`.
    Unrestricted,
    /// An OIDC identity restricted to the given scope patterns.
    Scoped {
        /// Glob patterns from the provider's `namespace_scope` (segment-aware,
        /// see [`crate::validation::namespace_match`]).
        patterns: Arc<[String]>,
        /// Provider name, included in deny logs and the metric (never the token).
        provider: Arc<str>,
        /// Whether a mismatch denies (403) or is only audited.
        mode: ScopeEnforcement,
    },
}

impl NamespaceAuthority {
    /// Build an authority from an OIDC provider's `namespace_scope`.
    ///
    /// A scope containing a bare `*` collapses to [`NamespaceAuthority::Unrestricted`]
    /// so the default `namespace_scope = ["*"]` is a true no-op. An empty scope
    /// (`[]`) stays `Scoped` with no patterns and therefore denies every write
    /// (fail-closed) — a deliberate operator lockout.
    pub fn from_oidc_scope(provider: &str, scope: &[String], mode: ScopeEnforcement) -> Self {
        if scope.iter().any(|p| p == "*") {
            return NamespaceAuthority::Unrestricted;
        }
        NamespaceAuthority::Scoped {
            patterns: Arc::from(scope.to_vec()),
            provider: Arc::from(provider),
            mode,
        }
    }
}

/// A write was denied because its artifact coordinate fell outside the
/// authenticated OIDC identity's `namespace_scope`. Callers map this to HTTP 403
/// and must not touch storage (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDenied;

/// Enforce an OIDC `namespace_scope` against the artifact `namespace` coordinate
/// a write handler is about to act on.
///
/// `namespace` MUST be the canonical artifact coordinate the handler derived
/// (docker image name, npm package, raw path, …) — never the raw URL path and
/// never the storage key, which carry transport prefixes/suffixes that would make
/// scoping format-dependent and bypassable.
///
/// Returns `Ok(())` for an [`NamespaceAuthority::Unrestricted`] authority, when
/// `namespace` matches a scope pattern, or when the provider is in
/// [`ScopeEnforcement::Audit`] mode (the mismatch is logged and counted as
/// `would_deny`, but allowed). Returns `Err(NamespaceDenied)` only for an
/// enforced mismatch. Every decision increments `nora_auth_namespace_scope_total`.
pub fn enforce_namespace_scope(
    authority: &NamespaceAuthority,
    namespace: &str,
) -> Result<(), NamespaceDenied> {
    let (patterns, provider, mode) = match authority {
        NamespaceAuthority::Unrestricted => return Ok(()),
        NamespaceAuthority::Scoped {
            patterns,
            provider,
            mode,
        } => (patterns, provider, *mode),
    };

    if patterns.iter().any(|p| namespace_match(p, namespace)) {
        NAMESPACE_SCOPE_DECISIONS
            .with_label_values(&[provider, "allow"])
            .inc();
        return Ok(());
    }

    match mode {
        ScopeEnforcement::Enforce => {
            NAMESPACE_SCOPE_DECISIONS
                .with_label_values(&[provider, "deny"])
                .inc();
            tracing::warn!(
                provider = %provider,
                namespace = %namespace,
                patterns = ?patterns,
                "OIDC namespace_scope denied write outside provider scope"
            );
            Err(NamespaceDenied)
        }
        ScopeEnforcement::Audit => {
            NAMESPACE_SCOPE_DECISIONS
                .with_label_values(&[provider, "would_deny"])
                .inc();
            tracing::warn!(
                provider = %provider,
                namespace = %namespace,
                patterns = ?patterns,
                "OIDC namespace_scope (audit) would have denied write outside provider scope"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scope(patterns: &[&str]) -> Vec<String> {
        patterns.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_star_scope_is_unrestricted() {
        // The default `namespace_scope = ["*"]` collapses to Unrestricted (no-op).
        let auth =
            NamespaceAuthority::from_oidc_scope("ci", &scope(&["*"]), ScopeEnforcement::Enforce);
        assert!(matches!(auth, NamespaceAuthority::Unrestricted));
        assert!(enforce_namespace_scope(&auth, "anyorg/whatever").is_ok());
        // A `*` anywhere in the list is enough to be unrestricted.
        let auth = NamespaceAuthority::from_oidc_scope(
            "ci",
            &scope(&["myorg/**", "*"]),
            ScopeEnforcement::Enforce,
        );
        assert!(matches!(auth, NamespaceAuthority::Unrestricted));
    }

    #[test]
    fn unrestricted_authority_always_allows() {
        assert!(enforce_namespace_scope(&NamespaceAuthority::Unrestricted, "").is_ok());
        assert!(enforce_namespace_scope(&NamespaceAuthority::Unrestricted, "a/b/c").is_ok());
    }

    #[test]
    fn scoped_enforce_allows_inside_denies_outside() {
        let auth = NamespaceAuthority::from_oidc_scope(
            "github",
            &scope(&["myorg/**"]),
            ScopeEnforcement::Enforce,
        );
        assert!(enforce_namespace_scope(&auth, "myorg/repo").is_ok());
        assert!(enforce_namespace_scope(&auth, "myorg/team/repo").is_ok());
        assert_eq!(
            enforce_namespace_scope(&auth, "other/repo"),
            Err(NamespaceDenied)
        );
        // The #583 lookalike must be denied, not allowed.
        assert_eq!(
            enforce_namespace_scope(&auth, "myorg-evil/repo"),
            Err(NamespaceDenied)
        );
    }

    #[test]
    fn audit_mode_allows_but_never_errors() {
        let auth = NamespaceAuthority::from_oidc_scope(
            "github",
            &scope(&["myorg/**"]),
            ScopeEnforcement::Audit,
        );
        // Inside scope: allowed. Outside scope: still allowed (only counted/logged).
        assert!(enforce_namespace_scope(&auth, "myorg/repo").is_ok());
        assert!(enforce_namespace_scope(&auth, "other/repo").is_ok());
    }

    #[test]
    fn empty_scope_is_fail_closed() {
        // `namespace_scope = []` is a deliberate lockout: deny everything.
        let auth =
            NamespaceAuthority::from_oidc_scope("ci", &scope(&[]), ScopeEnforcement::Enforce);
        assert_eq!(
            enforce_namespace_scope(&auth, "anything"),
            Err(NamespaceDenied)
        );
    }

    #[test]
    fn empty_namespace_under_scope_is_denied() {
        // A handler that fails to derive a coordinate must not fall open.
        let auth = NamespaceAuthority::from_oidc_scope(
            "ci",
            &scope(&["myorg/**"]),
            ScopeEnforcement::Enforce,
        );
        assert_eq!(enforce_namespace_scope(&auth, ""), Err(NamespaceDenied));
    }
}
