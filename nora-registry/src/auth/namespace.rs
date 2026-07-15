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
    /// An OIDC identity restricted to the given scopes.
    Scoped {
        /// Conjunction of scope pattern-sets (segment-aware globs, see
        /// [`crate::validation::namespace_match`]): a namespace is in scope
        /// only if it matches at least one pattern in **every** set. One set
        /// is the provider's `namespace_scope`; a matched rule's
        /// `namespace_scope` adds a second — so a rule can only narrow the
        /// provider scope, never widen past it.
        scopes: Arc<[Arc<[String]>]>,
        /// Provider name, included in deny logs and the metric (never the token).
        provider: Arc<str>,
        /// Whether a mismatch denies (403) or is only audited.
        mode: ScopeEnforcement,
    },
}

impl NamespaceAuthority {
    /// Build an authority from a single `namespace_scope`.
    ///
    /// A scope containing a bare `*` collapses to [`NamespaceAuthority::Unrestricted`]
    /// so the default `namespace_scope = ["*"]` is a true no-op. An empty scope
    /// (`[]`) stays `Scoped` with no patterns and therefore denies every write
    /// (fail-closed) — a deliberate operator lockout.
    #[cfg(test)]
    pub fn from_oidc_scope(provider: &str, scope: &[String], mode: ScopeEnforcement) -> Self {
        Self::from_oidc_scopes(provider, [scope], mode)
    }

    /// Build an authority from a conjunction of scopes, all of which a write
    /// must satisfy (provider scope + optional per-rule scope).
    ///
    /// Each set collapses independently: a set containing a bare `*` is
    /// unrestricted and drops out of the conjunction; if every set drops out
    /// the authority is [`NamespaceAuthority::Unrestricted`]. An empty set
    /// (`[]`) is kept and denies every write (fail-closed), exactly as in
    /// [`NamespaceAuthority::from_oidc_scope`].
    pub fn from_oidc_scopes<'a>(
        provider: &str,
        scopes: impl IntoIterator<Item = &'a [String]>,
        mode: ScopeEnforcement,
    ) -> Self {
        let scopes: Vec<Arc<[String]>> = scopes
            .into_iter()
            .filter(|scope| !scope.iter().any(|p| p == "*"))
            .map(Arc::from)
            .collect();
        if scopes.is_empty() {
            return NamespaceAuthority::Unrestricted;
        }
        NamespaceAuthority::Scoped {
            scopes: Arc::from(scopes),
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
    let (scopes, provider, mode) = match authority {
        NamespaceAuthority::Unrestricted => return Ok(()),
        NamespaceAuthority::Scoped {
            scopes,
            provider,
            mode,
        } => (scopes, provider, *mode),
    };
    // Use `provider` as `&str` for the metric label slices below. The mixed
    // `&[&Arc<str>, &'static str]` array relied on element LUB coercion, which the
    // Kani verifier's pinned rustc rejects (E0308) where stable accepts it — this
    // explicit deref makes both elements `&str` and compiles under both toolchains.
    let provider: &str = provider;

    if scopes
        .iter()
        .all(|scope| scope.iter().any(|p| namespace_match(p, namespace)))
    {
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
                scopes = ?scopes,
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
                scopes = ?scopes,
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
    fn rule_scope_narrows_provider_scope() {
        // Provider ["*"] + rule scope: the rule narrows (the motivating case).
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["*"])[..], &scope(&["ci-transport/**"])[..]],
            ScopeEnforcement::Enforce,
        );
        assert!(enforce_namespace_scope(&auth, "ci-transport/run1").is_ok());
        assert_eq!(
            enforce_namespace_scope(&auth, "other/repo"),
            Err(NamespaceDenied)
        );

        // Both scopes must allow: the conjunction is an intersection.
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["myorg/**"])[..], &scope(&["myorg/ci/**"])[..]],
            ScopeEnforcement::Enforce,
        );
        assert!(enforce_namespace_scope(&auth, "myorg/ci/x").is_ok());
        assert_eq!(
            enforce_namespace_scope(&auth, "myorg/other"),
            Err(NamespaceDenied)
        );
    }

    #[test]
    fn rule_scope_cannot_widen_past_provider_ceiling() {
        // A rule scope of ["*"] drops out of the conjunction; the provider
        // scope keeps enforcing. It must NOT promote the identity to
        // Unrestricted past a narrow provider ceiling.
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["myorg/**"])[..], &scope(&["*"])[..]],
            ScopeEnforcement::Enforce,
        );
        assert!(enforce_namespace_scope(&auth, "myorg/repo").is_ok());
        assert_eq!(
            enforce_namespace_scope(&auth, "other/repo"),
            Err(NamespaceDenied)
        );
        // A disjoint rule scope yields an empty intersection: deny-all,
        // not either-side-allows.
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["myorg/**"])[..], &scope(&["elsewhere/**"])[..]],
            ScopeEnforcement::Enforce,
        );
        assert_eq!(
            enforce_namespace_scope(&auth, "myorg/repo"),
            Err(NamespaceDenied)
        );
        assert_eq!(
            enforce_namespace_scope(&auth, "elsewhere/repo"),
            Err(NamespaceDenied)
        );
    }

    #[test]
    fn all_star_scopes_collapse_to_unrestricted() {
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["*"])[..], &scope(&["*"])[..]],
            ScopeEnforcement::Enforce,
        );
        assert!(matches!(auth, NamespaceAuthority::Unrestricted));
    }

    #[test]
    fn empty_rule_scope_in_conjunction_is_fail_closed() {
        // `namespace_scope = []` on a rule locks the identity out even when
        // the provider scope is wide open.
        let auth = NamespaceAuthority::from_oidc_scopes(
            "ci",
            [&scope(&["*"])[..], &scope(&[])[..]],
            ScopeEnforcement::Enforce,
        );
        assert_eq!(
            enforce_namespace_scope(&auth, "anything"),
            Err(NamespaceDenied)
        );
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
