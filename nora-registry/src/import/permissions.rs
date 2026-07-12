//! Best-effort permission mapping → NORA's file-first auth (#599, review R3).
//!
//! NORA's auth model **cannot** represent a per-repo grant on a mintable `nra_`
//! token (`Role` is a single global `{Read,Write,Admin}`; per-namespace scope
//! exists only for OIDC identities, and an empty scope `[]` is a deny-all
//! lockout). So this module never mints live credentials. It emits an **inert
//! `import-permissions-report.json` proposal** for a human to ratify (file-first,
//! ADR-5), applying three hard safety rules:
//!
//! 1. Never propose a role above `Read` unless `--grant-write` is set — over-Read
//!    grants are listed in the **widen set** instead (no silent escalation).
//! 2. Never emit an OIDC `namespace_scope: []` (guaranteed write-lockout).
//! 3. Admins are narrowed to `Write` (least privilege) and audited as `narrow`;
//!    groups are flattened to per-user `max(role)` and reported.
//!
//! Nexus exposes **no** permission API, so `--with-permissions` against Nexus is
//! a hard error, raised by `run` before any bytes move ([`ensure_supported`]);
//! `assess` additionally prints an informational NOTE for any Nexus source.

use serde::Serialize;
use std::path::{Path, PathBuf};

use super::source::SourceHttp;
use super::{Result, SourceKind};

/// Effective verb a source principal holds (already reduced from the source's
/// richer ACL to a single strongest verb per (principal, scope)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verb {
    Read,
    Write,
    Admin,
}

/// A principal (user or group) discovered on the source, with the repos it is
/// scoped to (empty = global) and its effective verb.
#[derive(Debug, Clone)]
pub struct SourcePrincipal {
    pub name: String,
    pub is_group: bool,
    /// Members, if this is a group (flattened at map time; discarded after).
    pub members: Vec<String>,
    /// Repos this grant is scoped to (empty ⇒ applies globally).
    pub repos: Vec<String>,
    pub verb: Verb,
}

/// Options controlling how aggressively the proposal maps roles.
#[derive(Debug, Clone, Copy)]
pub struct PermOpts {
    /// Allow proposing a role above `Read`.
    pub grant_write: bool,
}

/// A proposed NORA token for one user — **inert**: no credential is created.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenProposal {
    pub user: String,
    /// Proposed global role, one of `read`/`write` (never `admin`; admins are
    /// narrowed to write). Clamped to `read` unless `--grant-write`.
    pub role: String,
    /// Human-readable provenance for the audit trail.
    pub provenance: String,
}

/// An OIDC scope suggestion for a CI/OIDC identity — the ONLY way NORA can
/// express per-repo scope. Never emitted with an empty `namespace_scope`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OidcSuggestion {
    pub identity: String,
    pub namespace_scope: Vec<String>,
    pub role: String,
}

/// The inert proposal written to `import-permissions-report.json`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PermissionsReport {
    pub source: String,
    /// Loud reminder that nothing was created.
    pub note: String,
    pub proposed_tokens: Vec<TokenProposal>,
    pub oidc_scope_suggestions: Vec<OidcSuggestion>,
    /// Grants that were WIDENED (per-repo → global, or Write withheld pending
    /// `--grant-write`) — the operator must review these.
    pub widened: Vec<String>,
    /// Grants that were NARROWED (admin → write, group → discarded after flatten).
    pub narrowed: Vec<String>,
    /// Structural limitations the operator must know (e.g. token scope loss).
    pub warnings: Vec<String>,
}

/// Reduce a set of source principals to an inert NORA permission proposal.
///
/// Pure and total: groups are flattened to per-user `max(role)`, admins narrowed
/// to write, per-repo grants collapsed to global with a widen note, and — unless
/// `--grant-write` — any above-Read role is proposed as `read` with the user
/// listed in `widened`. Never proposes `admin`; never emits `namespace_scope: []`.
pub fn map_to_proposal(
    source_host: &str,
    principals: &[SourcePrincipal],
    opts: PermOpts,
) -> PermissionsReport {
    use std::collections::BTreeMap;

    // 1. Flatten groups to per-user contributions; track the strongest verb and
    //    whether any contributing grant was repo-scoped (→ widen).
    struct Acc {
        verb: Verb,
        repo_scoped: bool,
        from_group: bool,
    }
    let mut per_user: BTreeMap<String, Acc> = BTreeMap::new();
    let mut narrowed = Vec::new();
    let mut widened = Vec::new();
    let mut warnings = Vec::new();
    let mut oidc = Vec::new();

    let mut contribute = |user: &str, verb: Verb, repo_scoped: bool, from_group: bool| {
        let e = per_user.entry(user.to_string()).or_insert(Acc {
            verb: Verb::Read,
            repo_scoped: false,
            from_group: false,
        });
        e.verb = e.verb.max(verb);
        e.repo_scoped |= repo_scoped;
        e.from_group |= from_group;
    };

    for p in principals {
        let repo_scoped = !p.repos.is_empty();
        if p.is_group {
            narrowed.push(format!(
                "group {:?} ({} verb) flattened to {} member(s); group discarded",
                p.name,
                verb_str(p.verb),
                p.members.len()
            ));
            for m in &p.members {
                contribute(m, p.verb, repo_scoped, true);
            }
            // A repo-scoped CI/service group is the one case NORA CAN scope — via
            // an OIDC provider suggestion (never with an empty scope).
            if repo_scoped {
                let scope: Vec<String> = p.repos.iter().map(|r| format!("{r}/**")).collect();
                if !scope.is_empty() {
                    oidc.push(OidcSuggestion {
                        identity: p.name.clone(),
                        namespace_scope: scope,
                        role: role_str(narrow_admin(p.verb)),
                    });
                }
            }
        } else {
            contribute(&p.name, p.verb, repo_scoped, false);
        }
    }

    // 2. Emit per-user token proposals applying the safety clamps.
    let mut proposed_tokens = Vec::new();
    for (user, acc) in per_user {
        let mapped = narrow_admin(acc.verb); // admin → write (least privilege)
        if acc.verb == Verb::Admin {
            narrowed.push(format!(
                "user {user:?} admin → write (least privilege; promote manually)"
            ));
        }
        if acc.repo_scoped {
            widened.push(format!(
                "user {user:?} had per-repo scope → global {} (nra_ tokens cannot be repo-scoped)",
                role_str(mapped)
            ));
        }
        // Rule 1: never propose above Read without --grant-write.
        let role = if mapped == Verb::Read || opts.grant_write {
            mapped
        } else {
            widened.push(format!(
                "user {user:?} would get {} — withheld to read (pass --grant-write to propose it)",
                role_str(mapped)
            ));
            Verb::Read
        };
        let mut provenance = format!("imported from {source_host}");
        if acc.from_group {
            provenance.push_str(" (via group membership)");
        }
        proposed_tokens.push(TokenProposal {
            user,
            role: role_str(role),
            provenance,
        });
    }

    if !oidc.is_empty() {
        warnings.push(
            "OIDC suggestions require the operator to wire an IdP; they are not mintable tokens."
                .to_string(),
        );
    }
    if proposed_tokens.iter().any(|t| t.role != "read") {
        warnings.push(
            "Proposed non-read tokens grant GLOBAL write across all namespaces (no per-repo scope for nra_ tokens)."
                .to_string(),
        );
    }

    PermissionsReport {
        source: source_host.to_string(),
        note: "INERT PROPOSAL — no credentials were created. Review and apply manually (ADR-5 file-first)."
            .to_string(),
        proposed_tokens,
        oidc_scope_suggestions: oidc,
        widened,
        narrowed,
        warnings,
    }
}

fn narrow_admin(v: Verb) -> Verb {
    match v {
        Verb::Admin => Verb::Write,
        other => other,
    }
}

fn verb_str(v: Verb) -> &'static str {
    match v {
        Verb::Read => "read",
        Verb::Write => "write",
        Verb::Admin => "admin",
    }
}

fn role_str(v: Verb) -> String {
    // Maps the (already admin-narrowed) verb to a NORA role token.
    match v {
        Verb::Read => "read",
        Verb::Write | Verb::Admin => "write",
    }
    .to_string()
}

/// Write the inert proposal to `<dir>/import-permissions-report.json` with `0600`
/// perms (it names users; not a secret, but least-exposure by default).
pub async fn write_report(report: &PermissionsReport, dir: &Path) -> Result<PathBuf> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| format!("create report dir: {e}"))?;
    let path = dir.join("import-permissions-report.json");
    let json = serde_json::to_vec_pretty(report).map_err(|e| format!("serialize report: {e}"))?;
    tokio::fs::write(&path, &json)
        .await
        .map_err(|e| format!("write report: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort, but a failed restriction must be visible — otherwise the
        // report silently lands at the default umask (review: swallowed chmod).
        if let Err(e) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            tracing::warn!(error = %e, path = %path.display(), "could not chmod 0600 permissions report");
        }
    }
    Ok(path)
}

/// The hard error for `--with-permissions` against Nexus (no permission API).
/// Surfaced by `assess` before any bytes move (review R3).
pub fn nexus_unsupported() -> String {
    "--with-permissions is unsupported for Nexus: it exposes no permission API. \
     Re-run without --with-permissions, or migrate ACLs manually."
        .to_string()
}

/// Best-effort fetch of Artifactory permission targets (v2 API) reduced to
/// [`SourcePrincipal`]s. Defensive: missing/unknown fields are skipped rather
/// than failing the whole import. Not exercised by unit tests (needs a live
/// instance); the *mapping* it feeds is fully tested.
pub async fn fetch_artifactory_principals(http: &SourceHttp) -> Result<Vec<SourcePrincipal>> {
    let list = http.get("/api/v2/security/permissions").await?;
    if !list.status().is_success() {
        return Err(format!(
            "Artifactory permissions: HTTP {} (token needs admin)",
            list.status().as_u16()
        ));
    }
    let names: serde_json::Value = list
        .json()
        .await
        .map_err(|_| "Artifactory permissions: invalid JSON".to_string())?;
    let mut out = Vec::new();
    if let Some(arr) = names.as_array() {
        for entry in arr {
            let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let detail = http
                .get(&format!("/api/v2/security/permissions/{name}"))
                .await?;
            if !detail.status().is_success() {
                continue;
            }
            let Ok(v) = detail.json::<serde_json::Value>().await else {
                continue;
            };
            collect_principals(&v, &mut out);
        }
    }
    Ok(out)
}

/// Parse one Artifactory v2 permission target's `repo.actions.{users,groups}`
/// into principals. `read`/`write`(deploy)/`manage`(admin) collapse to [`Verb`].
fn collect_principals(target: &serde_json::Value, out: &mut Vec<SourcePrincipal>) {
    let repos: Vec<String> = target
        .pointer("/repo/repositories")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|r| r.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    // "ANY"/"ANY LOCAL" etc. mean global scope.
    let repos = if repos
        .iter()
        .any(|r| r.to_ascii_uppercase().starts_with("ANY"))
    {
        Vec::new()
    } else {
        repos
    };
    for (kind_key, is_group) in [("users", false), ("groups", true)] {
        let Some(map) = target
            .pointer(&format!("/repo/actions/{kind_key}"))
            .and_then(|v| v.as_object())
        else {
            continue;
        };
        for (principal, actions) in map {
            let verb = actions_to_verb(actions);
            out.push(SourcePrincipal {
                name: principal.clone(),
                is_group,
                members: Vec::new(), // Artifactory group membership is a separate API; left to manual review.
                repos: repos.clone(),
                verb,
            });
        }
    }
}

fn actions_to_verb(actions: &serde_json::Value) -> Verb {
    let has = |a: &str| {
        actions
            .as_array()
            .map(|arr| arr.iter().any(|x| x.as_str() == Some(a)))
            .unwrap_or(false)
    };
    if has("manage") || has("delete") {
        Verb::Admin
    } else if has("write") || has("deploy") {
        Verb::Write
    } else {
        Verb::Read
    }
}

/// Guard: `--with-permissions` is only meaningful for Artifactory.
pub fn ensure_supported(kind: SourceKind) -> Result<()> {
    match kind {
        SourceKind::Artifactory => Ok(()),
        SourceKind::Nexus => Err(nexus_unsupported()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, verb: Verb, repos: &[&str]) -> SourcePrincipal {
        SourcePrincipal {
            name: name.into(),
            is_group: false,
            members: vec![],
            repos: repos.iter().map(|s| s.to_string()).collect(),
            verb,
        }
    }

    fn group(name: &str, verb: Verb, members: &[&str], repos: &[&str]) -> SourcePrincipal {
        SourcePrincipal {
            name: name.into(),
            is_group: true,
            members: members.iter().map(|s| s.to_string()).collect(),
            repos: repos.iter().map(|s| s.to_string()).collect(),
            verb,
        }
    }

    #[test]
    fn write_is_withheld_without_grant_write() {
        let r = map_to_proposal(
            "h",
            &[user("alice", Verb::Write, &[])],
            PermOpts { grant_write: false },
        );
        let t = r
            .proposed_tokens
            .iter()
            .find(|t| t.user == "alice")
            .unwrap();
        assert_eq!(t.role, "read"); // clamped
        assert!(r
            .widened
            .iter()
            .any(|w| w.contains("alice") && w.contains("--grant-write")));
    }

    #[test]
    fn write_is_proposed_with_grant_write() {
        let r = map_to_proposal(
            "h",
            &[user("alice", Verb::Write, &[])],
            PermOpts { grant_write: true },
        );
        let t = r
            .proposed_tokens
            .iter()
            .find(|t| t.user == "alice")
            .unwrap();
        assert_eq!(t.role, "write");
    }

    #[test]
    fn admin_is_narrowed_to_write_and_audited() {
        let r = map_to_proposal(
            "h",
            &[user("root", Verb::Admin, &[])],
            PermOpts { grant_write: true },
        );
        let t = r.proposed_tokens.iter().find(|t| t.user == "root").unwrap();
        assert_eq!(t.role, "write"); // never "admin"
        assert!(r
            .narrowed
            .iter()
            .any(|n| n.contains("root") && n.contains("admin")));
    }

    #[test]
    fn groups_flatten_to_max_role_per_user() {
        let principals = vec![
            group("devs", Verb::Write, &["alice", "bob"], &[]),
            user("alice", Verb::Read, &[]), // alice also has a direct read grant
        ];
        let r = map_to_proposal("h", &principals, PermOpts { grant_write: true });
        // alice = max(group write, direct read) = write
        assert_eq!(
            r.proposed_tokens
                .iter()
                .find(|t| t.user == "alice")
                .unwrap()
                .role,
            "write"
        );
        assert_eq!(
            r.proposed_tokens
                .iter()
                .find(|t| t.user == "bob")
                .unwrap()
                .role,
            "write"
        );
        assert!(r
            .narrowed
            .iter()
            .any(|n| n.contains("devs") && n.contains("flattened")));
    }

    #[test]
    fn per_repo_scope_widens_to_global_with_warning() {
        let r = map_to_proposal(
            "h",
            &[user("carol", Verb::Write, &["libs-release"])],
            PermOpts { grant_write: true },
        );
        assert!(r
            .widened
            .iter()
            .any(|w| w.contains("carol") && w.contains("per-repo")));
    }

    #[test]
    fn never_emits_empty_namespace_scope() {
        // A repo-scoped GROUP would suggest OIDC scope — but only with real globs.
        let scoped = map_to_proposal(
            "h",
            &[group("ci", Verb::Write, &["svc"], &["team-a"])],
            PermOpts { grant_write: true },
        );
        assert!(scoped
            .oidc_scope_suggestions
            .iter()
            .all(|s| !s.namespace_scope.is_empty()));
        assert!(scoped
            .oidc_scope_suggestions
            .iter()
            .any(|s| s.identity == "ci"));

        // A GLOBAL group (no repos) must produce NO OIDC suggestion (never []).
        let global = map_to_proposal(
            "h",
            &[group("all", Verb::Read, &["x"], &[])],
            PermOpts { grant_write: true },
        );
        assert!(global.oidc_scope_suggestions.is_empty());
    }

    #[test]
    fn nexus_permissions_is_hard_error() {
        assert!(ensure_supported(SourceKind::Nexus).is_err());
        assert!(ensure_supported(SourceKind::Artifactory).is_ok());
    }

    #[tokio::test]
    async fn report_writes_inert_json_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let r = map_to_proposal(
            "art.example.com",
            &[user("alice", Verb::Read, &[])],
            PermOpts { grant_write: false },
        );
        let path = write_report(&r, tmp.path()).await.unwrap();
        let body = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(body.contains("INERT PROPOSAL"));
        assert!(body.contains("alice"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(&path)
                .await
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn actions_to_verb_maps_read_write_admin() {
        use serde_json::json;
        assert_eq!(actions_to_verb(&json!(["read"])), Verb::Read);
        assert_eq!(actions_to_verb(&json!([])), Verb::Read);
        assert_eq!(actions_to_verb(&json!(["read", "write"])), Verb::Write);
        assert_eq!(actions_to_verb(&json!(["deploy"])), Verb::Write);
        assert_eq!(actions_to_verb(&json!(["read", "manage"])), Verb::Admin);
        assert_eq!(actions_to_verb(&json!(["delete"])), Verb::Admin);
    }

    #[test]
    fn collect_principals_parses_users_groups_and_repos() {
        use serde_json::json;
        let target = json!({
            "repo": {
                "repositories": ["libs-release"],
                "actions": {
                    "users": { "alice": ["read", "write"] },
                    "groups": { "devs": ["read"] }
                }
            }
        });
        let mut out = Vec::new();
        collect_principals(&target, &mut out);
        assert_eq!(out.len(), 2);
        let alice = out.iter().find(|p| p.name == "alice").unwrap();
        assert!(!alice.is_group);
        assert_eq!(alice.verb, Verb::Write);
        assert_eq!(alice.repos, vec!["libs-release".to_string()]);
        let devs = out.iter().find(|p| p.name == "devs").unwrap();
        assert!(devs.is_group);
        assert_eq!(devs.verb, Verb::Read);
    }

    #[test]
    fn collect_principals_any_repo_is_global_scope() {
        use serde_json::json;
        let target = json!({
            "repo": {
                "repositories": ["ANY LOCAL"],
                "actions": { "users": { "bob": ["read"] } }
            }
        });
        let mut out = Vec::new();
        collect_principals(&target, &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].repos.is_empty(), "ANY* → global scope");
    }
}
