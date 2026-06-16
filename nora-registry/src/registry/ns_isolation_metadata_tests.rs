// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Cross-registry regression suite for namespace isolation on METADATA paths
//! (contrib-kit#68).
//!
//! Namespace isolation (`internal_namespaces`, the dependency-confusion defense,
//! "always active" — issue #185) historically gated only the download/artifact
//! path via `check_download`. Every proxy registry's metadata / index / version-list
//! / search path proxied upstream UNGATED, leaking internal package names. PR #725
//! fixed npm only.
//!
//! These tests pin the invariant for EVERY registry:
//! 1. an internal-namespace package's metadata with no local copy is BLOCKED (403),
//!    never proxied upstream;
//! 2. a locally-published internal package's metadata is still SERVED (200) — the
//!    guard must come after the local/cache serve, never blocking a local copy;
//! 3. a non-internal package is NOT blocked (proxies / 404s normally);
//! 4. a search query matching an internal pattern is NOT forwarded upstream.
//!
//! NB the test harness MERGES registry routers at the root (no per-registry nest),
//! so pypi lives at `/simple/...`; and several registries default to `enabled:false`,
//! so each test turns its registry on explicitly.

#![cfg(test)]
#![allow(clippy::unwrap_used)]

use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};

/// Connection-refused sentinel: if a guard is missing, the handler would try this
/// upstream and fail with a proxy error (≠ 403), exposing the leak path.
const BLACKHOLE: &str = "http://127.0.0.1:1";

// ── pypi: package_versions — serve local-only before gating the upstream merge ──

#[tokio::test]
async fn pypi_internal_metadata_blocked_not_proxied() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.pypi.proxy = Some(BLACKHOLE.to_string());
    });
    // Internal name, no local copy → 403 (never the BLACKHOLE upstream).
    let resp = send(&ctx.app, Method::GET, "/simple/internalpkg/", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pypi_internal_locally_published_served_hole5() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.pypi.proxy = Some(BLACKHOLE.to_string());
    });
    // A locally-published internal wheel must still be listed: the guard skips the
    // upstream merge but the local-only serve still answers.
    ctx.state
        .storage
        .put(
            "pypi/internalpkg/internalpkg-1.0-py3-none-any.whl",
            b"wheel-bytes",
        )
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/simple/internalpkg/", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-published internal package must be served, not 403"
    );
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(
        body.contains("internalpkg-1.0-py3-none-any.whl"),
        "listing must contain the locally-published file"
    );
}

#[tokio::test]
async fn pypi_public_metadata_not_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        // no proxy, no local → a non-internal name resolves to 404, NOT a 403 block.
    });
    let resp = send(&ctx.app, Method::GET, "/simple/publicpkg/", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a non-internal package must not be namespace-blocked"
    );
}

// ── maven: maven-metadata.xml (ArtifactMeta) ────────────────────────────────

#[tokio::test]
async fn maven_internal_metadata_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["com.internal.**".to_string()];
        c.maven.proxies = vec![];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/internal/lib/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── nuget: version list + search ────────────────────────────────────────────

#[tokio::test]
async fn nuget_internal_version_list_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.nuget.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/internalpkg/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn nuget_internal_search_not_forwarded() {
    let ctx = create_test_context_with_config(|c| {
        c.nuget.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.nuget.proxy = Some(BLACKHOLE.to_string());
        c.nuget.serve_stale = false; // without the guard, the BLACKHOLE failure → 503
    });
    // Searching an exact internal name must serve the local index, never forward it.
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=internalpkg", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "internal search term must be served locally, not forwarded to upstream"
    );
}

// ── conan: recipe metadata + search ─────────────────────────────────────────

#[tokio::test]
async fn conan_internal_recipe_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.conan.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/conan/v2/conans/internalpkg/1.0/user/channel/latest",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn conan_internal_search_not_forwarded() {
    let ctx = create_test_context_with_config(|c| {
        c.conan.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/conan/v2/conans/search?q=internalpkg",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(
        body.contains("\"results\""),
        "internal search must return an empty result set, not forward upstream"
    );
}

// ── pub_dart: version metadata ──────────────────────────────────────────────

#[tokio::test]
async fn pubdart_internal_version_metadata_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.pub_dart.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/pub/api/packages/internalpkg/versions/1.0.0",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── terraform: provider versions ────────────────────────────────────────────

#[tokio::test]
async fn terraform_internal_provider_versions_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.terraform.enabled = true;
        c.curation.internal_namespaces = vec!["acme/**".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/terraform/v1/providers/acme/aws/versions",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── ansible: collection detail (shared proxy_json helper) ───────────────────

#[tokio::test]
async fn ansible_internal_collection_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.ansible.enabled = true;
        c.curation.internal_namespaces = vec!["acme.**".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/ansible/v3/collections/acme/internal/",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── gems: gemspec (per-package metadata) ────────────────────────────────────

#[tokio::test]
async fn gems_internal_gemspec_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.gems.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/gems/quick/Marshal.4.8/internalgem-1.0.gemspec.rz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── go: module metadata (@v/list) ───────────────────────────────────────────

#[tokio::test]
async fn go_internal_metadata_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.go.proxy = Some(BLACKHOLE.to_string()); // go 404s without a proxy before the guard
    });
    let resp = send(&ctx.app, Method::GET, "/go/internal.corp/lib/@v/list", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn go_internal_stale_cached_served() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.go.proxy = Some(BLACKHOLE.to_string());
        c.go.metadata_ttl = 0; // @v/list is mutable; ttl=0 → "not fresh" → reaches the guard
    });
    // A cached internal module's mutable version list must be served (stale), never
    // re-proxied to the BLACKHOLE upstream (serve cached first, then block).
    ctx.state
        .storage
        .put("go/internal.corp/lib/@v/list", b"v1.0.0\n")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/go/internal.corp/lib/@v/list", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "cached internal go module must be served stale, not re-proxied (Shape B)"
    );
}

// ── npm: PR #725 residual — TTL-stale refetch must not re-proxy an internal pkg ──

#[tokio::test]
async fn npm_internal_stale_not_refetched() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.npm.proxy = Some(BLACKHOLE.to_string());
        c.npm.metadata_ttl = 0; // every pull is "stale" → would trigger refetch_metadata
        c.npm.serve_stale = false; // without the guard, the failed refetch → 502
    });
    // A locally-published internal packument whose cache is "stale" must be served
    // from the local copy, NOT re-fetched upstream (the #725 residual leak).
    ctx.state
        .storage
        .put(
            "npm/internalpkg/metadata.json",
            br#"{"name":"internalpkg","versions":{}}"#,
        )
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/npm/internalpkg", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "stale internal packument must serve cached copy, not re-proxy (PR #725 residual)"
    );
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(body.contains("internalpkg"));
}
