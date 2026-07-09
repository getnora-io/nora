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

// ── #733: serve-local for internal on download + check_download metadata paths ──
// An internal-namespace package that is locally published/cached must be SERVED (not 403'd by
// the pre-serve check_download), while an internal name with no local copy is still blocked.

#[tokio::test]
async fn pypi_internal_download_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.pypi.proxy = Some(BLACKHOLE.to_string());
    });
    ctx.state
        .storage
        .put("pypi/internalpkg/internalpkg-1.0.tar.gz", b"sdist")
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/internalpkg/internalpkg-1.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-published internal sdist must be downloadable, not 403'd (#733)"
    );
}

#[tokio::test]
async fn pypi_internal_download_no_local_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.pypi.proxy = Some(BLACKHOLE.to_string());
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/internalpkg/internalpkg-9.9.tar.gz",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "internal download with no local copy is blocked, never proxied"
    );
}

#[tokio::test]
async fn cargo_internal_download_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.cargo.proxy = Some(BLACKHOLE.to_string());
    });
    ctx.state
        .storage
        .put(
            "cargo/internalcrate/1.0.0/internalcrate-1.0.0.crate",
            b"crate-bytes",
        )
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/cargo/api/v1/crates/internalcrate/1.0.0/download",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-published internal crate must be downloadable (#733)"
    );
}

#[tokio::test]
async fn raw_internal_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    ctx.state
        .storage
        .put("raw/internal/secret.txt", b"data")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/raw/internal/secret.txt", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-stored internal raw file must be served (#733; raw has no upstream)"
    );
}

#[tokio::test]
async fn nuget_internal_registration_index_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.nuget.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    ctx.state
        .storage
        .put(
            "nuget/registration/internalpkg/index.json",
            br#"{"count":0,"items":[]}"#,
        )
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/internalpkg/index.json",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "internal registration index must be served from local (#733 over-block fix)"
    );
}

#[tokio::test]
async fn pubdart_internal_listing_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.pub_dart.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    ctx.state
        .storage
        .put(
            "pub/api/packages/internalpkg.json",
            br#"{"name":"internalpkg","versions":[]}"#,
        )
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/pub/api/packages/internalpkg", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "internal package listing must be served from local (#733 over-block fix)"
    );
}

#[tokio::test]
async fn gems_internal_compact_index_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.gems.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    ctx.state
        .storage
        .put("gems/info/internalgem", b"---\n1.0.0 |checksum:abc\n")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/gems/info/internalgem", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "internal gem compact-index must be served from local (#733 over-block fix)"
    );
}

#[tokio::test]
async fn conan_internal_recipe_file_served_local() {
    let ctx = create_test_context_with_config(|c| {
        c.conan.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    ctx.state
        .storage
        .put(
            "conan/internalpkg/1.0/user/stable/revisions/rev1/files/conanfile.py",
            b"from conan import ConanFile",
        )
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/conan/v2/conans/internalpkg/1.0/user/stable/revisions/rev1/files/conanfile.py",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-cached internal conan recipe file must be served (#733)"
    );
}

// ── #821: Docker/OCI internal-namespace local MISS is 404, never 403 ──
// A hosted internal-namespace image's absent manifest/blob is a not-found, not an authz denial.
// Docker/BuildKit treats 403 on a manifest HEAD/GET as FATAL (breaks `docker push` HEAD-probes and
// OCI referrers lookups), whereas 404 MANIFEST_UNKNOWN/BLOB_UNKNOWN lets it proceed. The
// dependency-confusion defense is unchanged: the internal branch precedes the proxy loop, so the
// live BLACKHOLE upstream is NEVER contacted — proven by the synthetic OCI error body (a leak or a
// proxy-fallback would yield a bare-body 404, failing the code assertion).

#[tokio::test]
async fn docker_internal_manifest_miss_get_404_not_403() {
    use crate::config::DockerUpstream;
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
        c.docker.upstreams = vec![DockerUpstream {
            url: BLACKHOLE.to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        }];
    });
    // A tag that does not exist yet in a hosted internal namespace (docker push pre-flight).
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/internal/backend/manifests/3.19.2",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "internal-ns manifest miss must be 404, not 403 (#821)"
    );
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["errors"][0]["code"], "MANIFEST_UNKNOWN",
        "must be OCI MANIFEST_UNKNOWN — proves the internal branch fired, upstream never contacted"
    );
}

#[tokio::test]
async fn docker_internal_manifest_miss_head_404_not_403() {
    use crate::config::DockerUpstream;
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
        c.docker.upstreams = vec![DockerUpstream {
            url: BLACKHOLE.to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        }];
    });
    // The HEAD probe docker issues before pushing a new tag — 403 here is fatal to the client.
    let resp = send(
        &ctx.app,
        Method::HEAD,
        "/v2/internal/backend/manifests/3.19.2",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "internal-ns manifest HEAD miss must be 404, not the fatal-to-docker 403 (#821)"
    );
}

#[tokio::test]
async fn docker_internal_referrers_tag_miss_head_404() {
    use crate::config::DockerUpstream;
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
        c.docker.upstreams = vec![DockerUpstream {
            url: BLACKHOLE.to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        }];
    });
    // OCI referrers fallback tag (sha256-<digest>) for a hosted image with no attestations:
    // this HEAD must 404 so `docker pull` of attestation-carrying internal images proceeds.
    let resp = send(
        &ctx.app,
        Method::HEAD,
        "/v2/internal/app/manifests/sha256-1111111111111111111111111111111111111111111111111111111111111111",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "internal-ns referrers-tag miss must be 404 (#821)"
    );
}

#[tokio::test]
async fn docker_internal_blob_miss_get_404_and_head_agrees() {
    use crate::config::DockerUpstream;
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
        c.docker.upstreams = vec![DockerUpstream {
            url: BLACKHOLE.to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        }];
    });
    let digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let uri = format!("/v2/internal/backend/blobs/{digest}");
    // GET was the 403 half of the HEAD/GET asymmetry (check_blob already 404s) — now 404 BLOB_UNKNOWN.
    let get = send(&ctx.app, Method::GET, &uri, "").await;
    assert_eq!(
        get.status(),
        StatusCode::NOT_FOUND,
        "internal-ns blob GET miss must be 404, not 403 (#821)"
    );
    let body = body_bytes(get).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["errors"][0]["code"], "BLOB_UNKNOWN");
    // HEAD and GET must now agree (both 404), closing the pre-fix asymmetry.
    let head = send(&ctx.app, Method::HEAD, &uri, "").await;
    assert_eq!(
        head.status(),
        StatusCode::NOT_FOUND,
        "internal-ns blob HEAD and GET must agree (both 404)"
    );
}

#[tokio::test]
async fn docker_internal_manifest_served_local_still_ok() {
    // Regression guard: the #821 fix touches only the MISS branch; a locally-hosted internal
    // manifest must still be served 200 (serve-local, #733), never namespace-blocked.
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
    });
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    // No upstream configured → canonicalize namespace is None → key docker/<name>/manifests/<ref>.json.
    ctx.state
        .storage
        .put(
            "docker/internal/backend/manifests/1.0.json",
            &serde_json::to_vec(&manifest).unwrap(),
        )
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/internal/backend/manifests/1.0",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "locally-hosted internal manifest must still be served, not blocked (#733 serve-local)"
    );
}

// ── observability: namespace-isolation refusals are counted in Prometheus ──
// The dependency-confusion defense firing was previously invisible in telemetry (only
// the client 403/404 and a test-internal counter existed). nora_namespace_isolation_refused_total
// makes it alertable/graphable. Delta assertion (after > before) is robust to parallel tests
// incrementing the same label, and still catches a removed increment (nothing bumps the label
// anywhere -> after == before -> fail).

#[tokio::test]
async fn docker_internal_miss_increments_isolation_refused_metric() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal/**".to_string()];
    });
    let before = crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&["docker"])
        .get();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/internal/backend/manifests/9.9.9",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let after = crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&["docker"])
        .get();
    assert!(
        after > before,
        "a docker internal-namespace refusal must increment nora_namespace_isolation_refused_total{{registry=docker}}"
    );
}

#[tokio::test]
async fn pypi_internal_refusal_increments_isolation_refused_metric() {
    let ctx = create_test_context_with_config(|c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.pypi.proxy = Some(BLACKHOLE.to_string());
    });
    let before = crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&["pypi"])
        .get();
    // Internal name, no local copy → check_namespace_isolation refusal (403).
    let resp = send(&ctx.app, Method::GET, "/simple/internalpkg-metric/", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let after = crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&["pypi"])
        .get();
    assert!(
        after > before,
        "a non-docker internal-namespace refusal (check_namespace_isolation) must increment the isolation-refused metric"
    );
}
