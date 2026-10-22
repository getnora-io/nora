// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Cross-registry regression suite for namespace isolation on METADATA paths
//! (#732).
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

// ── pub_dart: search ────────────────────────────────────────────────────────

/// A search term naming an internal namespace never reaches the upstream; a public term does.
#[tokio::test]
async fn pubdart_internal_search_not_forwarded() {
    use sha2::Digest;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"packages":[{"package":"x"}]}"#),
        )
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.pub_dart.enabled = true;
        c.pub_dart.proxy = Some(uri);
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    // A stored answer to an internal term (an older release cached it) is not served either.
    ctx.state
        .storage
        .put(
            &format!(
                "pub/search/{}.json",
                hex::encode(sha2::Sha256::digest(b"q=internalcached"))
            ),
            br#"{"packages":[{"package":"x"}]}"#,
        )
        .await
        .unwrap();
    for query in [
        "q=internalpkg",
        "q=internal%70kg&page=2",
        "page=1&q=internalpkg",
        "q=INTERNALpkg",
        "q=package:internalpkg",
        "q=dependency%3Ainternalpkg",
        "q=tools+internalpkg",
        "q=internalcached",
        "q=publicpkg&q=internalpkg",
        "%71=internalpkg",
        "page=1&sort=top&q=internalpkg",
        "q=-internalpkg",
        "q=internalpkg-x",
    ] {
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/pub/api/packages?{query}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{query}");
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(!body.contains("\"x\""), "{query}: upstream result served");
    }
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "an internal term reached the upstream"
    );
    let resp = send(&ctx.app, Method::GET, "/pub/api/packages?q=publicpkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        1,
        "a public term is asked upstream"
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
async fn nuget_internal_nuspec_served_local_and_miss_blocked() {
    let ctx = create_test_context_with_config(|c| {
        c.nuget.enabled = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.nuget.proxy = Some(BLACKHOLE.to_string());
    });
    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/internalpkg/1.0.0/internalpkg.nuspec",
            b"<package/>",
        )
        .await
        .unwrap();
    let served = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.nuspec",
        "",
    )
    .await;
    assert_eq!(served.status(), StatusCode::OK);
    assert_eq!(&body_bytes(served).await[..], b"<package/>");
    // No local copy: refused as the package itself is, never asked of the upstream.
    let missing = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/internalpkg/2.0.0/internalpkg.nuspec",
        "",
    )
    .await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
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

// ── A recording upstream: an internal name never reaches it, dates included ──
//
// BLACKHOLE shows a missing guard only where the failed fetch changes the answer. A
// best-effort lookup — a release date for the quarantine clock, a metadata self-prime —
// swallows its failure, so a leak there answers the same. A recording upstream sees every
// request; each internal path has a public twin that must reach it, so no path passes for
// being dead.

const INTERNAL_PATHS: [&str; 35] = [
    "/npm/internalpkg",
    "/npm/internalpkg/-/internalpkg-1.0.0.tgz",
    "/simple/internalpkg/",
    "/simple/internalpkg/internalpkg-1.0.tar.gz",
    "/cargo/api/v1/crates/internalpkg",
    "/cargo/api/v1/crates/internalpkg/1.0.0/download",
    "/gems/info/internalpkg",
    "/gems/gems/internalpkg-1.0.0.gem",
    "/gems/gems/internalpkg-1.0.0-x86_64-linux.gem",
    "/gems/quick/Marshal.4.8/internalpkg-1.0.0.gemspec.rz",
    "/nuget/v3/flatcontainer/internalpkg/index.json",
    "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.1.0.0.nupkg",
    "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.nuspec",
    "/go/internal.corp/lib/@v/list",
    "/go/internal.corp/lib/@v/v1.0.0.info",
    "/go/internal.corp/lib/@v/v1.0.0.zip",
    "/pub/api/packages/internalpkg",
    "/pub/packages/internalpkg/versions/1.0.0.tar.gz",
    "/conan/v2/conans/internalpkg/1.0/_/_/latest",
    "/ansible/api/v3/plugin/ansible/content/published/collections/index/internalns/coll/",
    "/ansible/api/v3/plugin/ansible/content/published/collections/index/internalns/coll/versions/",
    "/ansible/download/internalns-coll-1.0.0.tar.gz",
    "/cpan/authors/id/I/IN/INTERNAL/internalpkg-1.0.tar.gz",
    "/terraform/v1/providers/internalns/infra/versions",
    "/terraform/v1/providers/internalns/infra/1.0.0/download/linux/amd64",
    "/terraform/v1/providers/download/internalns/infra/1.0.0/terraform-provider-infra_1.0.0_darwin_arm64.zip",
    "/terraform/v1/modules/internalns/vpc/aws/versions",
    "/terraform/v1/modules/internalns/vpc/aws/1.0.0/download",
    "/terraform/v1/modules/download/internalns/vpc/aws/2.0.0/source",
    "/terraform/registry.terraform.io/internalns/infra/index.json",
    "/terraform/registry.terraform.io/internalns/infra/1.0.0.json",
    "/maven2/internalpkg/lib/maven-metadata.xml",
    "/maven2/internalpkg/lib/1.0/lib-1.0.jar",
    "/v2/internalpkg/manifests/1.0",
    "/v2/internalpkg/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
];

async fn upstream_paths(upstream: &wiremock::MockServer) -> Vec<String> {
    upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

fn public_twin(path: &str) -> String {
    path.replace("internalpkg", "publicpkg")
        .replace("internal.corp", "public.corp")
        .replace("internalns", "publicns")
        .replace("I/IN/INTERNAL", "P/PU/PUBLIC")
}

#[tokio::test]
async fn an_internal_name_never_reaches_a_recording_upstream_dates_included() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let seed_uri = uri.clone();
    let ctx = create_test_context_with_config(move |c| {
        c.server.trust_upstream_dates = true;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.npm.proxy = Some(uri.clone());
        c.pypi.proxy = Some(uri.clone());
        c.cargo.proxy = Some(uri.clone());
        c.gems.enabled = true;
        c.gems.proxy = Some(uri.clone());
        c.nuget.enabled = true;
        c.nuget.proxy = Some(uri.clone());
        c.go.proxy = Some(uri.clone());
        c.pub_dart.enabled = true;
        c.pub_dart.proxy = Some(uri.clone());
        c.conan.enabled = true;
        c.conan.proxy = Some(uri.clone());
        c.ansible.enabled = true;
        c.ansible.proxy = Some(uri.clone());
        c.cpan.enabled = true;
        c.cpan.proxy = Some(uri.clone());
        c.terraform.enabled = true;
        c.terraform.proxy = Some(uri.clone());
        c.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri.clone())];
        c.docker.upstreams = vec![crate::config::DockerUpstream {
            url: uri,
            auth: None,
            namespace: None,
            prefix: None,
        }];
    });
    // Terraform metadata cached before the namespace became internal still names an upstream
    // URL for a provider's files and a module's archive; the public twin's names the same
    // upstream.
    for ns in ["internalns", "publicns"] {
        ctx.state
            .storage
            .put(
                &format!("terraform/providers/{ns}/infra/1.0.0/darwin_arm64.json"),
                serde_json::json!({"_nora_upstream_url": format!("{seed_uri}/{ns}-infra.zip")})
                    .to_string()
                    .as_bytes(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &format!("terraform/modules/{ns}/vpc/aws/2.0.0/_source_url"),
                format!("{seed_uri}/{ns}-vpc.tar.gz").as_bytes(),
            )
            .await
            .unwrap();
    }
    for path in INTERNAL_PATHS {
        let _ = send(&ctx.app, Method::GET, path, "").await;
    }
    let leaked = upstream_paths(&upstream).await;
    assert!(
        leaked.is_empty(),
        "internal names sent upstream: {leaked:?}"
    );

    // Control: each path is live — its public twin reaches the upstream.
    let mut dead = Vec::new();
    for path in INTERNAL_PATHS {
        let before = upstream_paths(&upstream).await.len();
        let twin = public_twin(path);
        let _ = send(&ctx.app, Method::GET, &twin, "").await;
        if upstream_paths(&upstream).await.len() == before {
            dead.push(twin);
        }
    }
    assert!(
        dead.is_empty(),
        "public twins that never reached upstream: {dead:?}"
    );
}

/// A hierarchical internal namespace isolates the PyPI projects under it in the form pip
/// requests them (`corp.tools` and `Corp_Tools` are requested as `corp-tools`).
#[tokio::test]
async fn a_hierarchical_namespace_isolates_pypi_projects_under_it() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.curation.internal_namespaces = vec!["corp.**".to_string()];
        c.pypi.proxy = Some(uri);
    });
    for path in [
        "/simple/corp/",
        "/simple/corp.tools/",
        "/simple/corp-tools/",
        "/simple/Corp_Tools/",
        "/simple/corp-tools/corp_tools-1.0.tar.gz",
    ] {
        let _ = send(&ctx.app, Method::GET, path, "").await;
    }
    let requested: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        requested.is_empty(),
        "internal projects sent upstream: {requested:?}"
    );
    let _ = send(&ctx.app, Method::GET, "/simple/corporate/", "").await;
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        1,
        "a project outside the namespace reaches the upstream"
    );
}

// ── A store that cannot be read: an internal package is unavailable, not absent ──
//
// An internal-namespace package is served from its local copy only. When the store fails to
// read that copy (an outage, not a missing key), the package is unavailable: 503. A 403 or a
// 404 tells a client with several feeds to look for the internal name in the next one, and no
// upstream is asked either way.

/// Each internal path, and the key its local copy lives under.
const INTERNAL_STORED: [(&str, &str); 11] = [
    (
        "/npm/internalpkg/-/internalpkg-1.0.0.tgz",
        "npm/internalpkg/tarballs/internalpkg-1.0.0.tgz",
    ),
    ("/npm/internalpkg", "npm/internalpkg/versions/1.0.0.json"),
    (
        "/npm/-/package/internalpkg/dist-tags",
        "npm/internalpkg/versions/1.0.0.json",
    ),
    (
        "/npm/internalpkg/1.0.0",
        "npm/internalpkg/versions/1.0.0.json",
    ),
    (
        "/simple/internalpkg/internalpkg-1.0.tar.gz",
        "pypi/internalpkg/internalpkg-1.0.tar.gz",
    ),
    (
        "/simple/internalpkg/",
        "pypi/internalpkg/internalpkg-1.0.tar.gz",
    ),
    (
        "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.1.0.0.nupkg",
        "nuget/flatcontainer/internalpkg/1.0.0/internalpkg.1.0.0.nupkg",
    ),
    (
        "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.nuspec",
        "nuget/flatcontainer/internalpkg/1.0.0/internalpkg.nuspec",
    ),
    (
        "/nuget/v3/flatcontainer/internalpkg/index.json",
        "nuget/flatcontainer/internalpkg/index.json",
    ),
    (
        "/nuget/v3/registration/internalpkg/index.json",
        "nuget/registration/internalpkg/index.json",
    ),
    (
        "/nuget/v3/registration/internalpkg/page/1.0.0/1.0.0.json",
        "nuget/registration/internalpkg/page/1.0.0/1.0.0.json",
    ),
];

/// The bytes stored under an [`INTERNAL_STORED`] key.
fn internal_stored_body(key: &str) -> Vec<u8> {
    if key.starts_with("npm/") && key.ends_with(".json") {
        br#"{"name":"internalpkg","version":"1.0.0"}"#.to_vec()
    } else if key.ends_with(".json") {
        br#"{"count":0,"items":[],"versions":["1.0.0"]}"#.to_vec()
    } else {
        b"local copy".to_vec()
    }
}

#[tokio::test]
async fn an_internal_package_on_a_store_that_cannot_be_read_is_unavailable_not_absent() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, move |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.npm.proxy = Some(uri.clone());
        c.pypi.proxy = Some(uri.clone());
        c.nuget.enabled = true;
        c.nuget.proxy = Some(uri);
    });
    for (_, key) in INTERNAL_STORED {
        ctx.state
            .storage
            .put(key, &internal_stored_body(key))
            .await
            .unwrap();
    }
    // The store up: each is served from its local copy.
    for (path, _) in INTERNAL_STORED {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{path} with the store up");
    }

    outage.begin();
    let mut wrong = Vec::new();
    for (path, _) in INTERNAL_STORED {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "internal packages answered other than 503 with the store down: {wrong:#?}"
    );
    let asked = upstream_paths(&upstream).await;
    assert!(
        asked.is_empty(),
        "upstream asked during the outage: {asked:?}"
    );

    // A package outside the internal namespaces is not handed to its upstream either: a store
    // that cannot list a package's published versions (npm) or its imported ones (NuGet, PyPI)
    // leaves NORA unable to tell whether the name is NORA's own: 503, as for cargo. With
    // listings answering, a public package still goes to its upstream (the test below).
    for path in [
        "/nuget/v3/flatcontainer/publicpkg/1.0.0/publicpkg.1.0.0.nupkg",
        "/npm/publicpkg/-/publicpkg-1.0.0.tgz",
        "/simple/publicpkg/",
    ] {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} during the outage"
        );
    }
    assert_eq!(upstream_paths(&upstream).await, Vec::<String>::new());
}

/// The same when only object reads fail and listings still answer (a store throttling its GETs):
/// a package that is not published but was cached before its name became internal included.
#[tokio::test]
async fn an_internal_package_whose_copy_cannot_be_read_is_unavailable_not_absent() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, move |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.npm.proxy = Some(uri.clone());
        c.pypi.proxy = Some(uri.clone());
        c.nuget.enabled = true;
        c.nuget.proxy = Some(uri);
    });
    let stored = [
        (
            "/npm/internalpkg/-/internalpkg-1.0.0.tgz",
            "npm/internalpkg/tarballs/internalpkg-1.0.0.tgz",
        ),
        (
            "/npm/internalcache",
            "npm/internalcache/upstream/packument.json",
        ),
        (
            "/simple/internalpkg/internalpkg-1.0.tar.gz",
            "pypi/internalpkg/internalpkg-1.0.tar.gz",
        ),
        (
            "/nuget/v3/flatcontainer/internalpkg/1.0.0/internalpkg.1.0.0.nupkg",
            "nuget/flatcontainer/internalpkg/1.0.0/internalpkg.1.0.0.nupkg",
        ),
        (
            "/nuget/v3/flatcontainer/internalpkg/index.json",
            "nuget/flatcontainer/internalpkg/index.json",
        ),
    ];
    for (_, key) in stored {
        let body = if key.ends_with(".json") {
            br#"{"name":"internalcache","versions":{},"dist-tags":{}}"#.to_vec()
        } else {
            b"local copy".to_vec()
        };
        ctx.state.storage.put(key, &body).await.unwrap();
    }
    for (path, _) in stored {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{path} with the store up");
    }

    outage.fail_reads();
    let mut wrong = Vec::new();
    for (path, _) in stored {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "internal packages answered other than 503 with reads failing: {wrong:#?}"
    );
    let asked = upstream_paths(&upstream).await;
    assert!(
        asked.is_empty(),
        "upstream asked while reads fail: {asked:?}"
    );

    // Control: listings still answer, so NORA can tell a public package is not its own, and its
    // upstream answers for it.
    for path in [
        "/nuget/v3/flatcontainer/publicpkg/1.0.0/publicpkg.1.0.0.nupkg",
        "/simple/publicpkg/",
    ] {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} while reads fail"
        );
    }
    let asked = upstream_paths(&upstream).await;
    assert!(
        asked.iter().any(|p| p.contains("/publicpkg/1.0.0/"))
            && asked.iter().any(|p| p.ends_with("/publicpkg/"))
            && asked.iter().all(|p| p.contains("publicpkg")),
        "{asked:?}"
    );
}

/// Each internal download of the other formats, and the key its local copy lives under.
const INTERNAL_STORED_ELSEWHERE: [(&str, &str); 17] = [
    (
        "/gems/gems/internalpkg-1.0.0.gem",
        "gems/gems/internalpkg-1.0.0.gem",
    ),
    (
        "/gems/quick/Marshal.4.8/internalpkg-1.0.0.gemspec.rz",
        "gems/quick/Marshal.4.8/internalpkg-1.0.0.gemspec.rz",
    ),
    (
        "/maven2/internalpkg/lib/1.0/lib-1.0.jar",
        "maven/internalpkg/lib/1.0/lib-1.0.jar",
    ),
    (
        "/maven2/internalpkg/lib/maven-metadata.xml",
        "maven/internalpkg/lib/maven-metadata.xml",
    ),
    (
        "/pub/packages/internalpkg/versions/1.0.0.tar.gz",
        "pub/packages/internalpkg/versions/1.0.0.tar.gz",
    ),
    (
        "/ansible/download/internalns-coll-1.0.0.tar.gz",
        "ansible/download/internalns-coll-1.0.0.tar.gz",
    ),
    (
        "/go/internal.corp/lib/@v/v1.0.0.zip",
        "go/internal.corp/lib/@v/v1.0.0.zip",
    ),
    (
        "/cargo/api/v1/crates/internalpkg/1.0.0/download",
        "cargo/internalpkg/1.0.0/internalpkg-1.0.0.crate",
    ),
    (
        "/cpan/authors/id/I/IN/INTERNAL/internalpkg-1.0.tar.gz",
        "cpan/authors/id/I/IN/INTERNAL/internalpkg-1.0.tar.gz",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/latest",
        "conan/internalpkg/1.0/_/_/latest.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions",
        "conan/internalpkg/1.0/_/_/revisions.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/files",
        "conan/internalpkg/1.0/_/_/revisions/abc1/files.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/files/conanfile.py",
        "conan/internalpkg/1.0/_/_/revisions/abc1/files/conanfile.py",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/latest",
        "conan/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/latest.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions",
        "conan/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions/def2/files",
        "conan/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions/def2/files.json",
    ),
    (
        "/conan/v2/conans/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions/def2/files/conaninfo.txt",
        "conan/internalpkg/1.0/_/_/revisions/abc1/packages/pid1/revisions/def2/files/conaninfo.txt",
    ),
];

/// A context serving [`INTERNAL_STORED_ELSEWHERE`] from `storage`, its formats turned on.
fn other_formats_context(storage: crate::storage::Storage) -> crate::test_helpers::TestContext {
    crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.gems.enabled = true;
        c.pub_dart.enabled = true;
        c.ansible.enabled = true;
        c.cpan.enabled = true;
        c.conan.enabled = true;
    })
}

/// The same for the other formats' downloads: an internal package's copy that the store could
/// not read answers 503, never 403 or 404.
#[tokio::test]
async fn an_internal_download_of_every_other_format_on_a_store_that_cannot_be_read_is_503() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = other_formats_context(storage);
    let stored = INTERNAL_STORED_ELSEWHERE;
    for (_, key) in stored {
        ctx.state.storage.put(key, b"local copy").await.unwrap();
    }
    let mut up = Vec::new();
    for (path, _) in stored {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::OK {
            up.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        up.is_empty(),
        "internal packages not served from their local copy with the store up: {up:#?}"
    );
    outage.begin();
    let mut wrong = Vec::new();
    for (path, _) in stored {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "internal packages answered other than 503 with the store down: {wrong:#?}"
    );
}

/// A CPAN distribution can be internal by its author path, not only by its name: such a
/// distribution is served from its local copy, and without one it is refused and never fetched.
#[tokio::test]
async fn a_cpan_distribution_internal_by_its_author_path_stays_local() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UPSTREAM".to_vec()))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.curation.internal_namespaces = vec!["I/IN/INTERNAL/**".to_string()];
        c.cpan.enabled = true;
        c.cpan.proxy = Some(uri);
    });
    ctx.state
        .storage
        .put(
            "cpan/authors/id/I/IN/INTERNAL/Corp-Lib-1.0.tar.gz",
            b"local copy",
        )
        .await
        .unwrap();
    let served = send(
        &ctx.app,
        Method::GET,
        "/cpan/authors/id/I/IN/INTERNAL/Corp-Lib-1.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(served.status(), StatusCode::OK);
    assert_eq!(&body_bytes(served).await[..], b"local copy");
    let missing = send(
        &ctx.app,
        Method::GET,
        "/cpan/authors/id/I/IN/INTERNAL/Corp-Lib-2.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(upstream_paths(&upstream).await, Vec::<String>::new());
    // Control: another author's distribution is fetched.
    let other = send(
        &ctx.app,
        Method::GET,
        "/cpan/authors/id/P/PU/PUBLIC/Corp-Lib-2.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(other.status(), StatusCode::OK);
}

/// An internal terraform provider and module: each stored key and its bytes, and each path they
/// are served from with its status with the store up.
#[allow(clippy::type_complexity)]
fn internal_terraform() -> (Vec<(String, Vec<u8>)>, [(String, StatusCode); 8]) {
    let zip = "terraform-provider-infra_1.0.0_linux_amd64.zip";
    let stored: Vec<(String, Vec<u8>)> = vec![
        (
            "terraform/providers/internalns/infra/versions.json".into(),
            br#"{"versions":[{"version":"1.0.0","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#.to_vec(),
        ),
        (
            "terraform/providers/internalns/infra/1.0.0/linux_amd64.json".into(),
            format!(r#"{{"os":"linux","arch":"amd64","filename":"{zip}","download_url":"http://nora/terraform/v1/providers/download/internalns/infra/1.0.0/{zip}","shasum":"00ff"}}"#).into_bytes(),
        ),
        (format!("terraform/download/internalns/infra/1.0.0/{zip}"), b"zip".to_vec()),
        (
            "terraform/modules/internalns/vpc/aws/versions.json".into(),
            br#"{"modules":[{"versions":[{"version":"1.0.0"}]}]}"#.to_vec(),
        ),
        (
            "terraform/modules/internalns/vpc/aws/1.0.0/_source_url".into(),
            b"https://modules.example/vpc-1.0.0.tar.gz".to_vec(),
        ),
        (
            "terraform/modules/internalns/vpc/aws/1.0.0/source.tar.gz".into(),
            b"tgz".to_vec(),
        ),
    ];
    let paths = [
        (
            "/terraform/v1/providers/internalns/infra/versions".to_string(),
            StatusCode::OK,
        ),
        (
            "/terraform/v1/providers/internalns/infra/1.0.0/download/linux/amd64".to_string(),
            StatusCode::OK,
        ),
        (
            format!("/terraform/v1/providers/download/internalns/infra/1.0.0/{zip}"),
            StatusCode::OK,
        ),
        (
            "/terraform/v1/modules/internalns/vpc/aws/versions".to_string(),
            StatusCode::OK,
        ),
        (
            "/terraform/v1/modules/internalns/vpc/aws/1.0.0/download".to_string(),
            StatusCode::NO_CONTENT,
        ),
        (
            "/terraform/v1/modules/download/internalns/vpc/aws/1.0.0/source".to_string(),
            StatusCode::OK,
        ),
        (
            "/terraform/registry.terraform.io/internalns/infra/index.json".to_string(),
            StatusCode::OK,
        ),
        (
            "/terraform/registry.terraform.io/internalns/infra/1.0.0.json".to_string(),
            StatusCode::OK,
        ),
    ];
    (stored, paths)
}

/// A context serving [`internal_terraform`] from `storage`, seeded.
async fn internal_terraform_context(
    storage: crate::storage::Storage,
) -> crate::test_helpers::TestContext {
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.terraform.enabled = true;
        c.terraform.proxy = Some(BLACKHOLE.to_string());
    });
    for (key, body) in internal_terraform().0 {
        ctx.state.storage.put(&key, &body).await.unwrap();
    }
    ctx
}

/// Terraform: every path an internal provider or module is served from — the registry protocol,
/// its file downloads and the provider network mirror — answers 503 when the store cannot read
/// the local copy.
#[tokio::test]
async fn an_internal_terraform_provider_or_module_on_a_store_that_cannot_be_read_is_503() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = internal_terraform_context(storage).await;
    let (_, paths) = internal_terraform();
    let mut up = Vec::new();
    for (path, expected) in &paths {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != *expected {
            up.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        up.is_empty(),
        "internal terraform objects not served from their local copy with the store up: {up:#?}"
    );
    outage.begin();
    let mut wrong = Vec::new();
    for (path, _) in &paths {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "internal terraform objects answered other than 503 with the store down: {wrong:#?}"
    );
}

/// The network mirror lists every platform of an internal provider's version from its cached
/// metadata: a platform whose metadata the store cannot read makes the answer 503, never a list
/// that silently leaves the platform out.
#[tokio::test]
async fn an_internal_mirror_platform_whose_metadata_cannot_be_read_is_503_not_left_out() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.terraform.enabled = true;
        c.terraform.proxy = Some(BLACKHOLE.to_string());
    });
    ctx.state
        .storage
        .put(
            "terraform/providers/internalns/infra/versions.json",
            br#"{"versions":[{"version":"1.0.0","platforms":[{"os":"linux","arch":"amd64"},{"os":"darwin","arch":"arm64"}]}]}"#,
        )
        .await
        .unwrap();
    for platform in ["linux_amd64", "darwin_arm64"] {
        ctx.state
            .storage
            .put(
                &format!("terraform/providers/internalns/infra/1.0.0/{platform}.json"),
                format!(r#"{{"download_url":"http://nora/{platform}.zip","shasum":"00ff"}}"#)
                    .as_bytes(),
            )
            .await
            .unwrap();
    }
    let path = "/terraform/registry.terraform.io/internalns/infra/1.0.0.json";
    let both = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(both.status(), StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_slice(&body_bytes(both).await).unwrap();
    assert_eq!(listed["archives"].as_object().unwrap().len(), 2);
    outage.fail_reads_of("/darwin_arm64.json");
    let resp = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A local copy that fails its integrity check (changed on disk) is neither served nor taken for
/// absent: 500, never 403/404 and not the 503 of an outage, and no upstream is asked — in every
/// format, for each key on its own.
#[tokio::test]
async fn an_internal_package_whose_copy_fails_its_integrity_check_is_500_in_every_format() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    use crate::test_helpers::{ReadFault, StorageOutage, TestContext};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Each path answered with its key's copy changed on disk, where the answer is not 500.
    async fn not_500(
        ctx: &TestContext,
        outage: &StorageOutage,
        stored: &[(&str, &str)],
    ) -> Vec<String> {
        let mut wrong = Vec::new();
        for (path, key) in stored {
            outage.end();
            outage.fault_reads_of(key, ReadFault::Tampered);
            let status = send(&ctx.app, Method::GET, path, "").await.status();
            if status != StatusCode::INTERNAL_SERVER_ERROR {
                wrong.push(format!("{path} ({key}) -> {status}"));
            }
        }
        outage.end();
        wrong
    }

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, move |c| {
        c.curation.internal_namespaces = vec!["internal*".to_string()];
        c.npm.proxy = Some(uri.clone());
        c.pypi.proxy = Some(uri.clone());
        c.nuget.enabled = true;
        c.nuget.proxy = Some(uri);
    });
    for (_, key) in INTERNAL_STORED {
        ctx.state
            .storage
            .put(key, &internal_stored_body(key))
            .await
            .unwrap();
    }
    // The project listing names its files from the store's listing and reads no copy of them.
    let reads_its_copy: Vec<(&str, &str)> = INTERNAL_STORED
        .into_iter()
        .filter(|(path, _)| *path != "/simple/internalpkg/")
        .collect();
    let mut wrong = not_500(&ctx, &outage, &reads_its_copy).await;
    let asked = upstream_paths(&upstream).await;
    assert!(
        asked.is_empty(),
        "upstream asked for a tampered copy: {asked:?}"
    );

    let (storage, outage) = outage_storage();
    let ctx = other_formats_context(storage);
    for (_, key) in INTERNAL_STORED_ELSEWHERE {
        ctx.state.storage.put(key, b"local copy").await.unwrap();
    }
    wrong.extend(not_500(&ctx, &outage, &INTERNAL_STORED_ELSEWHERE).await);

    // Terraform: a path reads several keys, so every key is changed at once.
    let (storage, outage) = outage_storage();
    let ctx = internal_terraform_context(storage).await;
    let (stored, paths) = internal_terraform();
    for (key, _) in &stored {
        outage.fault_reads_of(key, ReadFault::Tampered);
    }
    for (path, _) in &paths {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "internal packages whose copy fails its integrity check answered other than 500: {wrong:#?}"
    );
}

/// A Go module path with capitals travels encoded (`!c` for `C`); the namespace it belongs to is
/// read from the decoded path. An internal module spelled with capitals is served from its copy,
/// refused without one, and unavailable (503) when the copy cannot be read — on every endpoint.
#[tokio::test]
async fn an_internal_go_module_with_capitals_is_internal_on_every_path() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |c| {
        c.curation.internal_namespaces = vec!["Corp.example/*".to_string()];
        c.go.proxy = Some(BLACKHOLE.to_string());
    });
    let files = [
        "@v/v1.0.0.zip",
        "@v/v1.0.0.info",
        "@v/v1.0.0.mod",
        "@v/list",
        "@latest",
    ];
    for file in files {
        ctx.state
            .storage
            .put(&format!("go/!corp.example/!lib/{file}"), b"local copy")
            .await
            .unwrap();
    }
    let mut wrong = Vec::new();
    for file in files {
        let path = format!("/go/!corp.example/!lib/{file}");
        let status = send(&ctx.app, Method::GET, &path, "").await.status();
        if status != StatusCode::OK {
            wrong.push(format!("{path} with the store up -> {status}"));
        }
        let missing = format!("/go/!corp.example/!other/{file}");
        let status = send(&ctx.app, Method::GET, &missing, "").await.status();
        if status != StatusCode::FORBIDDEN {
            wrong.push(format!("{missing} without a copy -> {status}"));
        }
    }
    outage.fail_reads();
    for file in files {
        let path = format!("/go/!corp.example/!lib/{file}");
        let status = send(&ctx.app, Method::GET, &path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} with reads failing -> {status}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// An internal npm package's packument or version manifest cached from an upstream lives under
/// its `upstream/` key, or — cached by a release before 1.4.0 — under the legacy
/// `<path>/metadata.json`. Whichever key holds the copy, a read of it that fails leaves the
/// package unavailable (503), not absent, and the upstream is not asked.
#[tokio::test]
async fn an_internal_npm_document_whose_cached_copy_cannot_be_read_is_503_under_either_key() {
    use crate::test_helpers::ReadFault;
    use crate::test_helpers::{create_test_context_with_storage_and_config, outage_storage};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    let cases = [
        (
            "/npm/internalcache",
            "npm/internalcache/upstream/packument.json",
        ),
        ("/npm/internalcache", "npm/internalcache/metadata.json"),
        (
            "/npm/internalcache/1.0.0",
            "npm/internalcache/upstream/manifests/1.0.0.json",
        ),
        (
            "/npm/internalcache/1.0.0",
            "npm/internalcache/1.0.0/metadata.json",
        ),
    ];
    let mut wrong = Vec::new();
    for (path, key) in cases {
        for (fault, expected) in [
            (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
            (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let uri = upstream.uri();
            let (storage, outage) = outage_storage();
            let ctx = create_test_context_with_storage_and_config(storage, move |c| {
                c.curation.internal_namespaces = vec!["internal*".to_string()];
                c.npm.proxy = Some(uri);
            });
            ctx.state
                .storage
                .put(
                    key,
                    br#"{"name":"internalcache","version":"1.0.0","versions":{},"dist-tags":{}}"#,
                )
                .await
                .unwrap();
            let status = send(&ctx.app, Method::GET, path, "").await.status();
            if status != StatusCode::OK {
                wrong.push(format!("{path} from {key} with the store up -> {status}"));
            }
            outage.fault_reads_of(key, fault);
            let status = send(&ctx.app, Method::GET, path, "").await.status();
            if status != expected {
                wrong.push(format!("{path} from {key}, {fault:?} -> {status}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    let asked = upstream_paths(&upstream).await;
    assert!(asked.is_empty(), "upstream asked: {asked:?}");
}
