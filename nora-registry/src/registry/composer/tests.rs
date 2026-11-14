// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::*;
use crate::test_helpers::{
    blocklist_file, body_bytes, create_test_context_with_anonymous_read_and_config,
    create_test_context_with_config, send, send_with_headers, upstream_paths, TestContext,
};
use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::json;
use wiremock::matchers::{header as wm_header, method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ── names and versions ─────────────────────────────────────────────────────────

#[test]
fn package_names_are_composer_s() {
    for (vendor, package) in [
        ("monolog", "monolog"),
        ("symfony", "polyfill-php80"),
        ("a1", "b"),
        ("my.vendor", "my_pkg"),
        ("vendor", "double--dash"),
        ("0", "0"),
    ] {
        assert!(is_valid_package_name(vendor, package), "{vendor}/{package}");
    }
    for (vendor, package) in [
        ("Monolog", "monolog"),
        ("vendor", "Pkg"),
        ("", "pkg"),
        ("vendor", ""),
        ("-vendor", "pkg"),
        ("vendor", "pkg-"),
        ("ven..dor", "pkg"),
        ("vendor", "a---b"),
        ("ven--dor", "pkg"),
        ("vendor", "p/kg"),
        ("vendor", "pk g"),
        ("vendor", ".."),
        ("vendor", "pkg~dev"),
    ] {
        assert!(
            !is_valid_package_name(vendor, package),
            "{vendor}/{package}"
        );
    }
}

/// Expected values are what Composer's `VersionParser::normalize` returns for each.
#[test]
fn versions_normalize_as_composer_normalizes_them() {
    let table = [
        ("1.0.0", Some("1.0.0.0")),
        ("v1.2", Some("1.2.0.0")),
        ("V1.2", Some("1.2.0.0")),
        ("1", Some("1.0.0.0")),
        ("1.2.3.4", Some("1.2.3.4")),
        ("1.2.3.4.5", None),
        ("00.01.03", Some("00.01.03.0")),
        ("1.0.0-beta.2", Some("1.0.0.0-beta2")),
        ("1.0.0beta2", Some("1.0.0.0-beta2")),
        ("v8.2.0-BETA1", Some("8.2.0.0-beta1")),
        ("1.0.0-RC1", Some("1.0.0.0-RC1")),
        ("1.0.0rc1", Some("1.0.0.0-RC1")),
        ("1.0.0-a", Some("1.0.0.0-alpha")),
        ("1.0.0-alpha1.2", Some("1.0.0.0-alpha1.2")),
        ("1.0.0-b3", Some("1.0.0.0-beta3")),
        ("1.0.0-p1", Some("1.0.0.0-patch1")),
        ("1.0.0-pl2", Some("1.0.0.0-patch2")),
        ("1.0.0.beta", Some("1.0.0.0-beta")),
        ("1.0.0-stable", Some("1.0.0.0")),
        ("1.0-dev", Some("1.0.0.0-dev")),
        ("1.0.0_dev", Some("1.0.0.0-dev")),
        ("1.0.0-beta-dev", Some("1.0.0.0-beta-dev")),
        ("1.0.0+build.5", Some("1.0.0.0")),
        ("dev-main", Some("dev-main")),
        ("dev-Feature/X", Some("dev-Feature/X")),
        ("1.x-dev", None),
        ("123456.0", None),
        ("1.0.0-bogus", None),
        ("abc", None),
        ("", None),
        ("1.0.0+", None),
    ];
    for (version, expected) in table {
        assert_eq!(
            normalize_version(version).as_deref(),
            expected,
            "{version:?}"
        );
    }
}

#[test]
fn hosted_versions_sort_newest_first() {
    let mut versions = vec![
        "1.0.0.0",
        "1.10.0.0",
        "1.2.0.0",
        "2.0.0.0-beta1",
        "2.0.0.0-RC1",
        "2.0.0.0",
        "2.0.0.0-alpha3",
        "1.0.0.0-patch1",
    ];
    versions.sort_by(|a, b| version_order(b, a));
    assert_eq!(
        versions,
        [
            "2.0.0.0",
            "2.0.0.0-RC1",
            "2.0.0.0-beta1",
            "2.0.0.0-alpha3",
            "1.10.0.0",
            "1.2.0.0",
            "1.0.0.0-patch1",
            "1.0.0.0",
        ]
    );
}

#[test]
fn a_version_stands_in_a_path_as_written_or_as_a_digest() {
    for plain in ["1.0.0", "v8.2.0-BETA1", "dev-main", "1.x-dev", "2.0_rc"] {
        assert_eq!(version_segment(plain), plain);
        assert!(is_version_segment(plain));
    }
    for odd in [
        "dev-feature/x",
        "1.0+build",
        "..",
        ".hidden",
        "a b",
        "1..2",
        "",
    ] {
        let segment = version_segment(odd);
        assert!(segment.starts_with('~') && segment.len() == 33, "{odd}");
        assert!(is_version_segment(&segment), "{odd}");
        assert!(!is_version_segment(odd), "{odd}");
    }
    assert_ne!(version_segment("dev-a/b"), version_segment("dev-a/c"));
    assert!(!is_version_segment("~xyz"));
    assert!(!is_version_segment("a/b"));
}

// ── minified metadata ──────────────────────────────────────────────────────────

#[test]
fn a_minified_list_expands_and_minifies_back() {
    let minified = vec![
        json!({"name": "a/b", "version": "2.0.0", "require": {"php": ">=8"}, "dist": {"url": "u2", "type": "zip"}, "extra": {"x": 1}}),
        json!({"version": "1.1.0", "dist": {"url": "u11", "type": "zip"}}),
        json!({"version": "1.0.0", "require": "__unset", "dist": {"url": "u10", "type": "zip"}}),
    ];
    let expanded = expand(&minified);
    assert_eq!(expanded.len(), 3);
    assert_eq!(expanded[1]["name"], "a/b");
    assert_eq!(expanded[1]["require"], json!({"php": ">=8"}));
    assert_eq!(expanded[1]["extra"], json!({"x": 1}));
    assert!(!expanded[2].contains_key("require"));
    assert_eq!(expanded[2]["name"], "a/b");
    assert_eq!(minify(&expanded), minified);
    assert_eq!(expand(&minify(&expanded)), expanded);
}

fn upstream_doc(dist_host: &str) -> Value {
    json!({
        "minified": "composer/2.0",
        "packages": {
            "acme/lib": [
                {"name": "acme/lib", "version": "2.0.0", "time": "2026-01-02T03:04:05+00:00",
                 "source": {"type": "git", "url": "https://github.com/acme/lib.git", "reference": "bbbb"},
                 "dist": {"type": "zip", "url": format!("{dist_host}/archives/lib-2.0.0.zip"), "reference": "bbbb", "shasum": ""}},
                // Same dist as 2.0.0, inherited: the minified form leaves it out.
                {"version": "2.0.0-RC1"},
                {"version": "1.0.0",
                 "source": {"type": "git", "url": "https://github.com/acme/lib.git", "reference": "aaaa"},
                 "dist": {"type": "zip", "url": format!("{dist_host}/archives/lib-1.0.0.zip"), "reference": "aaaa", "shasum": "", "mirrors": [{"url": "https://mirror.example/%package%", "preferred": true}]}}
            ]
        },
        "security-advisories": [{"advisoryId": "PKSA-1", "affectedVersions": "<1.0.1"}]
    })
}

#[test]
fn every_dist_url_points_at_nora_and_the_listing_finds_the_original() {
    let raw = serde_json::to_vec(&upstream_doc("https://up.example")).unwrap();
    let served = rewrite_document(&raw, "acme/lib", "http://nora:4000", false, true).unwrap();
    let doc: Value = serde_json::from_slice(&served).unwrap();
    assert_eq!(doc["minified"], MINIFIED, "stays minified");
    assert_eq!(doc["security-advisories"][0]["advisoryId"], "PKSA-1");
    let versions = versions_of(&doc, "acme/lib");
    let urls: Vec<&str> = versions
        .iter()
        .map(|v| v["dist"]["url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        [
            "http://nora:4000/composer/dists/acme/lib/2.0.0/bbbb.zip",
            // An inherited dist names its own version, not the one it was inherited from.
            "http://nora:4000/composer/dists/acme/lib/2.0.0-RC1/bbbb.zip",
            "http://nora:4000/composer/dists/acme/lib/1.0.0/aaaa.zip",
        ]
    );
    assert!(versions[2]["dist"].get("mirrors").is_none());
    assert!(versions.iter().all(|v| v.contains_key("source")));
    for (version, url) in [
        ("2.0.0", "https://up.example/archives/lib-2.0.0.zip"),
        ("2.0.0-RC1", "https://up.example/archives/lib-2.0.0.zip"),
        ("1.0.0", "https://up.example/archives/lib-1.0.0.zip"),
    ] {
        let token = if version == "1.0.0" { "aaaa" } else { "bbbb" };
        let listed = find_listed(&raw, "acme/lib", version, token, "zip").unwrap();
        assert_eq!(
            (listed.version.as_str(), listed.url.as_str()),
            (version, url)
        );
    }
    assert_eq!(find_listed(&raw, "acme/lib", "1.0.0", "bbbb", "zip"), None);
    assert_eq!(find_listed(&raw, "acme/lib", "1.0.0", "aaaa", "tar"), None);
    assert_eq!(
        find_listed(&raw, "acme/other", "1.0.0", "aaaa", "zip"),
        None
    );
}

#[test]
fn without_keep_source_a_version_served_through_nora_has_no_source() {
    let mut doc = upstream_doc("https://up.example");
    // A version with no dist keeps its source: it has no other way to install.
    doc["packages"]["acme/lib"]
        .as_array_mut()
        .unwrap()
        .push(json!({"version": "0.1.0", "dist": "__unset", "source": {"type": "git", "url": "https://github.com/acme/lib.git", "reference": "cccc"}}));
    let raw = serde_json::to_vec(&doc).unwrap();
    let served = rewrite_document(&raw, "acme/lib", "http://nora", false, false).unwrap();
    let versions = versions_of(&serde_json::from_slice(&served).unwrap(), "acme/lib");
    assert!(versions[..3].iter().all(|v| !v.contains_key("source")));
    assert!(versions[3].contains_key("source") && !versions[3].contains_key("dist"));
}

#[test]
fn a_document_serves_the_package_it_is_for_alone() {
    let mut doc = upstream_doc("https://up.example");
    doc["packages"]["corp/internal"] = json!([{"name": "corp/internal", "version": "9.9.9",
        "dist": {"type": "zip", "url": "https://evil.example/x.zip", "reference": "eeee"}}]);
    let raw = serde_json::to_vec(&doc).unwrap();
    let served = rewrite_document(&raw, "acme/lib", "http://nora", false, true).unwrap();
    let served: Value = serde_json::from_slice(&served).unwrap();
    let names: Vec<&String> = served["packages"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["acme/lib"]);
}

#[test]
fn a_dist_without_a_plain_reference_is_named_by_its_url() {
    let dist = json!({"type": "zip", "url": "https://x/y.zip", "reference": "v1.2.3"});
    let token = dist_token(dist.as_object().unwrap()).unwrap();
    assert_eq!(token.len(), 40);
    assert!(is_plain_token(&token));
    let dist = json!({"type": "ZIP!", "reference": "abc"});
    assert_eq!(dist_ext(dist.as_object().unwrap()), "bin");
    assert_eq!(dist_token(&Map::new()), None);
}

#[test]
fn an_upstream_root_says_where_its_documents_are() {
    let base = "https://repo.example.com/acme";
    let default = parse_root(base, None);
    assert_eq!(
        default.metadata_url,
        "https://repo.example.com/acme/p2/%package%.json"
    );
    assert_eq!(default.advisories_url, None);
    let packagist = br#"{"metadata-url":"https://repo.packagist.org/p2/%package%.json","security-advisories":{"metadata":true,"api-url":"https://packagist.org/api/security-advisories/"}}"#;
    let root = parse_root("https://repo.packagist.org", Some(packagist));
    assert_eq!(
        root.p2_url("a/b", true),
        "https://repo.packagist.org/p2/a/b~dev.json"
    );
    assert_eq!(
        root.advisories_url.as_deref(),
        Some("https://packagist.org/api/security-advisories/")
    );
    // A path from the root of the upstream's host, as Composer reads it.
    let private = br#"{"metadata-url":"/acme/p2/%package%.json"}"#;
    assert_eq!(
        parse_root(base, Some(private)).metadata_url,
        "https://repo.example.com/acme/p2/%package%.json"
    );
    for odd in [
        &br#"{"metadata-url":"p2/%package%.json"}"#[..],
        br#"{"metadata-url":"//evil.example/%package%"}"#,
        br#"{"metadata-url":"/p2/fixed.json"}"#,
        b"not json",
    ] {
        assert_eq!(parse_root(base, Some(odd)), default);
    }
}

// ── the proxy against a mock upstream ──────────────────────────────────────────

const ZIP_1: &[u8] = b"PK\x03\x04 archive one";

fn sha1_hex(data: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(data))
}

/// A Composer repository with `acme/lib` 1.0.0 (archive on the same host, sha1 given).
async fn upstream() -> MockServer {
    let up = MockServer::start().await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    up
}

async fn mount_lib(up: &MockServer, dist_host: &str, shasum: Option<&str>) {
    let doc = json!({
        "packages": {"acme/lib": [
            {"name": "acme/lib", "version": "1.0.0", "time": "2020-01-01T00:00:00+00:00",
             "dist": {"type": "zip", "url": format!("{dist_host}/archives/lib-1.0.0.zip"), "reference": "aaaa", "shasum": shasum.unwrap_or("")}}
        ]}
    });
    Mock::given(wm_method("GET"))
        .and(wm_path("/packages.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [],
            "metadata-url": "/p2/%package%.json",
            "security-advisories": {"metadata": true, "api-url": format!("{}/api/security-advisories/", up.uri())}
        })))
        .mount(up)
        .await;
    Mock::given(wm_method("GET"))
        .and(wm_path("/p2/acme/lib.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v1\"")
                .insert_header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
                .set_body_json(doc),
        )
        .mount(up)
        .await;
    Mock::given(wm_method("GET"))
        .and(wm_path("/archives/lib-1.0.0.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .mount(up)
        .await;
}

fn proxy_ctx(up: &str, customize: impl FnOnce(&mut crate::config::Config)) -> TestContext {
    let up = up.to_string();
    create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(up);
        customize(c);
    })
}

fn base(ctx: &TestContext) -> String {
    crate::registry::nora_base_url(&ctx.state)
}

async fn json_of(resp: Response) -> Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

fn count(paths: &[String], path: &str) -> usize {
    paths.iter().filter(|p| *p == path).count()
}

#[tokio::test]
async fn the_root_points_composer_at_nora() {
    let ctx = proxy_ctx("http://127.0.0.1:1", |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/packages.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let root = json_of(resp).await;
    let base = base(&ctx);
    assert_eq!(
        root["metadata-url"],
        format!("{base}/composer/p2/%package%.json")
    );
    assert_eq!(
        root["security-advisories"]["api-url"],
        format!("{base}/composer/api/security-advisories/")
    );
    assert!(
        root.get("available-packages").is_none(),
        "an upstream may have any package"
    );
}

#[tokio::test]
async fn a_package_installs_through_the_proxy_and_its_archive_is_cached() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::LAST_MODIFIED],
        "Wed, 01 Jan 2020 00:00:00 GMT"
    );
    let doc = json_of(resp).await;
    let url = doc["packages"]["acme/lib"][0]["dist"]["url"]
        .as_str()
        .unwrap()
        .to_string();
    let path = url.strip_prefix(&base(&ctx)).unwrap().to_string();
    assert_eq!(path, "/composer/dists/acme/lib/1.0.0/aaaa.zip");

    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, &path, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/zip");
        assert_eq!(&body_bytes(resp).await[..], ZIP_1);
    }
    let sent = upstream_paths(&up).await;
    assert_eq!(count(&sent, "/archives/lib-1.0.0.zip"), 1, "{sent:?}");
    assert_eq!(
        count(&sent, "/p2/acme/lib.json"),
        1,
        "fresh copy served: {sent:?}"
    );
    let sidecar = ctx
        .state
        .storage
        .get("composer/dists/acme/lib/1.0.0/aaaa.zip.sha256")
        .await
        .unwrap();
    assert_eq!(
        &sidecar[..],
        hex::encode(sha2::Sha256::digest(ZIP_1)).as_bytes()
    );

    // A resumed download.
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        &path,
        vec![("range", "bytes=0-1")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body_bytes(resp).await[..], b"PK");
}

#[tokio::test]
async fn an_archive_the_metadata_does_not_list_is_never_asked_for() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    for path in [
        "/composer/dists/acme/lib/1.0.0/bbbb.zip",
        "/composer/dists/acme/lib/9.9.9/aaaa.zip",
        "/composer/dists/acme/lib/1.0.0/aaaa.tar",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let sent = upstream_paths(&up).await;
    assert!(
        !sent.iter().any(|p| p.starts_with("/archives/")),
        "{sent:?}"
    );
    // Fresh metadata is believed: made-up URLs cost no metadata request either, and a
    // release is not looked for among the branches.
    assert_eq!(count(&sent, "/p2/acme/lib.json"), 1, "{sent:?}");
    assert_eq!(count(&sent, "/p2/acme/lib~dev.json"), 0, "{sent:?}");
}

#[tokio::test]
async fn bad_paths_are_refused_before_storage_or_upstream() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    for path in [
        "/composer/p2/Acme/lib.json",
        "/composer/p2/acme/li%20b.json",
        "/composer/p2/acme/..json",
        "/composer/dists/acme/lib/1.0.0/aa%2Faa.zip",
        "/composer/dists/acme/lib/%2E%2E/aaaa.zip",
        "/composer/dists/acme/lib/1.0.0/aaaa.ZIP",
        "/composer/dists/acme/lib/~zz/aaaa.zip",
        "/composer/dists/acme/Lib/1.0.0/aaaa.zip",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "{path}: {}",
            resp.status()
        );
    }
    assert!(upstream_paths(&up).await.is_empty());
}

#[tokio::test]
async fn an_archive_that_does_not_match_its_sha1_is_refused_and_not_cached() {
    let up = MockServer::start().await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(b"other bytes"))).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(ctx
        .state
        .storage
        .get("composer/dists/acme/lib/1.0.0/aaaa.zip")
        .await
        .is_err());
}

#[tokio::test]
async fn an_archive_asked_before_its_metadata_fetches_the_metadata_first() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
}

#[tokio::test]
async fn stale_metadata_is_revalidated_and_a_304_keeps_the_copy() {
    let up = MockServer::start().await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .and(wm_header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&up)
        .await;
    mount_lib(&up, &up.uri(), None).await;
    let ctx = proxy_ctx(&up.uri(), |c| c.composer.metadata_ttl = 0);
    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc = json_of(resp).await;
        assert_eq!(doc["packages"]["acme/lib"][0]["version"], "1.0.0");
    }
    let requests = up.received_requests().await.unwrap();
    let p2: Vec<&Request> = requests
        .iter()
        .filter(|r| r.url.path() == "/p2/acme/lib.json")
        .collect();
    assert_eq!(p2.len(), 2);
    assert!(p2[0].headers.get("if-none-match").is_none());
    assert_eq!(p2[1].headers["if-none-match"], "\"v1\"");
}

#[tokio::test]
async fn a_client_revalidating_its_own_copy_gets_a_304() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    let last_modified = resp.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_string();
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/composer/p2/acme/lib.json",
        vec![("if-modified-since", &last_modified)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert!(body_bytes(resp).await.is_empty());
}

#[tokio::test]
async fn metadata_is_served_stale_when_the_upstream_is_down() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |c| c.composer.metadata_ttl = 0);
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    up.reset().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&up)
        .await;
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-nora-stale"], "true");
    // Without a copy the outage is a gateway failure, not "no such package".
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/other.json", "").await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_package_no_upstream_has_is_a_404() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/missing.json", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_first_upstream_that_has_a_package_serves_it_with_its_own_credential() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    mount_lib(&second, &second.uri(), None).await;
    let ctx = create_test_context_with_config(|c| {
        c.composer.enabled = true;
        c.composer.proxy = None;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(first.uri()),
            crate::config::ComposerProxyEntry::Full(crate::config::ComposerProxy {
                url: second.uri(),
                auth: Some(crate::secrets::ProtectedString::new("bot:s3cret".into())),
            }),
        ];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(upstream_paths(&first)
        .await
        .contains(&"/p2/acme/lib.json".to_string()));
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("bot:s3cret")
    );
    for request in second.received_requests().await.unwrap() {
        assert_eq!(
            request.headers["authorization"],
            expected,
            "{}",
            request.url.path()
        );
    }
    for request in first.received_requests().await.unwrap() {
        assert!(request.headers.get("authorization").is_none());
    }
}

#[tokio::test]
async fn a_redirect_off_the_upstream_s_origin_carries_no_credential() {
    let up = MockServer::start().await;
    let storage = MockServer::start().await;
    Mock::given(wm_path("/archives/lib-1.0.0.zip"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/blob/lib.zip", storage.uri())),
        )
        .with_priority(1)
        .mount(&up)
        .await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    Mock::given(wm_path("/blob/lib.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .mount(&storage)
        .await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.composer.proxy_auth = Some(crate::secrets::ProtectedString::new("bot:s3cret".into()));
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
    let hop = &storage.received_requests().await.unwrap()[0];
    assert!(hop.headers.get("authorization").is_none());
    let asked = up
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/archives/lib-1.0.0.zip")
        .unwrap();
    assert!(asked.headers.get("authorization").is_some());
}

#[tokio::test]
async fn an_archive_on_another_host_gets_no_upstream_credential() {
    let up = MockServer::start().await;
    let host = MockServer::start().await;
    mount_lib(&up, &host.uri(), None).await;
    Mock::given(wm_path("/archives/lib-1.0.0.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .mount(&host)
        .await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.composer.proxy_auth = Some(crate::secrets::ProtectedString::new("bot:s3cret".into()));
        c.composer.github_token = Some(crate::secrets::ProtectedString::new("ghp_x".into()));
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let asked = &host.received_requests().await.unwrap()[0];
    assert!(asked.headers.get("authorization").is_none());
}

#[tokio::test]
async fn the_github_token_goes_to_github_s_api_host_alone() {
    let ctx = create_test_context_with_config(|c| {
        c.composer.github_token = Some(crate::secrets::ProtectedString::new("ghp_tok".into()));
    });
    let up = crate::config::ComposerProxyEntry::Simple("https://repo.packagist.org".into());
    let header = |url: &str| {
        dist_auth(&ctx.state, &up, url)
            .map(|a| a.header_value().unwrap().to_str().unwrap().to_string())
    };
    assert_eq!(
        header("https://api.github.com/repos/a/b/zipball/0123").as_deref(),
        Some("Bearer ghp_tok")
    );
    for url in [
        "http://api.github.com/repos/a/b/zipball/0123",
        "https://codeload.github.com/a/b/legacy.zip/0123",
        "https://api.github.com.evil.example/x",
        "https://gitlab.com/api/v4/x",
    ] {
        assert_eq!(header(url), None, "{url}");
    }
}

// ── curation and namespace isolation ───────────────────────────────────────────

#[tokio::test]
async fn a_blocked_package_is_refused_and_nothing_is_fetched() {
    let up = upstream().await;
    let (_dir, blocklist) = blocklist_file("composer", "ACME/lib");
    let ctx = proxy_ctx(&up.uri(), move |c| {
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.blocklist_path = Some(blocklist);
    });
    for path in [
        "/composer/p2/acme/lib.json",
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let sent = upstream_paths(&up).await;
    assert!(
        !sent.iter().any(|p| p.starts_with("/archives/")),
        "{sent:?}"
    );
}

#[tokio::test]
async fn a_version_rule_holds_for_every_spelling_of_the_version() {
    let up = upstream().await;
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("blocklist.json");
    std::fs::write(
        &path,
        r#"{"version": 1, "rules": [{"registry": "composer", "name": "acme/lib", "version": "v1.0", "reason": "bad"}]}"#,
    )
    .unwrap();
    let blocklist = path.to_string_lossy().into_owned();
    let ctx = proxy_ctx(&up.uri(), move |c| {
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.blocklist_path = Some(blocklist);
    });
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the package itself is not blocked"
    );
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_release_younger_than_the_minimum_age_is_refused() {
    let up = MockServer::start().await;
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    Mock::given(wm_path("/p2/acme/fresh.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/fresh": [
            {"name": "acme/fresh", "version": "1.0.0", "time": now,
             "dist": {"type": "zip", "url": format!("{}/fresh.zip", up.uri()), "reference": "ffff"}}
        ]}})))
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/fresh/1.0.0/ffff.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(!upstream_paths(&up)
        .await
        .contains(&"/fresh.zip".to_string()));
}

#[tokio::test]
async fn an_internal_package_is_never_asked_of_an_upstream() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.curation.internal_namespaces = vec!["acme/*".to_string()];
    });
    for path in [
        "/composer/p2/acme/lib.json",
        "/composer/p2/acme/lib~dev.json",
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(upstream_paths(&up).await.is_empty());

    // Uploaded, it is served.
    let zip = upload_zip("acme/lib", None);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/2.0.0",
        zip,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(upstream_paths(&up).await.is_empty());
}

// ── hosted ─────────────────────────────────────────────────────────────────────

fn upload_zip(name: &str, version: Option<&str>) -> Vec<u8> {
    let mut manifest = json!({"name": name, "type": "library", "require": {"php": ">=8.1"}});
    if let Some(v) = version {
        manifest["version"] = json!(v);
    }
    let manifest = manifest.to_string();
    build_test_zip(&[
        ("pkg-1a2b/", b"", false),
        ("pkg-1a2b/composer.json", manifest.as_bytes(), true),
        ("pkg-1a2b/src/A.php", b"<?php", true),
    ])
}

fn hosted_ctx() -> TestContext {
    create_test_context_with_config(|c| c.composer.enabled = true)
}

#[tokio::test]
async fn an_uploaded_package_is_listed_and_downloads_with_its_sha1() {
    let ctx = hosted_ctx();
    let zip = upload_zip("acme/greeter", Some("v1.0.0"));
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/greeter/1.0.0",
        zip.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = json_of(resp).await;
    let sha1 = sha1_hex(&zip);
    assert_eq!(created["dist"]["shasum"], sha1);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/greeter/2.0.0-beta1",
        upload_zip("acme/greeter", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/greeter.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key(header::LAST_MODIFIED));
    let doc = json_of(resp).await;
    let versions = versions_of(&doc, "acme/greeter");
    let listed: Vec<&str> = versions
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["2.0.0-beta1", "1.0.0"]);
    let v1 = &versions[1];
    assert_eq!(v1["name"], "acme/greeter");
    assert_eq!(v1["require"]["php"], ">=8.1");
    assert_eq!(v1["dist"]["shasum"], sha1);
    assert_eq!(v1["dist"]["type"], "zip");
    let url = v1["dist"]["url"].as_str().unwrap();
    assert_eq!(created["dist"]["url"], url);
    let path = url.strip_prefix(&base(&ctx)).unwrap().to_string();
    assert_eq!(
        path,
        format!("/composer/dists/acme/greeter/1.0.0.0/{sha1}.zip")
    );

    let resp = send(&ctx.app, Method::GET, &path, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], &zip[..]);

    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/p2/acme/greeter~dev.json",
        "",
    )
    .await;
    assert_eq!(
        json_of(resp).await,
        json!({"packages": {"acme/greeter": []}})
    );

    // Another reference, or the same one under another version, is not this archive.
    for wrong in [
        "/composer/dists/acme/greeter/1.0.0.0/0000.zip".to_string(),
        format!("/composer/dists/acme/greeter/9.0.0.0/{sha1}.zip"),
        format!("/composer/dists/acme/greeter/1.0.0.0/{sha1}.tar"),
    ] {
        let resp = send(&ctx.app, Method::GET, &wrong, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{wrong}");
    }

    // A tampered archive is never served.
    ctx.state
        .storage
        .put("composer/hosted/acme/greeter/dists/1.0.0.0.zip", b"evil")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, &path, "").await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn an_upload_is_checked_before_anything_is_stored() {
    let ctx = hosted_ctx();
    let good = upload_zip("acme/greeter", None);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/greeter/1.0.0",
        good.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let cases: Vec<(&str, Vec<u8>, StatusCode)> = vec![
        // The same version, spelled otherwise.
        (
            "/composer/packages/upload/acme/greeter/v1.0",
            good.clone(),
            StatusCode::CONFLICT,
        ),
        (
            "/composer/packages/upload/acme/other/1.0.1",
            good.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.0.1",
            upload_zip("acme/greeter", Some("1.0.2")),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/dev-main",
            good.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.x-dev",
            good.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/latest",
            good.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/Acme/greeter/1.0.1",
            good.clone(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.0.1",
            b"not a zip".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.0.1",
            build_test_zip(&[("README", b"x", false)]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.0.1",
            build_test_zip(&[("composer.json", b"[1]", false)]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/composer/packages/upload/acme/greeter/1.0.1",
            build_test_zip(&[("composer.json", b"{}", false)]),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (path, body, status) in cases {
        let resp = send(&ctx.app, Method::PUT, path, body).await;
        assert_eq!(resp.status(), status, "{path}");
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/packages/upload/acme/greeter/1.0.0",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let keys = ctx.state.storage.list("composer/").await.unwrap();
    assert!(
        keys.iter()
            .all(|k| k.starts_with("composer/hosted/acme/greeter/")),
        "{keys:?}"
    );
    let doc =
        json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/greeter.json", "").await).await;
    assert_eq!(versions_of(&doc, "acme/greeter").len(), 1);
}

#[tokio::test]
async fn a_hosted_package_is_never_merged_with_an_upstream() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/3.0.0",
        upload_zip("acme/lib", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await).await;
    let versions: Vec<String> = versions_of(&doc, "acme/lib")
        .iter()
        .map(|v| v["version"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(versions, ["3.0.0"]);
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib~dev.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let sent = upstream_paths(&up).await;
    assert!(
        !sent
            .iter()
            .any(|p| p.contains("acme/lib") || p.starts_with("/archives/")),
        "{sent:?}"
    );
}

#[tokio::test]
async fn a_hosted_only_root_names_its_packages() {
    let ctx = hosted_ctx();
    send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/b/1.0.0",
        upload_zip("acme/b", None),
    )
    .await;
    send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/a/1.0.0",
        upload_zip("acme/a", None),
    )
    .await;
    let root = json_of(send(&ctx.app, Method::GET, "/composer/packages.json", "").await).await;
    assert_eq!(root["available-packages"], json!(["acme/a", "acme/b"]));
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/c.json", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_hosted_metadata_is_rebuilt_from_the_versions() {
    let ctx = hosted_ctx();
    send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/a/1.0.0",
        upload_zip("acme/a", None),
    )
    .await;
    ctx.state
        .storage
        .delete("composer/hosted/acme/a/p2.json")
        .await
        .unwrap();
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/a.json", "").await).await;
    assert_eq!(versions_of(&doc, "acme/a").len(), 1);
    assert!(ctx
        .state
        .storage
        .stat("composer/hosted/acme/a/p2.json")
        .await
        .is_some());
}

#[tokio::test]
async fn stored_versions_list_hosted_and_cached_archives() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/own/1.2.0",
        upload_zip("acme/own", None),
    )
    .await;
    let cached = stored_versions(&ctx.state.storage, "acme/lib").await;
    assert_eq!(cached.len(), 1);
    assert_eq!(
        (cached[0].version.as_str(), cached[0].hosted),
        ("1.0.0", false)
    );
    let own = stored_versions(&ctx.state.storage, "acme/own").await;
    assert_eq!((own[0].version.as_str(), own[0].hosted), ("1.2.0", true));
    let keys = ctx.state.storage.list("composer/").await.unwrap();
    let mut packages: Vec<String> = keys.iter().filter_map(|k| package_of_archive(k)).collect();
    packages.sort();
    assert_eq!(packages, ["acme/lib", "acme/own"]);
}

// ── security advisories ────────────────────────────────────────────────────────

#[tokio::test]
async fn advisories_are_asked_for_public_names_only() {
    let up = upstream().await;
    Mock::given(wm_method("POST"))
        .and(wm_path("/api/security-advisories/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"advisories": {"vendor/public": [{"advisoryId": "PKSA-1"}]}}),
            ),
        )
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.curation.internal_namespaces = vec!["corp/*".to_string()];
    });
    send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/own/1.0.0",
        upload_zip("acme/own", None),
    )
    .await;
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        "packages%5B0%5D=vendor%2Fpublic&packages%5B1%5D=acme%2Fown&packages%5B2%5D=corp%2Fsecret&updatedSince=100",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_of(resp).await["advisories"]["vendor/public"][0]["advisoryId"],
        "PKSA-1"
    );
    let posted = up
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.method.as_str() == "POST")
        .unwrap();
    let body = String::from_utf8(posted.body.clone()).unwrap();
    assert!(body.contains("vendor%2Fpublic"), "{body}");
    assert!(body.contains("updatedSince=100"), "{body}");
    assert!(!body.contains("acme") && !body.contains("corp"), "{body}");

    // Private names alone are answered here, never upstream.
    up.reset().await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/api/security-advisories?packages[]=acme/own&packages[]=corp/x",
        "",
    )
    .await;
    assert_eq!(json_of(resp).await, json!({"advisories": {}}));
    assert!(upstream_paths(&up).await.is_empty());
}

#[tokio::test]
async fn composer_audit_is_a_read_under_anonymous_read() {
    let up = upstream().await;
    let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "pw")], |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(up.uri());
    });
    let resp = send(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/x/1.0.0",
        upload_zip("acme/x", None),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an upload is a write"
    );
}
