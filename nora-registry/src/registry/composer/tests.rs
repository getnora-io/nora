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
    let served =
        rewrite_document(&raw, "acme/lib", "http://nora:4000", false, Sources::Keep).unwrap();
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
    let served = rewrite_document(&raw, "acme/lib", "http://nora", false, Sources::Drop).unwrap();
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
    let served = rewrite_document(&raw, "acme/lib", "http://nora", false, Sources::Keep).unwrap();
    let served: Value = serde_json::from_slice(&served).unwrap();
    let names: Vec<&String> = served["packages"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["acme/lib"]);
}

/// A document names a package as Composer reads it (`isset($response['packages'][$name])`):
/// an empty version list names it, so the upstream that sent it has the package.
#[test]
fn a_document_names_a_package_as_composer_reads_it() {
    let names = |body: &str| names_package(body.as_bytes(), "acme/lib");
    assert!(names(r#"{"packages":{"acme/lib":[]}}"#));
    assert!(names(r#"{"packages":{"acme/lib":[{"version":"1.0.0"}]}}"#));
    assert!(!names(r#"{"packages":{"acme/other":[]}}"#));
    assert!(!names(r#"{"packages":{"acme/lib":null}}"#));
    assert!(!names(r#"{"packages":[]}"#));
    assert!(!names("not json"));
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
    // The served document is NORA's rewrite: dated no earlier than the configuration that
    // shapes it, whatever the upstream's 2020 date.
    assert_eq!(
        resp.headers()[header::LAST_MODIFIED],
        http_date(ctx.state.curation().loaded_at as u64).as_str()
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

// ── If-Modified-Since is a date, not a string (#1315) ─────────────────────────────────

/// `Sun, 22 Nov 2026 08:00:00 GMT` in RFC 850 form: `Sunday, 22-Nov-26 08:00:00 GMT`.
fn rfc850(imf: &str) -> String {
    let days = [
        ("Mon", "Monday"),
        ("Tue", "Tuesday"),
        ("Wed", "Wednesday"),
        ("Thu", "Thursday"),
        ("Fri", "Friday"),
        ("Sat", "Saturday"),
        ("Sun", "Sunday"),
    ];
    let f: Vec<&str> = imf.split(' ').collect();
    let day = days
        .iter()
        .find(|(short, _)| f[0] == format!("{short},"))
        .unwrap()
        .1;
    format!("{day}, {}-{}-{} {} GMT", f[1], f[2], &f[3][2..], f[4])
}

/// The same date in asctime form: `Sun Nov 22 08:00:00 2026` (day padded with a space).
fn asctime(imf: &str) -> String {
    let f: Vec<&str> = imf.split(' ').collect();
    let day: u32 = f[1].parse().unwrap();
    format!("{} {} {day:>2} {} {}", &f[0][..3], f[2], f[4], f[3])
}

fn imf(t: std::time::SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    crate::datetime::UtcTime::from_unix(secs, 0)
        .unwrap()
        .http_date()
}

async fn proxied_last_modified(ctx: &TestContext) -> String {
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    resp.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_string()
}

async fn revalidate(ctx: &TestContext, since: &str) -> StatusCode {
    send_with_headers(
        &ctx.app,
        Method::GET,
        "/composer/p2/acme/lib.json",
        vec![("if-modified-since", since)],
        "",
    )
    .await
    .status()
}

#[test]
fn if_modified_since_is_one_date_at_or_after_last_modified_and_not_ahead_of_the_clock() {
    let lm = "Sun, 22 Nov 2026 08:00:00 GMT";
    let now = crate::datetime::parse_rfc2822_to_unix(lm).unwrap() + 3600;
    let h = |values: &[&str]| {
        let mut m = HeaderMap::new();
        for v in values {
            m.append(header::IF_MODIFIED_SINCE, v.parse().unwrap());
        }
        m
    };
    let yes = |values: &[&str], lm: &str| not_modified_since(&h(values), lm, now);
    assert!(yes(&[lm], lm));
    assert!(yes(&["Sunday, 22-Nov-26 08:00:00 GMT"], lm));
    assert!(yes(&["Sun Nov 22 08:00:00 2026"], lm));
    assert!(yes(&["Sun, 22 Nov 2026 08:30:00 GMT"], lm));
    assert!(yes(&["Sun, 22 Nov 2026 09:00:00 GMT"], lm), "now itself");
    assert!(
        !yes(&["Sun, 22 Nov 2026 07:59:59 GMT"], lm),
        "before Last-Modified"
    );
    assert!(
        !yes(&["Sun, 22 Nov 2026 09:00:01 GMT"], lm),
        "ahead of the clock"
    );
    assert!(!yes(&[lm, lm], lm), "more than one value");
    assert!(!yes(&["garbage"], lm));
    assert!(!yes(&[], lm));
    // An upstream Last-Modified NORA passes through in RFC 2822 form with an offset.
    assert!(yes(&[lm], "Sun, 22 Nov 2026 08:00:00 +0000"));
}

/// An upstream that dates a new body in asctime form: the served date moves forward with
/// it, so a client holding the older body gets the new one, not a 304. Read as RFC 2822 only,
/// the date fell back to when the configuration was loaded, which is before the client's.
#[test]
fn an_upstream_date_in_another_form_moves_last_modified_forward() {
    let since = crate::datetime::parse_rfc2822_to_unix("Sat, 22 Nov 2025 07:00:00 GMT").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_MODIFIED_SINCE,
        "Sat, 22 Nov 2025 08:00:00 GMT".parse().unwrap(),
    );
    for upstream in [
        "Sat Nov 22 08:30:00 2025",
        "Saturday, 22-Nov-25 08:30:00 GMT",
    ] {
        let resp = metadata_response(
            &headers,
            b"{}".to_vec(),
            Some(upstream.to_string()),
            false,
            since,
        );
        assert_eq!(resp.status(), StatusCode::OK, "{upstream}");
        assert_eq!(resp.headers()[header::LAST_MODIFIED], upstream);
    }
}

/// asctime writes a one-digit day as ` 4` or `04` (RFC 9110 5.6.7, date3); both are dates.
#[test]
fn asctime_with_a_zero_padded_day_is_a_date() {
    let lm = "Tue, 03 Nov 2026 08:00:00 GMT";
    let now = crate::datetime::parse_rfc2822_to_unix(lm).unwrap() + 86_400 * 3;
    for form in ["Wed Nov 04 08:30:00 2026", "Wed Nov  4 08:30:00 2026"] {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MODIFIED_SINCE, form.parse().unwrap());
        assert!(not_modified_since(&headers, lm, now), "{form:?}");
    }
    // An upstream that dates a new body that way moves the served date forward.
    let since = crate::datetime::parse_rfc2822_to_unix("Sun, 01 Nov 2026 07:00:00 GMT").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_MODIFIED_SINCE, lm.parse().unwrap());
    let resp = metadata_response(
        &headers,
        b"{}".to_vec(),
        Some("Wed Nov 04 08:30:00 2026".to_string()),
        false,
        since,
    );
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A leap second (`23:59:60`, which RFC 9110 allows) is later than `23:59:59`. NORA cannot
/// count it, so it is not read as `23:59:59`: a client holding `23:59:59` gets the document.
#[test]
fn a_leap_second_is_not_read_as_the_second_before_it() {
    let since = crate::datetime::parse_rfc2822_to_unix("Sat, 31 Dec 2016 23:58:20 GMT").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_MODIFIED_SINCE,
        "Sat, 31 Dec 2016 23:59:59 GMT".parse().unwrap(),
    );
    let resp = metadata_response(
        &headers,
        b"{}".to_vec(),
        Some("Sat, 31 Dec 2016 23:59:60 GMT".to_string()),
        false,
        since,
    );
    assert_eq!(resp.status(), StatusCode::OK);
}

/// An upstream date NORA cannot read is replaced by the time the configuration was loaded.
/// That date says nothing about the body, so it revalidates only the client that holds that
/// very value, as before #1315; a client holding any other date gets the document.
#[test]
fn an_unreadable_upstream_date_revalidates_only_its_own_value() {
    let since = crate::datetime::parse_rfc2822_to_unix("Sun, 01 Nov 2026 07:00:00 GMT").unwrap();
    let respond = |ims: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MODIFIED_SINCE, ims.parse().unwrap());
        metadata_response(
            &headers,
            b"{}".to_vec(),
            Some("not a date".to_string()),
            false,
            since,
        )
    };
    let later = respond("Tue, 03 Nov 2026 08:00:00 GMT");
    assert_eq!(
        later.status(),
        StatusCode::OK,
        "a later client date is not this body's"
    );
    let own = later.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(own, "Sun, 01 Nov 2026 07:00:00 GMT");
    assert_eq!(respond(&own).status(), StatusCode::NOT_MODIFIED);
}

/// A value that only looks like an HTTP-date is not one, and is ignored.
#[test]
fn a_malformed_date_is_ignored() {
    let lm = "Sun, 22 Nov 2026 08:00:00 GMT";
    let now = crate::datetime::parse_rfc2822_to_unix(lm).unwrap() + 3600;
    for bad in [
        "Sunday, 22-Nov-26X08:30:00 GMT",
        "Sunday, 22-Nov-26 08:30:00 GMTX",
        "Sun Nov 22 08:30:00 2026X",
        "Sun, 22 Nov 2026 08:30:00 UTC",
        "Mon, 22 Nov 2026 08:30:00 GMT",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MODIFIED_SINCE, bad.parse().unwrap());
        assert!(!not_modified_since(&headers, lm, now), "{bad:?}");
    }
}

#[test]
fn the_date_forms_in_these_tests_are_the_ones_rfc_9110_names() {
    let imf = "Sun, 06 Nov 1994 08:49:37 GMT";
    assert_eq!(rfc850(imf), "Sunday, 06-Nov-94 08:49:37 GMT");
    assert_eq!(asctime(imf), "Sun Nov  6 08:49:37 1994");
}

/// RFC 9110 5.6.7: a recipient accepts all three forms of an HTTP-date.
#[tokio::test]
async fn the_same_date_in_rfc_850_or_asctime_form_gets_a_304() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let lm = proxied_last_modified(&ctx).await;
    assert_eq!(
        revalidate(&ctx, &rfc850(&lm)).await,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        revalidate(&ctx, &asctime(&lm)).await,
        StatusCode::NOT_MODIFIED
    );
}

/// RFC 9110 13.1.3: not modified since a date at or after its Last-Modified. A cache that
/// stores the time it fetched sends such a date.
#[tokio::test]
async fn a_date_after_last_modified_and_not_in_the_future_gets_a_304() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let lm = proxied_last_modified(&ctx).await;
    // Leave the second Last-Modified names, so the clock is past it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let now = imf(std::time::SystemTime::now());
    assert_ne!(now, lm);
    assert_eq!(revalidate(&ctx, &now).await, StatusCode::NOT_MODIFIED);
}

/// A date before Last-Modified, a date later than the server's clock, a value that is no
/// date: the document is sent in full.
#[tokio::test]
async fn an_earlier_future_or_invalid_date_gets_the_document() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let _ = proxied_last_modified(&ctx).await;
    let day = std::time::Duration::from_secs(86_400);
    let earlier = imf(std::time::SystemTime::now() - 3650 * day);
    let future = imf(std::time::SystemTime::now() + day);
    for since in [earlier.as_str(), future.as_str(), "yesterday", ""] {
        assert_eq!(revalidate(&ctx, since).await, StatusCode::OK, "{since:?}");
    }
}

/// `If-None-Match`, when sent, decides alone: a stale tag gets the document even with a
/// date that would otherwise give a 304.
#[tokio::test]
async fn if_none_match_still_decides_over_a_matching_date() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let lm = proxied_last_modified(&ctx).await;
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/composer/p2/acme/lib.json",
        vec![("if-modified-since", &lm), ("if-none-match", "\"stale\"")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
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
    // The first upstream is a repository without the package (its root reads, its p2 is a
    // 404); one whose root cannot be read failed, and is not passed over.
    let first = MockServer::start().await;
    mount_root(&first).await;
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
    let now = crate::datetime::UtcTime::now().composer_time();
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
    // Its date: a_hosted_listing_changed_within_its_second_is_never_a_304.
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
    // The release time NORA gives an upload, spelled as it always was (#1282).
    let time = v1["time"].as_str().unwrap();
    let at = crate::datetime::parse_rfc3339_relaxed(time).unwrap();
    assert_eq!(time, at.composer_time(), "{time}");
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

// ── review findings (#1228) ────────────────────────────────────────────────────

#[test]
fn non_ascii_versions_are_rejected_without_panicking() {
    for version in [
        "aéé",
        "déév-x",
        "1.0é",
        "é",
        "v1.é",
        "dev\u{e9}x",
        "1.0-béta",
    ] {
        let outcome = std::panic::catch_unwind(|| normalize_version(version));
        assert!(outcome.is_ok(), "{version:?} panics");
    }
    assert_eq!(normalize_version("aéé"), None);
    assert_eq!(normalize_version("1.0é"), None);
}

#[tokio::test]
async fn a_non_ascii_version_in_an_upload_is_a_400() {
    let ctx = hosted_ctx();
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/a%C3%A9%C3%A9",
        upload_zip("acme/lib", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/1.0.0",
        upload_zip("acme/lib", Some("aéé")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `n` distinct package names as a `composer audit` form body.
fn audit_form(n: usize) -> String {
    (0..n)
        .map(|i| format!("packages%5B{i}%5D=vendor%2Fpkg{i}"))
        .collect::<Vec<_>>()
        .join("&")
}

async fn mount_advisories(up: &MockServer) {
    Mock::given(wm_method("POST"))
        .and(wm_path("/api/security-advisories/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"advisories": {}})))
        .mount(up)
        .await;
}

#[tokio::test]
async fn an_advisories_query_over_the_name_cap_is_refused_unforwarded() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        audit_form(MAX_ADVISORY_NAMES + 1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!upstream_paths(&up)
        .await
        .contains(&"/api/security-advisories/".to_string()));

    // At the cap, a query is answered: Composer itself asks 500 names at a time.
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        audit_form(MAX_ADVISORY_NAMES),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_advisories_query_costs_the_store_at_most_one_lookup_per_name() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let (storage, counts) = crate::test_helpers::op_counting_storage();
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
    });
    let mut cost = Vec::new();
    for n in [1, 400] {
        counts.reset();
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/composer/api/security-advisories/",
            vec![("content-type", "application/x-www-form-urlencoded")],
            audit_form(n),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        cost.push((n, counts.total(), counts.snapshot()));
    }
    assert!(cost[1].1 - cost[0].1 <= 399, "{cost:?}");
}

#[tokio::test]
async fn an_advisories_query_does_not_walk_the_hosted_space() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let (storage, counts) = crate::test_helpers::op_counting_storage();
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
    });
    // A registry with packages of its own: what one query for a public name costs must not
    // grow with them.
    for i in 0..60 {
        for key in ["p2.json", "versions/1.0.0.0.json", "dists/1.0.0.0.zip"] {
            ctx.state
                .storage
                .put(&format!("composer/hosted/acme/pkg{i}/{key}"), b"{}")
                .await
                .unwrap();
        }
    }
    counts.reset();
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        "packages%5B%5D=vendor%2Fpublic",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        counts.listed_keys(),
        0,
        "one public name enumerated the hosted space: {:?}",
        counts.snapshot()
    );
}

#[tokio::test]
async fn a_hosted_name_is_still_never_forwarded() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    assert_eq!(put_lib(&ctx, "1.0.0").await.status(), StatusCode::CREATED);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/api/security-advisories?packages[]=acme/lib&packages[]=vendor/public",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let posted = up
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.method.as_str() == "POST")
        .expect("vendor/public is asked");
    let form = String::from_utf8_lossy(&posted.body).to_string();
    assert!(form.contains("vendor%2Fpublic"), "{form}");
    assert!(!form.contains("acme"), "a hosted name left NORA: {form}");
}

#[tokio::test]
async fn a_repeated_name_is_asked_once() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/api/security-advisories?packages[]=vendor/a&packages[]=VENDOR/A&packages[]=vendor/b&packages[]=vendor/a",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let posted = up
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.method.as_str() == "POST")
        .unwrap();
    let body = String::from_utf8(posted.body.clone()).unwrap();
    assert_eq!(body, "packages%5B%5D=vendor%2Fa&packages%5B%5D=vendor%2Fb");
}

#[tokio::test]
async fn cold_audit_root_failure_is_not_empty_success() {
    let up = MockServer::start().await;
    Mock::given(wm_path("/packages.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        "packages%5B%5D=vendor%2Fpublic",
    )
    .await;
    assert!(
        resp.status().is_server_error(),
        "an outage is not 'no advisories': {}",
        resp.status()
    );
}

#[tokio::test]
async fn an_audit_that_cannot_tell_hosted_names_is_not_empty_success() {
    let up = upstream().await;
    mount_advisories(&up).await;
    let (storage, outage) = crate::test_helpers::outage_storage();
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
    });
    // Whichever way the store is asked about vendor/public — the hosted space or the name.
    outage.fail_listings_of("composer/hosted/");
    outage.fail_listings_of("composer/hosted/vendor/public/");
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/api/security-advisories?packages[]=vendor/public",
        "",
    )
    .await;
    assert!(resp.status().is_server_error(), "{}", resp.status());
}

async fn put_lib(ctx: &TestContext, version: &str) -> Response {
    send(
        &ctx.app,
        Method::PUT,
        &format!("/composer/packages/upload/acme/lib/{version}"),
        upload_zip("acme/lib", None),
    )
    .await
}

#[tokio::test]
async fn failed_p2_write_does_not_acknowledge_an_unlisted_version() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
    });
    assert_eq!(put_lib(&ctx, "1.0.0").await.status(), StatusCode::CREATED);
    outage.fail_writes_of("composer/hosted/acme/lib/p2.json");
    let resp = put_lib(&ctx, "2.0.0").await;
    assert!(
        resp.status().is_server_error(),
        "a version the listing does not hold is not created: {}",
        resp.status()
    );
    outage.end();
    // The retry publishes it, and it is listed.
    assert_eq!(put_lib(&ctx, "2.0.0").await.status(), StatusCode::CREATED);
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await).await;
    let listed: Vec<String> = versions_of(&doc, "acme/lib")
        .iter()
        .map(|v| v["version"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed, ["2.0.0", "1.0.0"]);
}

#[tokio::test]
async fn a_version_left_out_of_a_stale_listing_is_listed_again() {
    let ctx = hosted_ctx();
    assert_eq!(put_lib(&ctx, "1.0.0").await.status(), StatusCode::CREATED);
    let key = "composer/hosted/acme/lib/p2.json";
    let before = ctx.state.storage.get(key).await.unwrap();
    assert_eq!(put_lib(&ctx, "2.0.0").await.status(), StatusCode::CREATED);
    // An upload stopped after its version document, before the listing.
    ctx.state.storage.put(key, &before).await.unwrap();
    assert_eq!(put_lib(&ctx, "2.0.0").await.status(), StatusCode::CONFLICT);
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await).await;
    assert_eq!(versions_of(&doc, "acme/lib").len(), 2, "{doc}");
}

#[tokio::test]
async fn existing_version_survives_stat_failure() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
    });
    let first = upload_zip("acme/lib", None);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/1.0.0",
        first.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // The same version, other bytes: a valid upload the version's immutability refuses.
    let second = upload_zip("acme/lib", Some("1.0.0"));
    assert_ne!(second, first);
    let version_doc = "composer/hosted/acme/lib/versions/1.0.0.0.json";
    outage.fail_stats_of(version_doc);
    outage.fail_reads_of(version_doc);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/1.0.0",
        second.clone(),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::CREATED);
    outage.end();
    let stored = ctx
        .state
        .storage
        .get("composer/hosted/acme/lib/dists/1.0.0.0.zip")
        .await
        .unwrap();
    assert_eq!(
        &stored[..],
        &first[..],
        "an immutable version was overwritten"
    );
}

#[tokio::test]
async fn cached_internal_metadata_and_archive_are_served_without_upstream() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |c| c.composer.metadata_ttl = 0);
    let p2 = "/composer/p2/acme/lib.json";
    let dist = "/composer/dists/acme/lib/1.0.0/aaaa.zip";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&ctx.app, Method::GET, dist, "").await.status(),
        StatusCode::OK
    );
    crate::test_helpers::reload_curation(&ctx, |c| {
        c.curation.internal_namespaces = vec!["acme/*".to_string()];
    });
    up.reset().await;
    // Stale (TTL 0) and internal: served from what NORA holds, never asked upstream.
    let resp = send(&ctx.app, Method::GET, p2, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_of(resp).await["packages"]["acme/lib"][0]["version"],
        "1.0.0"
    );
    let resp = send(&ctx.app, Method::GET, dist, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
    assert!(upstream_paths(&up).await.is_empty());
    // Listed in the cached metadata, archive not cached: refused, not fetched.
    let archive_key = proxied_dist_key("acme/lib", "1.0.0", "aaaa", "zip");
    ctx.state.storage.delete(&archive_key).await.unwrap();
    let resp = send(&ctx.app, Method::GET, dist, "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // What NORA does not hold stays refused.
    for path in [
        "/composer/p2/acme/lib~dev.json",
        "/composer/p2/acme/none.json",
        "/composer/dists/acme/lib/2.0.0/bbbb.zip",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(upstream_paths(&up).await.is_empty());
}

#[tokio::test]
async fn metadata_revalidation_does_not_restart_release_age() {
    let up = MockServer::start().await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .and(wm_header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&up)
        .await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.composer.metadata_ttl = 0;
        c.server.trust_upstream_dates = false;
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
    });
    let p2 = "/composer/p2/acme/lib.json";
    let dist = "/composer/dists/acme/lib/1.0.0/aaaa.zip";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    // NORA first saw the listing ten days ago: a cache older than any record of it.
    let key = p2_key("acme/lib", false);
    let body = ctx.state.storage.get(&key).await.unwrap();
    let _ = ctx.state.storage.delete(&first_seen_key(&key)).await;
    crate::test_helpers::put_written_days_ago(&ctx, &key, &body, 10).await;
    // Revalidated (304) over and over: the release keeps its age.
    for _ in 0..3 {
        assert_eq!(
            send(&ctx.app, Method::GET, p2, "").await.status(),
            StatusCode::OK
        );
    }
    let resp = send(&ctx.app, Method::GET, dist, "").await;
    assert_eq!(resp.status(), StatusCode::OK, "the 304s restarted the age");
}

#[tokio::test]
async fn a_version_an_upstream_adds_later_starts_young() {
    let up = MockServer::start().await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.composer.metadata_ttl = 0;
        c.composer.revalidate = false;
        c.server.trust_upstream_dates = false;
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
    });
    let p2 = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    let key = p2_key("acme/lib", false);
    let body = ctx.state.storage.get(&key).await.unwrap();
    let _ = ctx.state.storage.delete(&first_seen_key(&key)).await;
    crate::test_helpers::put_written_days_ago(&ctx, &key, &body, 10).await;
    // The upstream now lists 2.0.0 too.
    up.reset().await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/lib": [
            {"name": "acme/lib", "version": "2.0.0", "time": "2020-01-01T00:00:00+00:00",
             "dist": {"type": "zip", "url": format!("{}/archives/lib-2.0.0.zip", up.uri()), "reference": "bbbb"}},
            {"name": "acme/lib", "version": "1.0.0", "time": "2020-01-01T00:00:00+00:00",
             "dist": {"type": "zip", "url": format!("{}/archives/lib-1.0.0.zip", up.uri()), "reference": "aaaa", "shasum": sha1_hex(ZIP_1)}}
        ]}})))
        .mount(&up)
        .await;
    Mock::given(wm_path("/archives/lib-1.0.0.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .mount(&up)
        .await;
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    let old = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(old.status(), StatusCode::OK, "a refetch made 1.0.0 young");
    let new = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/2.0.0/bbbb.zip",
        "",
    )
    .await;
    assert_eq!(new.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_first_seen_ledger_is_internal_state_backup_carries() {
    let key = first_seen_key(&p2_key("acme/lib", false));
    assert!(
        crate::registry::npm::INTERNAL_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix)),
        "{key}"
    );
    let ctx = hosted_ctx();
    ctx.state.storage.put(&key, b"{}").await.unwrap();
    let listed = ctx.state.storage.list("").await.unwrap();
    assert!(!listed.contains(&key), "a listing shows the ledger");
}

// ── second review (#1228): writes whose outcome is unknown, roots that are not roots ──

#[tokio::test]
async fn an_upload_whose_listing_landed_is_not_taken_back() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
    });
    assert_eq!(put_lib(&ctx, "1.0.0").await.status(), StatusCode::CREATED);
    // The listing naming 2.0.0 is stored, and the store reports a failure after it (the
    // rename published it; the directory sync did not answer).
    outage.fail_writes_after_landing_of("composer/hosted/acme/lib/p2.json");
    let resp = put_lib(&ctx, "2.0.0").await;
    assert_ne!(resp.status(), StatusCode::CREATED);
    outage.end();
    let first = upload_zip("acme/lib", None);
    let other = upload_zip("acme/lib", Some("2.0.0"));
    assert_ne!(other, first);
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/lib/2.0.0",
        other,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a listed version was published again"
    );
    let stored = ctx
        .state
        .storage
        .get("composer/hosted/acme/lib/dists/2.0.0.0.zip")
        .await
        .unwrap();
    assert_eq!(&stored[..], &first[..], "a listed archive was replaced");
}

async fn mount_root(up: &MockServer) {
    Mock::given(wm_method("GET"))
        .and(wm_path("/packages.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [],
            "metadata-url": "/p2/%package%.json"
        })))
        .mount(up)
        .await;
}

#[tokio::test]
async fn validators_never_describe_a_body_that_was_not_stored() {
    let up = MockServer::start().await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    let (storage, outage) = crate::test_helpers::outage_storage();
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
        c.composer.metadata_ttl = 0;
    });
    let p2 = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    // The upstream moves on to a document listing 2.0.0 too, under a new ETag.
    up.reset().await;
    mount_root(&up).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .and(wm_header("if-none-match", "\"v2\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&up)
        .await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v2\"")
                .set_body_json(json!({"packages": {"acme/lib": [
                    {"name": "acme/lib", "version": "2.0.0", "dist": {"type": "zip", "url": format!("{}/archives/lib-2.0.0.zip", up.uri()), "reference": "bbbb"}},
                    {"name": "acme/lib", "version": "1.0.0", "dist": {"type": "zip", "url": format!("{}/archives/lib-1.0.0.zip", up.uri()), "reference": "aaaa"}}
                ]}})),
        )
        .mount(&up)
        .await;
    // The new body cannot be stored.
    outage.fail_writes_of(&p2_key("acme/lib", false));
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    outage.end();
    let doc = json_of(send(&ctx.app, Method::GET, p2, "").await).await;
    assert_eq!(
        versions_of(&doc, "acme/lib").len(),
        2,
        "a 304 for the new ETag kept serving the old body: {doc}"
    );
}

#[tokio::test]
async fn a_version_with_no_age_of_its_own_is_young() {
    let up = MockServer::start().await;
    mount_lib(&up, &up.uri(), Some(&sha1_hex(ZIP_1))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    let (storage, outage) = crate::test_helpers::local_outage_storage(&path);
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.storage.path = path.clone();
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
        c.composer.metadata_ttl = 0;
        c.composer.revalidate = false;
        c.server.trust_upstream_dates = false;
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
    });
    let p2 = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    // A listing cached ten days ago, before any record of first sight.
    let key = p2_key("acme/lib", false);
    let body = ctx.state.storage.get(&key).await.unwrap();
    let _ = ctx.state.storage.delete(&first_seen_key(&key)).await;
    crate::test_helpers::put_written_days_ago(&ctx, &key, &body, 10).await;
    // The upstream adds 2.0.0, and neither the ledger nor the new listing can be stored.
    up.reset().await;
    mount_root(&up).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/lib": [
            {"name": "acme/lib", "version": "2.0.0", "dist": {"type": "zip", "url": format!("{}/archives/lib-2.0.0.zip", up.uri()), "reference": "bbbb"}},
            {"name": "acme/lib", "version": "1.0.0", "dist": {"type": "zip", "url": format!("{}/archives/lib-1.0.0.zip", up.uri()), "reference": "aaaa", "shasum": sha1_hex(ZIP_1)}}
        ]}})))
        .mount(&up)
        .await;
    for archive in ["lib-1.0.0.zip", "lib-2.0.0.zip"] {
        Mock::given(wm_path(format!("/archives/{archive}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
            .mount(&up)
            .await;
    }
    outage.fail_writes_of(&first_seen_key(&key));
    outage.fail_writes_of(&key);
    let new = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/2.0.0/bbbb.zip",
        "",
    )
    .await;
    assert_eq!(
        new.status(),
        StatusCode::FORBIDDEN,
        "2.0.0 took the age of a listing that does not hold it"
    );
    // The listing that holds 1.0.0 still gives it its age.
    let old = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/1.0.0/aaaa.zip",
        "",
    )
    .await;
    assert_eq!(old.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_audit_against_a_root_that_is_not_one_is_not_empty_success() {
    for root in [
        json!(null),
        json!([]),
        json!({"error": "service unavailable"}),
    ] {
        let up = MockServer::start().await;
        Mock::given(wm_path("/packages.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(root.clone()))
            .mount(&up)
            .await;
        mount_advisories(&up).await;
        let ctx = proxy_ctx(&up.uri(), |_| {});
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/composer/api/security-advisories/",
            vec![("content-type", "application/x-www-form-urlencoded")],
            "packages%5B%5D=vendor%2Fpublic",
        )
        .await;
        assert!(
            resp.status().is_server_error(),
            "root {root}: {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn a_root_without_an_advisories_api_is_still_a_root() {
    // A repository that offers no advisories (a private Satis, say) has none to report.
    let up = MockServer::start().await;
    mount_root(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        "packages%5B%5D=vendor%2Fpublic",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── final review (#1228): no way around curation, an unread root, a bounded audit ──

async fn mount_source_only(up: &MockServer) {
    mount_root(up).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).insert_header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT").set_body_json(json!({"packages": {"acme/lib": [
            {"name": "acme/lib", "version": "2.0.0",
             "source": {"type": "git", "url": "https://git.example.invalid/acme/lib.git", "reference": "bbbb"}},
            {"name": "acme/lib", "version": "1.0.0", "time": "2020-01-01T00:00:00+00:00",
             "dist": {"type": "zip", "url": format!("{}/archives/lib-1.0.0.zip", up.uri()), "reference": "aaaa"},
             "source": {"type": "git", "url": "https://git.example.invalid/acme/lib.git", "reference": "aaaa"}}
        ]}})))
        .mount(up)
        .await;
}

#[tokio::test]
async fn a_curated_proxy_lists_no_way_around_nora() {
    let up = MockServer::start().await;
    mount_source_only(&up).await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        assert!(c.composer.keep_source, "the default keeps sources");
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
    });
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await).await;
    let versions = versions_of(&doc, "acme/lib");
    let listed: Vec<&str> = versions
        .iter()
        .filter_map(|v| v.get("version").and_then(Value::as_str))
        .collect();
    assert_eq!(
        listed,
        ["1.0.0"],
        "a version NORA cannot curate is listed: {doc}"
    );
    assert!(
        versions.iter().all(|v| !v.contains_key("source")),
        "a source lets the client past curation: {doc}"
    );
}

#[tokio::test]
async fn without_curation_sources_are_kept_as_configured() {
    let up = MockServer::start().await;
    mount_source_only(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let doc = json_of(send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await).await;
    let versions = versions_of(&doc, "acme/lib");
    assert_eq!(versions.len(), 2, "{doc}");
    assert!(versions.iter().all(|v| v.contains_key("source")), "{doc}");
}

#[tokio::test]
async fn an_unread_root_and_a_guessed_path_is_not_a_missing_package() {
    // A repository whose metadata lives elsewhere than `/p2/`: its root is the only place
    // that says so, and it is down.
    let up = MockServer::start().await;
    Mock::given(wm_path("/packages.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&up)
        .await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "an outage read as 'no such package'"
    );
}

#[tokio::test]
async fn a_read_root_and_a_missing_package_is_a_404() {
    let up = MockServer::start().await;
    mount_root(&up).await;
    Mock::given(wm_path("/p2/acme/none.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/none.json", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── after the final review (#1228): a client's copy of what NORA served, upstreams that failed ──

#[tokio::test]
async fn a_conditional_request_answers_for_what_is_served_now() {
    let up = MockServer::start().await;
    mount_source_only(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let p2 = "/composer/p2/acme/lib.json";
    let first = send(&ctx.app, Method::GET, p2, "").await;
    assert_eq!(first.status(), StatusCode::OK);
    let last_modified = first.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_string();
    // Unchanged, the client's copy is current.
    let again = send_with_headers(
        &ctx.app,
        Method::GET,
        p2,
        vec![("if-modified-since", last_modified.as_str())],
        "",
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    // Curation turned on: the served document is another one (no source-only version, no source).
    crate::test_helpers::reload_curation(&ctx, |c| {
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.min_release_age = Some("7d".into());
        c.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
    });
    // As Composer asks: `If-Modified-Since` alone.
    let conditions = vec![("if-modified-since", last_modified.as_str())];
    let after = send_with_headers(&ctx.app, Method::GET, p2, conditions, "").await;
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "a 304 kept the client on a document NORA no longer serves"
    );
    let doc = json_of(after).await;
    assert!(
        versions_of(&doc, "acme/lib")
            .iter()
            .all(|v| !v.contains_key("source")),
        "{doc}"
    );
}

#[tokio::test]
async fn an_etag_names_the_served_document() {
    let up = upstream().await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let p2 = "/composer/p2/acme/lib.json";
    let first = send(&ctx.app, Method::GET, p2, "").await;
    let etag = first.headers()[header::ETAG].to_str().unwrap().to_string();
    let again = send_with_headers(
        &ctx.app,
        Method::GET,
        p2,
        vec![("if-none-match", etag.as_str())],
        "",
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    let other = send_with_headers(
        &ctx.app,
        Method::GET,
        p2,
        vec![("if-none-match", "\"something-else\"")],
        "",
    )
    .await;
    assert_eq!(other.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_not_found_beside_a_failed_upstream_is_not_a_missing_package() {
    let first = MockServer::start().await;
    mount_root(&first).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&first)
        .await;
    let second = MockServer::start().await;
    mount_root(&second).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&second)
        .await;
    let (a, b) = (first.uri(), second.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "the package may be on the upstream that failed"
    );
}

#[tokio::test]
async fn every_upstream_saying_not_found_is_a_404() {
    let first = MockServer::start().await;
    mount_root(&first).await;
    let second = MockServer::start().await;
    mount_root(&second).await;
    for up in [&first, &second] {
        Mock::given(wm_path("/p2/acme/lib.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(up)
            .await;
    }
    let (a, b) = (first.uri(), second.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_reload_dates_a_newer_configuration() {
    // What a served document's `Last-Modified` stands on: a reload within the same second as
    // the last one still dates the new configuration later.
    let ctx = hosted_ctx();
    let mut dates = vec![ctx.state.curation().loaded_at];
    for _ in 0..3 {
        crate::test_helpers::reload_curation(&ctx, |_| {});
        dates.push(ctx.state.curation().loaded_at);
    }
    assert!(dates.windows(2).all(|w| w[1] > w[0]), "{dates:?}");
}

#[tokio::test]
async fn advisories_offered_only_inline_are_not_a_clean_audit() {
    // The root says the repository has advisories, in its metadata only: NORA has no API to
    // ask, and an empty answer would read as "no vulnerabilities".
    let up = MockServer::start().await;
    Mock::given(wm_path("/packages.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [],
            "metadata-url": "/p2/%package%.json",
            "security-advisories": {"metadata": true}
        })))
        .mount(&up)
        .await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/composer/api/security-advisories/",
        vec![("content-type", "application/x-www-form-urlencoded")],
        "packages%5B%5D=vendor%2Fpublic",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ── xhigh-1: an archive a lock file names stays downloadable once NORA holds it ───────

async fn mount_branch(up: &MockServer, reference: &str, bytes: &[u8]) {
    Mock::given(wm_path("/p2/acme/lib~dev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/lib": [
            {"name": "acme/lib", "version": "dev-main",
             "dist": {"type": "zip", "url": format!("{}/archives/main-{reference}.zip", up.uri()), "reference": reference}}
        ]}})))
        .mount(up)
        .await;
    Mock::given(wm_path(format!("/archives/main-{reference}.zip")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(up)
        .await;
}

/// `composer install` downloads the URL its lock file recorded. A branch that moved on since
/// leaves that URL out of the current metadata, but the archive under it is the one NORA
/// fetched and checked then: it is served from the cache, curation still deciding, and a
/// reference NORA never held is still not asked of anyone.
#[tokio::test]
async fn an_archive_a_lock_file_names_is_served_after_its_branch_moves() {
    let up = MockServer::start().await;
    mount_root(&up).await;
    mount_branch(&up, "aaaa", ZIP_1).await;
    let ctx = proxy_ctx(&up.uri(), |c| c.composer.metadata_ttl = 0);
    let dev = "/composer/p2/acme/lib~dev.json";
    let locked = "/composer/dists/acme/lib/dev-main/aaaa.zip";
    assert_eq!(
        send(&ctx.app, Method::GET, dev, "").await.status(),
        StatusCode::OK
    );
    let resp = send(&ctx.app, Method::GET, locked, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);

    // The branch moves on.
    up.reset().await;
    mount_root(&up).await;
    mount_branch(&up, "bbbb", b"PK\x03\x04 archive two").await;
    let doc = json_of(send(&ctx.app, Method::GET, dev, "").await).await;
    let url = doc["packages"]["acme/lib"][0]["dist"]["url"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.ends_with("/composer/dists/acme/lib/dev-main/bbbb.zip"),
        "{url}"
    );

    let resp = send(&ctx.app, Method::GET, locked, "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the archive NORA holds under the locked reference"
    );
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/dev-main/cccc.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let sent = upstream_paths(&up).await;
    assert!(
        !sent.iter().any(|p| p.starts_with("/archives/")),
        "{sent:?}"
    );

    // Curation decides on a held archive as on any other.
    let (_dir, blocklist) = blocklist_file("composer", "acme/lib");
    crate::test_helpers::reload_curation(&ctx, move |c| {
        c.curation.mode = crate::config::CurationMode::Enforce;
        c.curation.blocklist_path = Some(blocklist);
    });
    assert_eq!(
        send(&ctx.app, Method::GET, locked, "").await.status(),
        StatusCode::FORBIDDEN
    );
}

// ── xhigh-2: the upstream that has a package answers for both of its documents ────────

fn lib_doc(up: &str, version: &str, reference: &str) -> Value {
    json!({"packages": {"acme/lib": [
        {"name": "acme/lib", "version": version,
         "dist": {"type": "zip", "url": format!("{up}/archives/{reference}.zip"), "reference": reference}}
    ]}})
}

/// `[private, public]`, both with `acme/lib`: the private upstream with one of its two
/// documents (the branches when `private_dev`, else the releases), the public one with both.
async fn split_upstreams(private_dev: bool) -> (MockServer, MockServer, TestContext) {
    let private = MockServer::start().await;
    mount_root(&private).await;
    let (has, lacks, version, reference) = if private_dev {
        (
            "/p2/acme/lib~dev.json",
            "/p2/acme/lib.json",
            "dev-main",
            "privatedev",
        )
    } else {
        (
            "/p2/acme/lib.json",
            "/p2/acme/lib~dev.json",
            "1.0.0",
            "privaterel",
        )
    };
    Mock::given(wm_path(has))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &private.uri(),
            version,
            reference,
        )))
        .mount(&private)
        .await;
    Mock::given(wm_path(lacks))
        .respond_with(ResponseTemplate::new(404))
        .mount(&private)
        .await;
    let public = MockServer::start().await;
    mount_root(&public).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &public.uri(),
            "6.6.6",
            "publicrel",
        )))
        .mount(&public)
        .await;
    Mock::given(wm_path("/p2/acme/lib~dev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &public.uri(),
            "dev-main",
            "publicdev",
        )))
        .mount(&public)
        .await;
    Mock::given(wm_method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .with_priority(10)
        .mount(&public)
        .await;
    let (a, b) = (private.uri(), public.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    (private, public, ctx)
}

/// Composer finds a package in a repository by either of its two documents and asks no
/// later repository for it (`PoolBuilder` drops every name found). Neither document of a
/// package the first upstream has comes from another, nor does an archive the other lists.
#[tokio::test]
async fn the_upstream_that_has_a_package_answers_for_both_of_its_documents() {
    for private_dev in [false, true] {
        let (_private, public, ctx) = split_upstreams(private_dev).await;
        let (own, other) = if private_dev {
            ("~dev", "")
        } else {
            ("", "~dev")
        };
        // Composer asks for both at once: the one the private upstream lacks may come first.
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/composer/p2/acme/lib{other}.json"),
            "",
        )
        .await;
        let status = resp.status();
        let served = if status == StatusCode::OK {
            versions_of(&json_of(resp).await, "acme/lib").len()
        } else {
            0
        };
        assert!(
            status == StatusCode::NOT_FOUND || (status == StatusCode::OK && served == 0),
            "private_dev={private_dev}: {status}, {served} versions of another upstream's"
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/composer/p2/acme/lib{own}.json"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        for path in [
            "/composer/dists/acme/lib/dev-main/publicdev.zip",
            "/composer/dists/acme/lib/6.6.6/publicrel.zip",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let asked = upstream_paths(&public).await;
        assert!(
            !asked
                .iter()
                .any(|p| p.contains("acme/lib") || p.starts_with("/archives/")),
            "private_dev={private_dev}: {asked:?}"
        );
    }
}

// ── xhigh-3: concurrent refetches leave a body with the validators that describe it ───

/// Two requests refetch one document while the upstream moves from state one to state two.
/// The writes interleave as the store lets them — body two, body one, validators one,
/// validators two — ordered by holding writes at the store, not by timing. Whatever is left
/// stored, the next revalidation must not be answered "not modified" for a body that was not
/// the one its validators came with, or the old body stays for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refetches_never_pin_an_old_body_under_a_new_etag() {
    let up = MockServer::start().await;
    mount_root(&up).await;
    let doc = |state: &str, versions: &[&str]| {
        let list: Vec<Value> = versions
            .iter()
            .map(|v| json!({"name": "acme/lib", "version": v,
                "dist": {"type": "zip", "url": format!("{}/archives/{v}.zip", up.uri()), "reference": "aaaa"}}))
            .collect();
        json!({"packages": {"acme/lib": list}, "x-nora-test": state})
    };
    Mock::given(wm_path("/p2/acme/lib.json"))
        .and(wm_header("if-none-match", "\"v2\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&up)
        .await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v1\"")
                .set_body_json(doc("state-one", &["1.0.0"])),
        )
        .up_to_n_times(1)
        .with_priority(2)
        .mount(&up)
        .await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v2\"")
                .set_body_json(doc("state-two", &["2.0.0", "1.0.0"])),
        )
        .with_priority(3)
        .mount(&up)
        .await;
    let (storage, outage) = crate::test_helpers::outage_storage();
    let uri = up.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.proxy = Some(uri);
        c.composer.metadata_ttl = 0;
    });
    let p2 = "/composer/p2/acme/lib.json";
    let key = p2_key("acme/lib", false);
    let older_body = outage.hold_write_of(&key, b"state-one");
    let newer_validators = outage.hold_write_of(&validators_key(&key), b"v2");
    // CANCEL-SAFETY: a watchdog over the scenario: a hang fails the test instead of stalling
    // the run; nothing is ordered by it.
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let app = ctx.app.clone();
        let first = tokio::spawn(async move { send(&app, Method::GET, p2, "").await.status() });
        // The first request read state one and is about to store it.
        older_body.reached().await;
        let app = ctx.app.clone();
        let second = tokio::spawn(async move { send(&app, Method::GET, p2, "").await.status() });
        // The second read state two, stored its body, and is about to store its validators.
        newer_validators.reached().await;
        older_body.release();
        assert_eq!(first.await.unwrap(), StatusCode::OK);
        newer_validators.release();
        assert_eq!(second.await.unwrap(), StatusCode::OK);
    })
    .await
    .expect("the ordered refetches finished");
    let doc = json_of(send(&ctx.app, Method::GET, p2, "").await).await;
    assert_eq!(
        versions_of(&doc, "acme/lib").len(),
        2,
        "a 304 for the newer ETag kept the older body: {doc}"
    );
}

// ── xhigh-4: a hosted name the store cannot be asked about is never an upstream's ─────

/// After an upload, the vendor directory loses its search permission: whether `acme/private`
/// is hosted cannot be read. It must not be taken for an upstream's name then — neither its
/// metadata nor an audit may reach an upstream that has a public package by that name.
#[tokio::test]
async fn a_hosted_name_the_store_cannot_be_asked_about_is_never_an_upstream_s() {
    use std::os::unix::fs::PermissionsExt;
    let up = MockServer::start().await;
    mount_root(&up).await;
    Mock::given(wm_path("/p2/acme/private.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/private": [
            {"name": "acme/private", "version": "6.6.6",
             "dist": {"type": "zip", "url": format!("{}/archives/evil.zip", up.uri()), "reference": "eeee"}}
        ]}})))
        .mount(&up)
        .await;
    mount_advisories(&up).await;
    let ctx = proxy_ctx(&up.uri(), |_| {});
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/composer/packages/upload/acme/private/1.0.0",
        upload_zip("acme/private", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let vendor = std::path::Path::new(&ctx.state.config.storage.path).join("composer/hosted/acme");
    std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o000)).unwrap();
    let blocked = std::fs::metadata(vendor.join("private")).is_err();
    let p2 = send(&ctx.app, Method::GET, "/composer/p2/acme/private.json", "").await;
    let dist = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/private/6.6.6/eeee.zip",
        "",
    )
    .await;
    let audit = send(
        &ctx.app,
        Method::GET,
        "/composer/api/security-advisories?packages[]=acme/private",
        "",
    )
    .await;
    std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !blocked {
        eprintln!("skipped: this user passes through a directory without permissions");
        return;
    }
    for (what, resp) in [("p2", &p2), ("dist", &dist), ("audit", &audit)] {
        assert!(resp.status().is_server_error(), "{what}: {}", resp.status());
    }
    let asked = upstream_paths(&up).await;
    assert!(
        !asked.iter().any(|p| p.contains("acme/private")
            || p.contains("advisories")
            || p.starts_with("/archives/")),
        "{asked:?}"
    );
}

use wiremock::matchers::path_regex as wm_path_regex;

// ── xhigh-5: an upstream that refused NORA or rate-limited it did not say "not found" ─

/// A 401 or 403 (an expired credential) and a 429 from an upstream whose root was read are
/// not "no such package": a cached copy is served stale, and without one the miss is a 502
/// or the 429 — never the 404 that sends Composer to the project's other repositories.
#[tokio::test]
async fn a_refusal_or_rate_limit_is_not_a_missing_package() {
    for refusal in [401u16, 403, 429] {
        let up = MockServer::start().await;
        mount_root(&up).await;
        Mock::given(wm_path("/p2/acme/lib.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
                &up.uri(),
                "1.0.0",
                "aaaa",
            )))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&up)
            .await;
        Mock::given(wm_path_regex("^/p2/"))
            .respond_with(ResponseTemplate::new(refusal).insert_header("retry-after", "30"))
            .with_priority(2)
            .mount(&up)
            .await;
        let ctx = proxy_ctx(&up.uri(), |c| c.composer.metadata_ttl = 0);
        let p2 = "/composer/p2/acme/lib.json";
        assert_eq!(
            send(&ctx.app, Method::GET, p2, "").await.status(),
            StatusCode::OK
        );
        let resp = send(&ctx.app, Method::GET, p2, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{refusal}: the cached copy");
        assert_eq!(resp.headers()["x-nora-stale"], "true", "{refusal}");
        let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/other.json", "").await;
        let expected = if refusal == 429 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_GATEWAY
        };
        assert_eq!(resp.status(), expected, "{refusal}: no copy");
    }
}

/// The upstream a cached copy came from holds the package. When it fails — refused NORA,
/// rate-limited it, or is down — a later upstream's package of the same name does not take
/// its place: the copy is served stale.
#[tokio::test]
async fn a_package_whose_upstream_fails_is_not_taken_from_the_next() {
    for failure in [401u16, 429, 503] {
        let private = MockServer::start().await;
        mount_root(&private).await;
        Mock::given(wm_path("/p2/acme/lib.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
                &private.uri(),
                "1.0.0",
                "privaterel",
            )))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&private)
            .await;
        Mock::given(wm_path("/p2/acme/lib.json"))
            .respond_with(ResponseTemplate::new(failure))
            .with_priority(2)
            .mount(&private)
            .await;
        let public = MockServer::start().await;
        mount_root(&public).await;
        Mock::given(wm_path("/p2/acme/lib.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
                &public.uri(),
                "6.6.6",
                "publicrel",
            )))
            .mount(&public)
            .await;
        let (a, b) = (private.uri(), public.uri());
        let ctx = create_test_context_with_config(move |c| {
            c.composer.enabled = true;
            c.composer.metadata_ttl = 0;
            c.composer.proxies = vec![
                crate::config::ComposerProxyEntry::Simple(a),
                crate::config::ComposerProxyEntry::Simple(b),
            ];
        });
        let p2 = "/composer/p2/acme/lib.json";
        assert_eq!(
            send(&ctx.app, Method::GET, p2, "").await.status(),
            StatusCode::OK
        );
        let resp = send(&ctx.app, Method::GET, p2, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{failure}");
        assert_eq!(resp.headers()["x-nora-stale"], "true", "{failure}");
        let doc = json_of(resp).await;
        assert_eq!(
            doc["packages"]["acme/lib"][0]["version"], "1.0.0",
            "{failure}"
        );
        let asked = upstream_paths(&public).await;
        assert!(
            !asked.iter().any(|p| p.contains("acme/lib")),
            "{failure}: {asked:?}"
        );
    }
}

// ── xhigh-6: a document never keeps the origin of the copy before it ──────────────────

/// The cache holds `acme/lib` from the second upstream; then the first, which has archives on
/// its own host behind its credential, starts serving it. Its document is stored but where it
/// came from cannot be: the archive it lists must still be fetched with the first upstream's
/// credential, never under the second's.
#[tokio::test]
async fn a_document_whose_origin_was_not_stored_is_not_another_upstream_s() {
    let private = MockServer::start().await;
    mount_root(&private).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(404))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&private)
        .await;
    let public = MockServer::start().await;
    mount_lib(&public, &public.uri(), None).await;
    let (storage, outage) = crate::test_helpers::outage_storage();
    let (a, b) = (private.uri(), public.uri());
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |c| {
        c.composer.enabled = true;
        c.composer.metadata_ttl = 0;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Full(crate::config::ComposerProxy {
                url: a,
                auth: Some(crate::secrets::ProtectedString::new("bot:s3cret".into())),
            }),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    let p2 = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, p2, "").await.status(),
        StatusCode::OK
    );
    // The first upstream now has the package.
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &private.uri(),
            "2.0.0",
            "pppp",
        )))
        .with_priority(2)
        .mount(&private)
        .await;
    let credential = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("bot:s3cret")
    );
    Mock::given(wm_path("/archives/pppp.zip"))
        .and(wm_header("authorization", credential.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .with_priority(1)
        .mount(&private)
        .await;
    Mock::given(wm_path("/archives/pppp.zip"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(2)
        .mount(&private)
        .await;
    outage.fail_writes_of(&origin_key(&p2_key("acme/lib", false)));
    let doc = json_of(send(&ctx.app, Method::GET, p2, "").await).await;
    assert_eq!(doc["packages"]["acme/lib"][0]["version"], "2.0.0");
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/2.0.0/pppp.zip",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the archive went out under the other upstream's credential"
    );
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
}

// ── xhigh-7: a hosted listing changed within the second its date names ────────────────

/// Two uploads within one second leave the listing's date at that second. A client given that
/// date before the second upload would get a 304 for it and never see the new version, so a
/// date the clock has not yet left is not given. A listing last changed in an earlier second
/// keeps its date, and that date revalidates. (A date ahead of the clock stands for "this
/// second", whatever second the test runs in.)
#[tokio::test]
async fn a_hosted_listing_changed_within_its_second_is_never_a_304() {
    let ctx = hosted_ctx();
    let key = hosted_document_key("acme/lib");
    let file = std::path::Path::new(&ctx.state.config.storage.path).join(&key);
    let date = |t: std::time::SystemTime| {
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(t)
            .unwrap()
    };
    let p2 = "/composer/p2/acme/lib.json";
    let this_second = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
    assert_eq!(put_lib(&ctx, "1.0.0").await.status(), StatusCode::CREATED);
    date(this_second);
    let first = send(&ctx.app, Method::GET, p2, "").await;
    assert_eq!(first.status(), StatusCode::OK);
    let given = first
        .headers()
        .get(header::LAST_MODIFIED)
        .map(|v| v.to_str().unwrap().to_string());
    assert_eq!(put_lib(&ctx, "2.0.0").await.status(), StatusCode::CREATED);
    date(this_second);
    if let Some(given) = given {
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            p2,
            vec![("if-modified-since", &given)],
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a 304 left the client without 2.0.0"
        );
    }
    // An earlier second: the date is given, and it revalidates.
    date(std::time::SystemTime::now() - std::time::Duration::from_secs(10));
    let resp = send(&ctx.app, Method::GET, p2, "").await;
    let given = resp.headers()[header::LAST_MODIFIED]
        .to_str()
        .unwrap()
        .to_string();
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        p2,
        vec![("if-modified-since", &given)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    // The same date in RFC 850 form revalidates a hosted listing too (#1315).
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        p2,
        vec![("if-modified-since", &rfc850(&given))],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}

/// The boundary itself: the second a listing was written in gets no date, the one after does.
#[test]
fn a_hosted_listing_is_dated_once_the_clock_leaves_its_second() {
    let t = 1_700_000_000;
    assert_eq!(hosted_date(t, t), None);
    assert_eq!(hosted_date(t + 5, t), None);
    assert_eq!(hosted_date(t, t + 1), Some(t));
    assert_eq!(hosted_date(t - 10, t), Some(t - 10));
}

// ── an upstream that failed before any answered: no later upstream answers instead ────

/// `[private, public]`: the private upstream behaves as `mount` makes it; the public one has
/// `acme/lib` 6.6.6 and its archive.
async fn private_before_public(
    mount: impl FnOnce(&MockServer) -> Vec<Mock>,
) -> (MockServer, MockServer, TestContext) {
    let private = MockServer::start().await;
    mount_root(&private).await;
    for mock in mount(&private) {
        mock.mount(&private).await;
    }
    let public = MockServer::start().await;
    mount_root(&public).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &public.uri(),
            "6.6.6",
            "publicrel",
        )))
        .mount(&public)
        .await;
    Mock::given(wm_path("/archives/publicrel.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ZIP_1.to_vec()))
        .mount(&public)
        .await;
    let (a, b) = (private.uri(), public.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    (private, public, ctx)
}

/// A way an upstream fails: its name, NORA's answer, and the upstream's mocks.
type Failure = (&'static str, StatusCode, fn() -> Vec<Mock>);

fn answers(path: &str, response: ResponseTemplate) -> Mock {
    Mock::given(wm_path(path)).respond_with(response)
}

/// Composer stops at a repository it cannot read (`ComposerRepository::asyncFetchFile` rejects
/// anything but a 404) and never asks the next one for the name. An upstream before the one
/// that would answer failed — down, refusing NORA's credential, rate-limiting it, answering
/// with something that is not metadata, or unable to say whether it has the package's other
/// document — and NORA holds no copy: the failure is the answer, and no later upstream's
/// package of the same name is served, its archive included.
#[tokio::test]
async fn a_failed_upstream_is_not_skipped_for_a_later_one() {
    let failures: Vec<Failure> = vec![
        ("down", StatusCode::BAD_GATEWAY, || {
            vec![answers("/p2/acme/lib.json", ResponseTemplate::new(503))]
        }),
        ("credential refused", StatusCode::BAD_GATEWAY, || {
            vec![answers("/p2/acme/lib.json", ResponseTemplate::new(401))]
        }),
        ("forbidden", StatusCode::BAD_GATEWAY, || {
            vec![answers("/p2/acme/lib.json", ResponseTemplate::new(403))]
        }),
        ("rate-limited", StatusCode::TOO_MANY_REQUESTS, || {
            vec![answers(
                "/p2/acme/lib.json",
                ResponseTemplate::new(429).insert_header("retry-after", "30"),
            )]
        }),
        ("not metadata", StatusCode::BAD_GATEWAY, || {
            vec![answers(
                "/p2/acme/lib.json",
                ResponseTemplate::new(200).set_body_string("<html>sign in</html>"),
            )]
        }),
        ("other document unknown", StatusCode::BAD_GATEWAY, || {
            vec![
                answers("/p2/acme/lib.json", ResponseTemplate::new(404)),
                answers("/p2/acme/lib~dev.json", ResponseTemplate::new(503)),
            ]
        }),
        (
            "other document not metadata",
            StatusCode::BAD_GATEWAY,
            || {
                vec![
                    answers("/p2/acme/lib.json", ResponseTemplate::new(404)),
                    answers(
                        "/p2/acme/lib~dev.json",
                        ResponseTemplate::new(200).set_body_string("<html>sign in</html>"),
                    ),
                ]
            },
        ),
    ];
    for (failure, expected, mount) in failures {
        let (_private, public, ctx) = private_before_public(|_| mount()).await;
        let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
        assert_eq!(resp.status(), expected, "{failure}");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/composer/dists/acme/lib/6.6.6/publicrel.zip",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK, "{failure}: the archive");
        let asked = upstream_paths(&public).await;
        assert!(
            !asked
                .iter()
                .any(|p| p.contains("acme/lib") || p.starts_with("/archives/")),
            "{failure}: {asked:?}"
        );
    }
}

/// The control: an upstream that answered it has no such package (neither document) is not a
/// failure, and the next upstream's package is served.
#[tokio::test]
async fn a_package_the_first_upstream_lacks_comes_from_the_next() {
    let (_private, _public, ctx) = private_before_public(|_| {
        vec![
            answers("/p2/acme/lib.json", ResponseTemplate::new(404)),
            answers("/p2/acme/lib~dev.json", ResponseTemplate::new(404)),
        ]
    })
    .await;
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_of(resp).await["packages"]["acme/lib"][0]["version"],
        "6.6.6"
    );
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/6.6.6/publicrel.zip",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── third review: a held archive keeps its age and stays reachable; one owner per package ─

/// `dev-main` at `reference`, released at `time`, its archive `bytes`.
async fn mount_dated_branch(up: &MockServer, reference: &str, time: &str, bytes: &[u8]) {
    Mock::given(wm_path("/p2/acme/lib~dev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages": {"acme/lib": [
            {"name": "acme/lib", "version": "dev-main", "time": time,
             "dist": {"type": "zip", "url": format!("{}/archives/main-{reference}.zip", up.uri()), "reference": reference}}
        ]}})))
        .mount(up)
        .await;
    Mock::given(wm_path(format!("/archives/main-{reference}.zip")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(up)
        .await;
}

/// A held archive is as old as it was when NORA fetched it. One fetched young (with the bypass
/// token) is refused for its age after its branch moved on, as it was before; one fetched old
/// is served.
#[tokio::test]
async fn a_held_archive_keeps_its_release_age() {
    let now = crate::datetime::UtcTime::now().composer_time();
    for (released, expected) in [
        (now.as_str(), StatusCode::FORBIDDEN),
        ("2020-01-01T00:00:00+00:00", StatusCode::OK),
    ] {
        let up = MockServer::start().await;
        mount_root(&up).await;
        mount_dated_branch(&up, "aaaa", released, ZIP_1).await;
        let ctx = proxy_ctx(&up.uri(), |c| {
            c.composer.metadata_ttl = 0;
            c.server.trust_upstream_dates = true;
            c.curation.mode = crate::config::CurationMode::Enforce;
            c.curation.min_release_age = Some("7d".into());
            c.curation.bypass_token = Some(crate::secrets::ProtectedString::from("let-me-in"));
        });
        let locked = "/composer/dists/acme/lib/dev-main/aaaa.zip";
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            locked,
            vec![("x-nora-bypass-token", "let-me-in")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{released}: fetched");
        assert_eq!(
            send(&ctx.app, Method::GET, locked, "").await.status(),
            expected,
            "{released}: listed"
        );
        up.reset().await;
        mount_root(&up).await;
        mount_dated_branch(&up, "bbbb", "2020-01-01T00:00:00+00:00", b"PK\x03\x04 two").await;
        assert_eq!(
            send(&ctx.app, Method::GET, "/composer/p2/acme/lib~dev.json", "")
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(&ctx.app, Method::GET, locked, "").await.status(),
            expected,
            "{released}: held after the branch moved"
        );
        // Without the record of its date, a held archive is young.
        let record = first_seen_key(&proxied_dist_key("acme/lib", "dev-main", "aaaa", "zip"));
        ctx.state.storage.delete(&record).await.unwrap();
        assert_eq!(
            send(&ctx.app, Method::GET, locked, "").await.status(),
            StatusCode::FORBIDDEN,
            "{released}: held without a recorded date"
        );
    }
}

/// A held archive does not depend on the metadata being reachable: the upstream down and
/// stale metadata not served, the archive a lock file names is still served from the cache;
/// a reference NORA never held is not.
#[tokio::test]
async fn a_held_archive_is_served_while_the_metadata_cannot_be_read() {
    let up = MockServer::start().await;
    mount_root(&up).await;
    mount_branch(&up, "aaaa", ZIP_1).await;
    let ctx = proxy_ctx(&up.uri(), |c| {
        c.composer.metadata_ttl = 0;
        c.composer.serve_stale = false;
    });
    let locked = "/composer/dists/acme/lib/dev-main/aaaa.zip";
    assert_eq!(
        send(&ctx.app, Method::GET, locked, "").await.status(),
        StatusCode::OK
    );
    up.reset().await;
    mount_root(&up).await;
    mount_branch(&up, "bbbb", b"PK\x03\x04 two").await;
    assert_eq!(
        send(&ctx.app, Method::GET, "/composer/p2/acme/lib~dev.json", "")
            .await
            .status(),
        StatusCode::OK
    );
    up.reset().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&up)
        .await;
    let resp = send(&ctx.app, Method::GET, locked, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], ZIP_1);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/dev-main/cccc.zip",
        "",
    )
    .await;
    assert_ne!(resp.status(), StatusCode::OK);
}

/// The package is the first upstream's that has either document, a copy past its TTL
/// included. The private upstream served the releases (cached, now stale), answers 404 for the
/// branches and fails for the releases: the branch document is its answer — none — not the
/// public upstream's, and the releases are its stale copy.
#[tokio::test]
async fn a_stale_copy_of_the_other_document_keeps_the_package_its_upstream_s() {
    let private = MockServer::start().await;
    mount_root(&private).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &private.uri(),
            "1.0.0",
            "privaterel",
        )))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&private)
        .await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(2)
        .mount(&private)
        .await;
    Mock::given(wm_path("/p2/acme/lib~dev.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&private)
        .await;
    let public = MockServer::start().await;
    mount_root(&public).await;
    Mock::given(wm_path("/p2/acme/lib~dev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &public.uri(),
            "dev-main",
            "publicdev",
        )))
        .mount(&public)
        .await;
    let (a, b) = (private.uri(), public.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.metadata_ttl = 0;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    let releases = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, releases, "").await.status(),
        StatusCode::OK
    );
    let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib~dev.json", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the branches are the private upstream's answer"
    );
    let resp = send(&ctx.app, Method::GET, releases, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-nora-stale"], "true");
    let asked = upstream_paths(&public).await;
    assert!(!asked.iter().any(|p| p.contains("acme/lib")), "{asked:?}");
}

/// The copy of the very document asked for, past its TTL, keeps the package its upstream's
/// too. The private upstream served the releases (cached, now stale) and answers 404 for both
/// documents: the releases are its answer — none — not the public upstream's package.
#[tokio::test]
async fn a_stale_copy_of_the_document_asked_for_keeps_the_package_its_upstream_s() {
    let private = MockServer::start().await;
    mount_root(&private).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &private.uri(),
            "1.0.0",
            "privaterel",
        )))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&private)
        .await;
    Mock::given(wm_path_regex("^/p2/acme/lib"))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(2)
        .mount(&private)
        .await;
    let public = MockServer::start().await;
    mount_root(&public).await;
    Mock::given(wm_path("/p2/acme/lib.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(lib_doc(
            &public.uri(),
            "6.6.6",
            "publicrel",
        )))
        .mount(&public)
        .await;
    let (a, b) = (private.uri(), public.uri());
    let ctx = create_test_context_with_config(move |c| {
        c.composer.enabled = true;
        c.composer.metadata_ttl = 0;
        c.composer.proxies = vec![
            crate::config::ComposerProxyEntry::Simple(a),
            crate::config::ComposerProxyEntry::Simple(b),
        ];
    });
    let releases = "/composer/p2/acme/lib.json";
    assert_eq!(
        send(&ctx.app, Method::GET, releases, "").await.status(),
        StatusCode::OK
    );
    let resp = send(&ctx.app, Method::GET, releases, "").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the releases are the private upstream's answer"
    );
    let resp = send(
        &ctx.app,
        Method::GET,
        "/composer/dists/acme/lib/6.6.6/publicrel.zip",
        "",
    )
    .await;
    assert_ne!(resp.status(), StatusCode::OK);
    let asked = upstream_paths(&public).await;
    assert!(!asked.iter().any(|p| p.contains("acme/lib")), "{asked:?}");
}

/// Metadata that names no package — `{"packages":[]}`, `{"packages":{}}`, another package's
/// document — is an upstream saying it does not have the package, as a 404 is: the next
/// upstream is asked, and with none having it the answer is 404. An answer that is not
/// metadata at all (a sign-in page, JSON without `packages`, `packages` that is a non-empty array
/// or not a list) is still a failure: 502.
#[tokio::test]
async fn metadata_naming_no_package_is_not_a_failure() {
    let no_package = [
        r#"{"packages":[]}"#,
        r#"{"packages":{}}"#,
        r#"{"packages":{"acme/other":[{"name":"acme/other","version":"1.0.0"}]}}"#,
    ];
    for body in no_package {
        for public_has in [false, true] {
            let private = MockServer::start().await;
            mount_root(&private).await;
            answers("/p2/acme/lib.json", ResponseTemplate::new(404))
                .mount(&private)
                .await;
            answers(
                "/p2/acme/lib~dev.json",
                ResponseTemplate::new(200).set_body_string(body),
            )
            .mount(&private)
            .await;
            let public = MockServer::start().await;
            mount_root(&public).await;
            if public_has {
                answers(
                    "/p2/acme/lib.json",
                    ResponseTemplate::new(200).set_body_json(lib_doc(
                        &public.uri(),
                        "6.6.6",
                        "publicrel",
                    )),
                )
                .mount(&public)
                .await;
            }
            let (a, b) = (private.uri(), public.uri());
            let ctx = create_test_context_with_config(move |c| {
                c.composer.enabled = true;
                c.composer.proxies = vec![
                    crate::config::ComposerProxyEntry::Simple(a),
                    crate::config::ComposerProxyEntry::Simple(b),
                ];
            });
            let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
            let expected = if public_has {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(
                resp.status(),
                expected,
                "{body}, public has it: {public_has}"
            );
        }
    }
    for (failure, body) in [
        ("sign-in page", "<html>sign in</html>"),
        ("JSON without packages", r#"{"error":"forbidden"}"#),
        (
            "a non-empty array",
            r#"{"packages":["authentication required"]}"#,
        ),
        ("packages that are not a list", r#"{"packages":"acme/lib"}"#),
    ] {
        let (_private, public, ctx) = private_before_public(|_| {
            vec![
                answers("/p2/acme/lib.json", ResponseTemplate::new(404)),
                answers(
                    "/p2/acme/lib~dev.json",
                    ResponseTemplate::new(200).set_body_string(body),
                ),
            ]
        })
        .await;
        let resp = send(&ctx.app, Method::GET, "/composer/p2/acme/lib.json", "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{failure}");
        let asked = upstream_paths(&public).await;
        assert!(
            !asked.iter().any(|p| p.contains("acme/lib")),
            "{failure}: {asked:?}"
        );
    }
}

/// The `Last-Modified` NORA gives a Composer document, as 1.4.5 wrote it (#1282); the epoch for
/// a date past the calendar. An upstream's own date is kept, as sent, when it reads as an
/// HTTP-date or as RFC 2822 (#1315 added the RFC 850 and asctime forms).
#[test]
fn composer_dates_are_the_http_dates_they_were() {
    assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
    assert_eq!(
        http_date(8_210_266_876_800),
        "Thu, 01 Jan 1970 00:00:00 GMT"
    );
    assert_eq!(http_date(u64::MAX), "Wed, 31 Dec 1969 23:59:59 GMT");
    let served = |upstream: &str, since: i64| {
        metadata_response(
            &HeaderMap::new(),
            b"{}".to_vec(),
            Some(upstream.to_string()),
            false,
            since,
        )
        .headers()
        .get(header::LAST_MODIFIED)
        .map(|v| v.to_str().unwrap().to_string())
    };
    let upstream = "Tue, 14 Nov 2023 22:13:20 GMT";
    assert_eq!(served(upstream, 1_700_000_000).as_deref(), Some(upstream));
    assert_eq!(
        served(upstream, 1_700_000_001).as_deref(),
        Some("Tue, 14 Nov 2023 22:13:21 GMT")
    );
    assert_eq!(
        served("tue, 14 nov 23 23:13:20 +0100", 1_700_000_000).as_deref(),
        Some("tue, 14 nov 23 23:13:20 +0100")
    );
    assert_eq!(
        served("Tue Nov 14 22:13:20 2023", 1_700_000_000).as_deref(),
        Some("Tue Nov 14 22:13:20 2023")
    );
    assert_eq!(
        served("2023-11-14T22:13:20Z", 0).as_deref(),
        Some("Thu, 01 Jan 1970 00:00:00 GMT")
    );
}
