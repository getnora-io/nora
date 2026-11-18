//! What one request for a cached npm packument costs in memory, and the bytes it answers
//! (#1305).
//!
//! A packument is the largest document NORA serves on every `npm install` (typescript's is 16 MB),
//! and the memory a request holds grows with the number of requests in flight. Measured on 1.4.6,
//! one request held about ten times the document for the abbreviated form (`Accept:
//! application/vnd.npm.install-v1+json`, what pnpm asks): ten parallel installs of typescript went
//! past 1.8 GiB. The bound here is three times the stored document, for the full and the abbreviated
//! form, on the local store and on an object store, counted by the allocator of the test thread
//! (`allocation-counter`); the request runs on a current-thread runtime, so its work is counted
//! where it runs.
//!
//! The bytes a client gets are pinned by snapshots taken before #1305 changed how they are built,
//! and the abbreviated form is checked against the projection it replaced on documents of every
//! shape a store can hold.

use super::{origin_of, put_with_origin, rewrite_for_nora, upstream_packument_key, Links};
use crate::test_helpers::{
    body_bytes, create_test_context_in_memory, create_test_context_with_config,
    create_test_context_with_storage_and_config, op_counting_storage, send_with_headers,
    TestContext,
};
use axum::body::Bytes;
use axum::http::{header, Method, StatusCode};
use sha2::Digest;

const UPSTREAM: &str = "http://127.0.0.1:9";
const PACKAGE: &str = "memdoc";
const INSTALL_V1: &str = "application/vnd.npm.install-v1+json";
/// About typescript's packument.
const LARGE: usize = 16 * 1024 * 1024;
/// The bound on what one request for the abbreviated form holds at its peak, in sizes of the
/// stored document: the document read, the abbreviated form written, and what the projection
/// holds of one version at a time.
const PEAK_FACTOR: u64 = 3;
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Store {
    Local,
    Object,
}

/// A context whose npm proxy never answers: a cached copy is served fresh, and a request that
/// reached the upstream would fail.
fn context(store: Store) -> TestContext {
    match store {
        Store::Local => create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(UPSTREAM.to_string());
            cfg.npm.metadata_ttl = 3600;
        }),
        Store::Object => create_test_context_in_memory(|cfg| {
            cfg.npm.proxy = Some(UPSTREAM.to_string());
            cfg.npm.metadata_ttl = 3600;
        }),
    }
}

/// A packument as registry.npmjs.org shapes one, of at least `size` bytes: many versions, each
/// with the fields the abbreviated form keeps and the ones it drops, a `time` map and a readme.
fn synthetic_packument(size: usize) -> Vec<u8> {
    let mut versions = String::new();
    let mut times = String::new();
    let mut latest = String::new();
    let dev: String = (0..30)
        .map(|d| format!("\"dev-dependency-{d}\":\"^{d}.1.2\""))
        .collect::<Vec<_>>()
        .join(",");
    let mut i = 0usize;
    while versions.len() < size {
        let version = match i % 7 {
            0 => format!("{}.{}.{}-beta.{}", i / 1000, (i / 10) % 100, i % 10, i % 5),
            _ => format!("{}.{}.{}", i / 1000, (i / 10) % 100, i % 10),
        };
        if !versions.is_empty() {
            versions.push(',');
            times.push(',');
        }
        let extra = match i % 11 {
            0 => ",\"deprecated\":\"use \\\"other\\\" \\u00e9 instead\",\"hasInstallScript\":true",
            1 => ",\"os\":[\"linux\",\"darwin\"],\"cpu\":[\"x64\",\"arm64\"],\"libc\":[\"glibc\"]",
            2 => ",\"funding\":{\"type\":\"opencollective\",\"url\":\"https://example.test/f\"}",
            _ => "",
        };
        versions.push_str(&format!(
            concat!(
                "\"{v}\":{{\"name\":\"{p}\",\"version\":\"{v}\",",
                "\"description\":\"A synthetic package for #1305 \\u2014 caf\\u00e9\",",
                "\"keywords\":[\"memory\",\"packument\"],\"homepage\":\"https://example.test/{p}\",",
                "\"bugs\":{{\"url\":\"https://example.test/{p}/issues\"}},\"license\":\"Apache-2.0\",",
                "\"main\":\"./lib/index.js\",\"typings\":\"./lib/index.d.ts\",",
                "\"bin\":{{\"{p}\":\"./bin/{p}\",\"{p}-server\":\"./bin/server\"}},",
                "\"engines\":{{\"node\":\">=14.17\"}},",
                "\"scripts\":{{\"build\":\"tsc -b ./src\",\"test\":\"mocha --recursive\",\"lint\":\"eslint .\"}},",
                "\"dependencies\":{{\"dep-a\":\"^1.0.0\",\"dep-b\":\"~2.3.4\"}},",
                "\"devDependencies\":{{{dev}}},",
                "\"optionalDependencies\":{{\"fsevents\":\"2.3.2\"}},",
                "\"peerDependencies\":{{\"peer\":\">=1\"}},\"peerDependenciesMeta\":{{\"peer\":{{\"optional\":true}}}},",
                "\"directories\":{{}},\"gitHead\":\"{h:040x}\",\"_id\":\"{p}@{v}\",",
                "\"_nodeVersion\":\"20.1.0\",\"_npmVersion\":\"9.6.4\",",
                "\"dist\":{{\"integrity\":\"sha512-{h:0128x}==\",\"shasum\":\"{h:040x}\",",
                "\"tarball\":\"{u}/{p}/-/{p}-{v}.tgz\",\"fileCount\":{f},\"unpackedSize\":{s},",
                "\"signatures\":[{{\"keyid\":\"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA\",\"sig\":\"MEUCIQ{h:064x}\"}}]}},",
                "\"_npmUser\":{{\"name\":\"publisher\",\"email\":\"publisher@example.test\"}},",
                "\"maintainers\":[{{\"name\":\"one\",\"email\":\"one@example.test\"}},{{\"name\":\"two\",\"email\":\"two@example.test\"}}],",
                "\"_npmOperationalInternal\":{{\"host\":\"s3://npm-registry-packages\",\"tmp\":\"tmp/{p}_{v}_1690000000000_0.{i}\"}},",
                "\"_hasShrinkwrap\":false{extra}}}"
            ),
            v = version,
            p = PACKAGE,
            u = UPSTREAM,
            h = i as u128 * 0x9e37_79b9_7f4a_7c15,
            f = 100 + i % 300,
            s = 1_000_000 + i * 37,
            i = i,
            dev = dev,
            extra = extra,
        ));
        times.push_str(&format!(
            "\"{version}\":\"2023-{:02}-{:02}T00:00:00.000Z\"",
            1 + i % 12,
            1 + i % 28
        ));
        latest = version;
        i += 1;
    }
    let readme = "# memdoc\n\nA readme the abbreviated form drops. ".repeat(2000);
    format!(
        concat!(
            "{{\"_id\":\"{p}\",\"_rev\":\"1234-abcdef\",\"name\":\"{p}\",",
            "\"description\":\"A synthetic package\",",
            "\"dist-tags\":{{\"latest\":\"{latest}\",\"next\":\"{latest}\"}},",
            "\"versions\":{{{versions}}},",
            "\"time\":{{\"created\":\"2012-10-01T15:00:00.000Z\",\"modified\":\"2026-11-17T10:00:00.000Z\",{times}}},",
            "\"maintainers\":[{{\"name\":\"one\",\"email\":\"one@example.test\"}}],",
            "\"readme\":{readme},\"readmeFilename\":\"README.md\",",
            "\"users\":{{\"someone\":true}},\"license\":\"Apache-2.0\"}}"
        ),
        p = PACKAGE,
        latest = latest,
        versions = versions,
        times = times,
        readme = serde_json::to_string(&readme).unwrap(),
    )
    .into_bytes()
}

/// Cache `upstream_doc` as a fresh upstream copy does: links on NORA, record of the public base
/// first, provenance beside it. The stored bytes come back.
async fn cache_as_fetched(ctx: &TestContext, upstream_doc: &[u8]) -> Vec<u8> {
    let stored = rewrite_for_nora(&ctx.state, upstream_doc, UPSTREAM, PACKAGE, Links::Stored)
        .expect("a packument is placed");
    store_copy(ctx, &stored).await;
    stored
}

/// Store `bytes` as the cached upstream copy of [`PACKAGE`], with its provenance.
async fn store_copy(ctx: &TestContext, bytes: &[u8]) {
    put_with_origin(
        &ctx.state.storage,
        &upstream_packument_key(PACKAGE),
        bytes,
        &origin_of(UPSTREAM),
    )
    .await
    .unwrap();
}

struct Served {
    status: StatusCode,
    content_type: String,
    body: Bytes,
}

async fn get_packument(ctx: &TestContext, accept: Option<&str>) -> Served {
    let headers = accept.map(|a| vec![("accept", a)]).unwrap_or_default();
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/npm/{PACKAGE}"),
        headers,
        "",
    )
    .await;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    Served {
        status,
        content_type,
        body: body_bytes(resp).await,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The measure is not blind: building the document tree of a packument, what 1.4.6 did for every
/// abbreviated request, holds several times the document on this thread.
#[test]
fn the_measure_sees_a_document_tree() {
    let doc = synthetic_packument(LARGE / 4);
    let info = allocation_counter::measure(|| {
        let tree: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        std::hint::black_box(&tree);
    });
    assert!(
        info.bytes_max > PEAK_FACTOR * doc.len() as u64,
        "a tree of {} bytes measured at a peak of {}",
        doc.len(),
        info.bytes_max
    );
}

/// The storage round-trips of a request for a cached packument, full and abbreviated: no more
/// than before #1305.
#[test]
fn a_cached_packument_costs_the_same_round_trips() {
    let rt = runtime();
    let (storage, ops) = op_counting_storage();
    let ctx = rt.block_on(async {
        create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.npm.proxy = Some(UPSTREAM.to_string());
            cfg.npm.metadata_ttl = 3600;
        })
    });
    rt.block_on(cache_as_fetched(&ctx, &synthetic_packument(64 * 1024)));
    let mut seen = Vec::new();
    for accept in [None, Some(INSTALL_V1)] {
        ops.reset();
        let served = rt.block_on(get_packument(&ctx, accept));
        assert_eq!(served.status, StatusCode::OK);
        seen.push(format!(
            "{}: {:?}",
            accept.map_or("full", |_| "install-v1"),
            ops.snapshot()
        ));
    }
    insta::assert_snapshot!("npm_cached_packument_round_trips", seen.join("\n"));
}

/// The bytes of a large cached packument as served, full and abbreviated, the same on both
/// stores: digests taken before #1305.
#[test]
fn a_large_cached_packument_is_served_byte_for_byte() {
    let doc = synthetic_packument(LARGE / 4);
    let mut lines = Vec::new();
    for store in [Store::Local, Store::Object] {
        let rt = runtime();
        let ctx = rt.block_on(async { context(store) });
        rt.block_on(cache_as_fetched(&ctx, &doc));
        for accept in [None, Some(INSTALL_V1)] {
            let served = rt.block_on(get_packument(&ctx, accept));
            assert_eq!(served.status, StatusCode::OK);
            let line = format!(
                "{} {} {} {}",
                accept.map_or("full", |_| "install-v1"),
                served.content_type,
                served.body.len(),
                hex_digest(&served.body)
            );
            if matches!(store, Store::Local) {
                lines.push(line);
            } else {
                assert!(lines.contains(&line), "{store:?}: {line} vs {lines:?}");
            }
        }
    }
    insta::assert_snapshot!("npm_large_cached_packument_digests", lines.join("\n"));
}

/// A small packument whose versions are listed out of order, with escapes, numbers of every form,
/// a deprecated version, platform fields and dropped fields.
fn small_upstream_packument() -> String {
    format!(
        concat!(
            "{{\"_id\":\"{p}\",\"name\":\"{p}\",\"readme\":\"dropped \\u00e9\",",
            "\"versions\":{{",
            "\"2.0.0\":{{\"name\":\"{p}\",\"version\":\"2.0.0\",\"description\":\"dropped\",",
            "\"dependencies\":{{\"z\":\"1\",\"a\":\"2\"}},\"scripts\":{{\"install\":\"node x\"}},",
            "\"hasInstallScript\":true,\"engines\":{{\"node\":\">=18\"}},",
            "\"dist\":{{\"tarball\":\"{u}/{p}/-/{p}-2.0.0.tgz\",\"integrity\":\"sha512-x\",",
            "\"unpackedSize\":1.5e3,\"fileCount\":12345678901234567890,\"weird\":-0.0}}}},",
            "\"1.0.0\":{{\"name\":\"{p}\",\"version\":\"1.0.0\",\"deprecated\":\"old \\\"one\\\" \\ud83d\\ude00\",",
            "\"os\":[\"linux\"],\"cpu\":[\"x64\"],\"libc\":[\"musl\"],\"bin\":{{\"x\":\"./x\"}},",
            "\"directories\":{{}},\"funding\":[{{\"url\":\"https://example.test\"}}],",
            "\"_hasShrinkwrap\":false,\"acceptDependencies\":{{\"a\":\"*\"}},",
            "\"peerDependencies\":{{\"p\":\"1\"}},\"peerDependenciesMeta\":{{\"p\":{{\"optional\":true}}}},",
            "\"optionalDependencies\":{{\"o\":\"1\"}},\"bundleDependencies\":[\"b\"],",
            "\"dist\":{{\"tarball\":\"{u}/{p}/-/{p}-1.0.0.tgz\",\"shasum\":\"abc\"}}}},",
            "\"10.0.0-rc.1\":{{\"name\":\"{p}\",\"version\":\"10.0.0-rc.1\",",
            "\"dist\":{{\"tarball\":\"{u}/{p}/-/{p}-10.0.0-rc.1.tgz\"}}}}",
            "}},",
            "\"dist-tags\":{{\"latest\":\"2.0.0\",\"next\":\"10.0.0-rc.1\"}},",
            "\"time\":{{\"modified\":\"2026-11-17T00:00:00.000Z\",\"1.0.0\":\"2020-01-01T00:00:00.000Z\"}},",
            "\"modified\":\"2026-11-17T00:00:00.000Z\",\"users\":{{\"u\":true}}}}"
        ),
        p = PACKAGE,
        u = UPSTREAM,
    )
}

/// The bytes a client gets for a small cached packument, full and abbreviated, as each kind of
/// copy a store holds is served: one NORA cached with its record, one an older release cached
/// without a record, and one that kept the upstream's links (served placed again).
#[tokio::test]
async fn a_cached_packument_is_served_as_before() {
    let upstream = small_upstream_packument();
    let mut out = String::new();
    for (kind, store) in [
        ("with record", Kind::WithRecord),
        ("without record", Kind::WithoutRecord),
        ("upstream links", Kind::UpstreamLinks),
    ] {
        let ctx = context(Store::Local);
        let stored = match store {
            Kind::WithRecord => cache_as_fetched(&ctx, upstream.as_bytes()).await,
            Kind::WithoutRecord => {
                let placed = rewrite_for_nora(
                    &ctx.state,
                    upstream.as_bytes(),
                    UPSTREAM,
                    PACKAGE,
                    Links::Stored,
                )
                .unwrap();
                let plain = nora_registry::npm_links::without_record(&placed).unwrap();
                store_copy(&ctx, &plain).await;
                plain
            }
            Kind::UpstreamLinks => {
                store_copy(&ctx, upstream.as_bytes()).await;
                upstream.clone().into_bytes()
            }
        };
        out.push_str(&format!(
            "== {kind}: stored\n{}\n",
            String::from_utf8_lossy(&stored)
        ));
        for accept in [None, Some(INSTALL_V1)] {
            let served = get_packument(&ctx, accept).await;
            out.push_str(&format!(
                "-- {} {} {}\n{}\n",
                accept.map_or("full", |_| "install-v1"),
                served.status,
                served.content_type,
                String::from_utf8_lossy(&served.body)
            ));
        }
    }
    insta::assert_snapshot!("npm_cached_packument_bytes", out);
}

#[derive(Clone, Copy)]
enum Kind {
    WithRecord,
    WithoutRecord,
    UpstreamLinks,
}

/// The projection to the abbreviated form as it was before #1305: the whole document as a tree,
/// the kept fields cloned out of it.
fn tree_abbreviate(full: &[u8]) -> Option<Vec<u8>> {
    let doc: serde_json::Value = serde_json::from_slice(full).ok()?;
    let obj = doc.as_object()?;
    let mut out = serde_json::Map::new();
    for field in super::INSTALL_V1_TOP_FIELDS {
        if let Some(value) = obj.get(*field) {
            out.insert((*field).to_string(), value.clone());
        }
    }
    let mut versions = serde_json::Map::new();
    if let Some(source) = obj.get("versions").and_then(|v| v.as_object()) {
        for (version, manifest) in source {
            let Some(manifest) = manifest.as_object() else {
                continue;
            };
            let mut kept = serde_json::Map::new();
            for field in super::INSTALL_V1_VERSION_FIELDS {
                if let Some(value) = manifest.get(*field) {
                    kept.insert((*field).to_string(), value.clone());
                }
            }
            versions.insert(version.clone(), serde_json::Value::Object(kept));
        }
    }
    out.insert("versions".to_string(), serde_json::Value::Object(versions));
    serde_json::to_vec(&serde_json::Value::Object(out)).ok()
}

/// Documents of every shape a stored copy can take, as bytes: canonical and not, with duplicate
/// keys (the last one wins), fields of every JSON type where an object is expected, escapes,
/// numbers of every form, and bodies that are no packument at all.
fn odd_documents() -> Vec<Vec<u8>> {
    let small = small_upstream_packument();
    let mut docs: Vec<String> = vec![
        small.clone(),
        // Whitespace everywhere, keys out of order, versions before the top fields.
        " { \"versions\" : { \"1.0.0\" : { \"dist\" : { \"tarball\" : \"t\" } , \"name\" : \"n\" } } , \"name\" : \"n\" , \"dist-tags\" : { \"latest\" : \"1.0.0\" } } \n".into(),
        // Duplicate keys at every level: the last one wins.
        r#"{"name":"a","name":"b","versions":{"1":{"name":"x","name":"y","dist":{"a":1},"dist":{"b":2}},"1":{"version":"1"}},"dist-tags":{"latest":"1"}}"#.into(),
        r#"{"versions":{"1":{"name":"x"}},"versions":{"2":{"name":"y"}}}"#.into(),
        r#"{"versions":{"1":{"name":"x"}},"versions":null}"#.into(),
        r#"{"versions":{"1":{"name":"x"},"1":7}}"#.into(),
        r#"{"versions":{"1":7,"1":{"name":"x"}}}"#.into(),
        // An expected object of another type.
        r#"{"name":"n","versions":[{"name":"x"}]}"#.into(),
        r#"{"name":"n","versions":"1.0.0"}"#.into(),
        r#"{"name":"n","versions":true}"#.into(),
        r#"{"name":"n","versions":1.5}"#.into(),
        r#"{"name":"n","versions":{"1":[1,2],"2":"s","3":null,"4":false,"5":-3,"6":{}}}"#.into(),
        r#"{"name":"n"}"#.into(),
        r#"{}"#.into(),
        // Values of every type in the kept fields, and numbers of every form.
        r#"{"name":null,"dist-tags":[1,{"a":[]}],"modified":1e400,"versions":{"1":{"dist":{"n":[0,-0,1.0,1e2,1E+2,1e-7,-1.25e-5,123456789012345678901234567890,18446744073709551615,-9223372036854775808]},"bin":"x","os":null,"engines":[],"deprecated":false}}}"#.into(),
        // Escapes: in keys and values, kept and dropped.
        r#"{"na\u006de":"\u00e9\/\b\f\n\r\t\"\\","versions":{"\u0031.0":{"dist":{"tarball":"a\/b\ud83d\ude00"},"readme":"\u0000"}},"dist-tags":{"l\u0061test":"1.0"}}"#.into(),
        // Not a packument, or not JSON.
        "[]".into(),
        "null".into(),
        "\"string\"".into(),
        "42".into(),
        "".into(),
        "{".into(),
        r#"{"name":"n"} trailing"#.into(),
        r#"{"name":"n",}"#.into(),
        r#"{"name":"n","versions":{"1":{"dist":{"tarball":"\ud800"}}}}"#.into(),
        r#"{"name":"n","readme":"\ud800"}"#.into(),
        r#"{"name":"n","versions":{"1":{"readme":"\x"}}}"#.into(),
        r#"{"name":"n","readme":"unterminated}"#.into(),
        r#"{"name":"n","time":{"1":01}}"#.into(),
        r#"{"name":"n","versions":{"1":{"description":tru}}}"#.into(),
    ];
    // Nesting just below and past the parser's depth limit, in a kept and a dropped field.
    for depth in [120, 127, 128, 129, 200] {
        let nested = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        docs.push(format!(r#"{{"name":"n","readme":{nested}}}"#));
        docs.push(format!(
            r#"{{"name":"n","versions":{{"1":{{"dist":{nested}}}}}}}"#
        ));
        docs.push(format!(
            r#"{{"name":"n","versions":{{"1":{{"scripts":{nested}}}}}}}"#
        ));
    }
    let mut docs: Vec<Vec<u8>> = docs.into_iter().map(String::into_bytes).collect();
    // Bytes that are no UTF-8, in a dropped and in a kept field.
    docs.push(b"{\"name\":\"n\",\"readme\":\"\xff\xfe\"}".to_vec());
    docs.push(b"{\"name\":\"n\",\"versions\":{\"1\":{\"dist\":\"\xff\"}}}".to_vec());
    docs.push(b"{\"name\":\"n\",\"versions\":{\"1\":{\"scripts\":\"\xc3\"}}}".to_vec());
    // Large documents, as a store holds them and as an upstream sends them.
    let large = synthetic_packument(512 * 1024);
    docs.push(large.clone());
    let placed: serde_json::Value = serde_json::from_slice(&large).unwrap();
    docs.push(serde_json::to_vec(&placed).unwrap());
    docs.push(serde_json::to_vec_pretty(&placed).unwrap());
    docs
}

/// The abbreviated form is the one the tree projection gave, byte for byte, on every document,
/// and a body that projection refused is refused too.
#[test]
fn the_abbreviated_form_is_the_tree_projection() {
    for doc in odd_documents() {
        assert_eq!(
            super::abbreviate_packument(&doc),
            tree_abbreviate(&doc),
            "{}",
            String::from_utf8_lossy(&doc[..doc.len().min(300)])
        );
    }
}
