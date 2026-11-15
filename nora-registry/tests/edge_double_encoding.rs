// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The path guard of the server as it ships: `nora serve` run as a process and sent raw request
//! lines over a socket, so the stack under test is the one `run_server` and `serve_connection`
//! assemble, not a router a test builds (which leaves the edge layers out). The npm upstream is a
//! local server on a thread of the test that records every path it is asked for.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// An npm upstream that answers every GET with a packument named after the last segment and
/// records the path of each request.
fn upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&asked);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = line.split(' ').nth(1).unwrap_or_default().to_string();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let name = path.rsplit('/').next().unwrap_or_default().to_string();
            record.lock().unwrap().push(path);
            let body =
                format!(r#"{{"_id":"{name}","name":"{name}","versions":{{}},"dist-tags":{{}}}}"#);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, asked)
}

/// `method path` sent as it is, with no client between to normalize it: the status and the body.
fn raw(port: u16, method: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer[9..12].parse().unwrap();
    let body = answer
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    (status, body)
}

/// A path that still holds a `%` once decoded is refused with 400 before any handler, whatever
/// the method, format, depth, length or form of the over-encoding, and the upstream is asked
/// nothing; a null byte keeps its own reason. A path encoded once reaches the upstream, so the
/// upstream would have seen a refused path that got through.
#[test]
fn the_shipped_server_refuses_over_encoded_paths_before_the_upstream() {
    let (upstream_port, asked) = upstream();
    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("data");
    let proxy = format!("http://127.0.0.1:{upstream_port}/pkgs/");
    let common::Started::Serving(nora) = common::start(
        dir.path(),
        &[
            ("NORA_STORAGE_PATH", storage.to_str().unwrap()),
            ("NORA_NPM_PROXY", &proxy),
        ],
    ) else {
        panic!("nora did not start");
    };
    let long = format!("/npm/@acme/{}/%252e%252e/x", "a".repeat(4000));
    let refused = [
        ("GET", "/npm/%252e%252e/x"),
        ("GET", "/npm/a/b/c/%252e%252e/x"),
        ("GET", long.as_str()),
        ("GET", "/npm/ev%2569l-pkg"),
        ("GET", "/npm/%25zz"),
        ("GET", "/npm/%%32%65%%32%65/x"),
        ("GET", "/npm/%%36%35vil-pkg"),
        ("GET", "/npm/%2%65%2%65/x"),
        ("GET", "/npm/%%34%30acme%2Fcore"),
        ("GET", "/go/%25252e%25252e/x/@v/list"),
        ("GET", "/npm/@acme%2F%2565vil-pkg"),
        ("GET", "/npm/%25%32%65%25%32%65/x"),
        ("GET", "/npm/foo%"),
        ("GET", "/v2/%252e%252e/x/manifests/latest"),
        ("HEAD", "/npm/%252e%252e/x"),
        ("POST", "/npm/%252e%252e/x"),
        ("PUT", "/npm/%2540acme%2Fcore"),
        ("PATCH", "/npm/%25%34%30acme%2Fcore"),
        ("DELETE", "/npm/%%32%65%%32%65/x"),
        ("OPTIONS", "/npm/%252e%252e/x"),
    ];
    for (method, path) in refused {
        let (status, body) = raw(nora.port, method, path);
        assert_eq!(status, 400, "{method} {path}: {body}");
        if method != "HEAD" {
            assert!(body.contains("double-encoded"), "{method} {path}: {body}");
        }
    }
    for path in ["/npm/%00", "/npm/%2500", "/npm/%00x", "/npm/a%00/b"] {
        let (status, body) = raw(nora.port, "GET", path);
        assert_eq!(status, 400, "{path}: {body}");
        assert!(body.contains("null byte"), "{path}: {body}");
    }
    assert_eq!(
        *asked.lock().unwrap(),
        Vec::<String>::new(),
        "the upstream was asked"
    );

    let (status, body) = raw(nora.port, "GET", "/npm/lodash");
    assert_eq!(status, 200, "{body}");
    assert_eq!(*asked.lock().unwrap(), ["/pkgs/lodash"]);
}

/// `nora serve` with an npm proxy at the recording upstream and the settings in `envs`.
fn serve(dir: &std::path::Path, upstream_port: u16, envs: &[(&str, &str)]) -> common::Nora {
    let storage = dir.join("data");
    let proxy = format!("http://127.0.0.1:{upstream_port}/pkgs/");
    let mut all = vec![
        ("NORA_STORAGE_PATH", storage.to_str().unwrap()),
        ("NORA_NPM_PROXY", proxy.as_str()),
    ];
    all.extend_from_slice(envs);
    match common::start(dir, &all) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
    }
}

/// HTTP/2 reaches the same stack: over a cleartext HTTP/2 connection a refused path is 400
/// with its reason and the upstream is asked nothing, while a plain name reaches it.
#[test]
fn the_shipped_server_refuses_over_encoded_paths_over_http2() {
    let (upstream_port, asked) = upstream();
    let dir = tempfile::tempdir().unwrap();
    let nora = serve(dir.path(), upstream_port, &[]);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .no_proxy()
        .timeout(common::DEADLINE)
        .build()
        .unwrap();
    let ask = |method: reqwest::Method, path: &str| {
        let url = format!("http://127.0.0.1:{}{path}", nora.port);
        runtime.block_on(async {
            let response = client.request(method, url).send().await.unwrap();
            assert_eq!(response.version(), reqwest::Version::HTTP_2, "{path}");
            let status = response.status().as_u16();
            (status, response.text().await.unwrap())
        })
    };
    for (method, path) in [
        (reqwest::Method::GET, "/npm/%252e%252e/x"),
        (reqwest::Method::GET, "/npm/%%32%65%%32%65/x"),
        (reqwest::Method::GET, "/npm/%25%32%65%25%32%65/x"),
        (reqwest::Method::POST, "/npm/%2540acme%2Fcore"),
        (reqwest::Method::GET, "/v2/%252e%252e/x/manifests/latest"),
    ] {
        let (status, body) = ask(method.clone(), path);
        assert_eq!(status, 400, "{method} {path}: {body}");
        assert!(body.contains("double-encoded"), "{method} {path}: {body}");
    }
    let (status, body) = ask(reqwest::Method::GET, "/npm/%00x");
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("null byte"), "{body}");
    assert_eq!(
        *asked.lock().unwrap(),
        Vec::<String>::new(),
        "the upstream was asked"
    );

    let (status, body) = ask(reqwest::Method::GET, "/npm/lodash");
    assert_eq!(status, 200, "{body}");
    assert_eq!(*asked.lock().unwrap(), ["/pkgs/lodash"]);
}

/// The edge is the outermost layer of the shipped server: with auth on, an anonymous refused
/// path is 400 from the edge, not 401 from auth, and the request metric does not count it,
/// while the metric counts the 401 auth gives a clean anonymous path.
#[test]
fn the_shipped_server_refuses_over_encoded_paths_outside_auth_and_metrics() {
    let (upstream_port, asked) = upstream();
    let dir = tempfile::tempdir().unwrap();
    let htpasswd = dir.path().join("htpasswd");
    let hash = bcrypt::hash("secret", 4).unwrap();
    std::fs::write(&htpasswd, format!("admin:{hash}\n")).unwrap();
    let tokens = dir.path().join("tokens");
    let nora = serve(
        dir.path(),
        upstream_port,
        &[
            ("NORA_AUTH_ENABLED", "true"),
            ("NORA_AUTH_PUBLIC_METRICS", "true"),
            ("NORA_AUTH_HTPASSWD_FILE", htpasswd.to_str().unwrap()),
            ("NORA_AUTH_TOKEN_STORAGE", tokens.to_str().unwrap()),
        ],
    );
    for (method, path) in [
        ("GET", "/npm/%252e%252e/x"),
        ("PUT", "/npm/%2540acme%2Fcore"),
        ("POST", "/npm/%%32%65%%32%65/x"),
        ("GET", "/v2/%252e%252e/x/manifests/latest"),
    ] {
        let (status, body) = raw(nora.port, method, path);
        assert_eq!(status, 400, "{method} {path}: {body}");
        assert!(body.contains("double-encoded"), "{method} {path}: {body}");
    }
    let (status, body) = raw(nora.port, "GET", "/npm/%00x");
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("null byte"), "{body}");

    let (status, body) = raw(nora.port, "GET", "/npm/lodash");
    assert_eq!(status, 401, "{body}");
    let (status, metrics) = raw(nora.port, "GET", "/metrics");
    assert_eq!(status, 200, "{metrics}");
    let counted: Vec<&str> = metrics
        .lines()
        .filter(|line| line.starts_with("nora_http_requests_total{"))
        .collect();
    assert!(
        counted.iter().any(|line| line.contains("status=\"401\"")),
        "{counted:?}"
    );
    assert!(
        !counted.iter().any(|line| line.contains("status=\"400\"")),
        "{counted:?}"
    );
    assert_eq!(
        *asked.lock().unwrap(),
        Vec::<String>::new(),
        "the upstream was asked"
    );
}
