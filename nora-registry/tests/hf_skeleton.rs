// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The Hugging Face format is mounted by `nora serve` itself, not only by the test router.
//! No test here reaches the network: the upstream is switched off (`NORA_HF_PROXY=`), so a
//! mounted file route answers 404 with its reason, and the datasets route its 501 — or it is
//! a local server on a thread of the test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(env: &[(&str, &str)]) -> Server {
    serve_in(tempfile::tempdir().unwrap(), env)
}

/// `nora serve` with its storage under `dir/data`, which a test may have prepared. Ready means
/// this server's own start-up line, not any listener on the port: a port picked here and
/// released could be taken by another test's server in between, and a connection to that one
/// would pass for this one. If the port was taken, this server cannot bind and exits; another
/// port is tried.
fn serve_in(dir: tempfile::TempDir, env: &[(&str, &str)]) -> Server {
    for _ in 0..5 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let log = dir.path().join("nora.log");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nora"));
        cmd.arg("serve")
            .current_dir(dir.path())
            .env_remove("NORA_CONFIG_PATH")
            .env_remove("NORA_HF_ENABLED")
            .env_remove("NORA_HF_PROXY")
            .env_remove("NORA_REGISTRIES_ENABLE")
            .env("NORA_HOST", "127.0.0.1")
            .env("NORA_PORT", port.to_string())
            .env("NORA_STORAGE_PATH", dir.path().join("data"))
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log).unwrap())
            .stderr(Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let started = loop {
            assert!(Instant::now() < deadline, "nora serve did not start");
            if child.try_wait().unwrap().is_some() {
                break false;
            }
            let lines = std::fs::read_to_string(&log).unwrap_or_default();
            if lines.lines().any(|line| {
                line.contains("Nora started") && line.contains(&format!("127.0.0.1:{port}"))
            }) {
                break true;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if !started {
            continue;
        }
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "nora serve did not accept");
            std::thread::sleep(Duration::from_millis(50));
        }
        return Server {
            child,
            port,
            _dir: dir,
        };
    }
    panic!("nora serve did not start on any of five ports");
}

/// The whole response to `method path`, over a plain HTTP/1.1 connection.
fn exchange(port: u16, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// The status line and headers of `method path`.
fn head_of(port: u16, method: &str, path: &str) -> String {
    exchange(port, method, path)
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .to_string()
}

/// The body of `GET path`, chunked transfer decoded when the server used it.
fn body_of(port: u16, path: &str) -> String {
    let response = exchange(port, "GET", path);
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or(("", ""));
    if !head.to_lowercase().contains("transfer-encoding: chunked") {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 || tail.len() < n {
            break;
        }
        out.push_str(&tail[..n]);
        rest = tail[n..].trim_start_matches("\r\n");
    }
    out
}

const RESOLVE: &str = "/hf/org/model/resolve/main/config.json";
const DATASETS: &str = "/hf/datasets/org/data/resolve/main/train.parquet";

/// Whether the response head carries NORA's reason header — a mounted hf route — as opposed
/// to the router's bare 404.
fn has_reason(head: &str) -> bool {
    head.to_lowercase().contains("x-error-message:")
}

#[test]
fn enabled_by_env_the_routes_are_mounted() {
    let server = serve(&[("NORA_HF_ENABLED", "true"), ("NORA_HF_PROXY", "")]);
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(
        head.starts_with("HTTP/1.1 404") && has_reason(&head),
        "{head}"
    );
    let head = head_of(server.port, "HEAD", DATASETS);
    assert!(
        head.starts_with("HTTP/1.1 501") && has_reason(&head),
        "{head}"
    );
    // The JSON body as `nora serve` assembles the response — not only as the test
    // router does.
    let body = body_of(server.port, DATASETS);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let error = json["error"].as_str().unwrap_or_default();
    assert!(error.contains("datasets"), "body: {body:?}");
    assert!(body_of(server.port, "/health").contains("\"hf\""));
}

#[test]
fn off_by_default_the_routes_do_not_exist() {
    let server = serve(&[]);
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(
        head.starts_with("HTTP/1.1 404") && !has_reason(&head),
        "{head}"
    );
}

/// `all` predates the format: it does not opt an operator in.
#[test]
fn all_registries_leave_hf_off_until_it_is_named() {
    let server = serve(&[("NORA_REGISTRIES_ENABLE", "all"), ("NORA_HF_PROXY", "")]);
    let head = head_of(server.port, "HEAD", DATASETS);
    assert!(
        head.starts_with("HTTP/1.1 404") && !has_reason(&head),
        "{head}"
    );
    assert!(!body_of(server.port, "/health").contains("\"hf\""));
    let server = serve(&[("NORA_REGISTRIES_ENABLE", "all,hf"), ("NORA_HF_PROXY", "")]);
    assert!(head_of(server.port, "HEAD", DATASETS).starts_with("HTTP/1.1 501"));
}

/// A cache fill a crash cut off leaves its temp file behind; the next start removes it once
/// it is old enough to belong to no running fill, and keeps a fresh one.
#[test]
fn a_start_removes_stale_fill_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let temps = dir.path().join("data/tmp/hf-proxy");
    std::fs::create_dir_all(&temps).unwrap();
    let stale = temps.join("stale.part");
    let fresh = temps.join("fresh.part");
    std::fs::write(&stale, b"cut off").unwrap();
    std::fs::write(&fresh, b"under way").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(5 * 60 * 60))
        .unwrap();
    let _server = serve_in(dir, &[("NORA_HF_ENABLED", "true"), ("NORA_HF_PROXY", "")]);
    assert!(!stale.exists(), "a stale fill temp file survived the start");
    assert!(fresh.exists(), "a fresh fill temp file was removed");
}

/// A local upstream on a thread of its own: every request gets `answer`, and its request
/// line is kept.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

fn upstream(answer: String) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            log.lock().unwrap().push(line);
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    Upstream { port, seen }
}

/// The client `nora serve` walks the Hub with does not follow redirects: the commit and
/// digest ride on the 302 to the CDN only, and a HEAD answers from that hop without asking
/// the CDN — with a client that followed the 302 the CDN would be asked, and its answer
/// carries no commit. The handler tests build their own client; this one is the server's.
#[test]
fn the_served_hub_client_walks_redirects_itself() {
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    let cdn = upstream(
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody".to_string(),
    );
    let hub = upstream(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/blob\r\nX-Repo-Commit: {COMMIT}\r\n\
         X-Linked-Etag: \"{}\"\r\nX-Linked-Size: 4\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        cdn.port,
        "a".repeat(64)
    ));
    let proxy = format!("http://127.0.0.1:{}", hub.port);
    let server = serve(&[("NORA_HF_ENABLED", "true"), ("NORA_HF_PROXY", &proxy)]);
    let head = head_of(
        server.port,
        "HEAD",
        "/hf/org/model/resolve/main/model.safetensors",
    )
    .to_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains(&format!("x-repo-commit: {COMMIT}")), "{head}");
    assert!(!head.contains("location:"), "{head}");
    assert_eq!(
        hub.seen.lock().unwrap().len(),
        1,
        "the hub was not asked once"
    );
    assert!(
        cdn.seen.lock().unwrap().is_empty(),
        "the CDN was asked: the server's client followed the redirect"
    );
}
