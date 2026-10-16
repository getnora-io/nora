// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The Hugging Face format is mounted by `nora serve` itself, not only by the test router:
//! with `NORA_HF_ENABLED=true` the file route answers its 501 until the download path
//! lands, and without it the routes do not exist.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nora"));
    cmd.arg("serve")
        .current_dir(dir.path())
        .env_remove("NORA_CONFIG_PATH")
        .env_remove("NORA_HF_ENABLED")
        .env_remove("NORA_REGISTRIES_ENABLE")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.path().join("data"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "nora serve did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    Server {
        child,
        port,
        _dir: dir,
    }
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

#[test]
fn enabled_by_env_the_routes_answer_501() {
    let server = serve(&[("NORA_HF_ENABLED", "true")]);
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(head.starts_with("HTTP/1.1 501"), "{head}");
    assert!(
        head.to_lowercase().contains("x-error-message:"),
        "the reason must travel in a header on HEAD: {head}"
    );
    // And in the JSON body on GET, as `nora serve` assembles the response — not only as
    // the test router does.
    let body = body_of(server.port, RESOLVE);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let error = json["error"].as_str().unwrap_or_default();
    assert!(error.contains("not implemented"), "body: {body:?}");
    assert!(body_of(server.port, "/health").contains("\"hf\""));
}

#[test]
fn off_by_default_the_routes_do_not_exist() {
    let server = serve(&[]);
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
}

/// `all` predates the format: it does not opt an operator in.
#[test]
fn all_registries_leave_hf_off_until_it_is_named() {
    let server = serve(&[("NORA_REGISTRIES_ENABLE", "all")]);
    assert!(head_of(server.port, "HEAD", RESOLVE).starts_with("HTTP/1.1 404"));
    assert!(!body_of(server.port, "/health").contains("\"hf\""));
    let server = serve(&[("NORA_REGISTRIES_ENABLE", "all,hf")]);
    assert!(head_of(server.port, "HEAD", RESOLVE).starts_with("HTTP/1.1 501"));
}
