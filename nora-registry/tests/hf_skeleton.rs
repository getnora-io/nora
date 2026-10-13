// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The Hugging Face format is mounted by `nora serve` itself, not only by the test router:
//! `NORA_HF_ENABLED=true` puts `/hf/` behind the skeleton's 501, and without it the routes
//! do not exist.

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

fn serve(hf_enabled: Option<&str>) -> Server {
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
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.path().join("data"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(value) = hf_enabled {
        cmd.env("NORA_HF_ENABLED", value);
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

/// The status line and headers of `method path`, over a plain HTTP/1.1 connection.
fn head_of(port: u16, method: &str, path: &str) -> String {
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
    response.split("\r\n\r\n").next().unwrap_or("").to_string()
}

const RESOLVE: &str = "/hf/org/model/resolve/main/config.json";

#[test]
fn enabled_by_env_the_routes_answer_501() {
    let server = serve(Some("true"));
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(head.starts_with("HTTP/1.1 501"), "{head}");
    assert!(
        head.to_lowercase().contains("x-error-message:"),
        "the reason must travel in a header on HEAD: {head}"
    );
    let health = head_of(server.port, "GET", "/health");
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
}

#[test]
fn off_by_default_the_routes_do_not_exist() {
    let server = serve(None);
    let head = head_of(server.port, "HEAD", RESOLVE);
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
}
