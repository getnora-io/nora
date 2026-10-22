// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! What `nora serve` writes down of an npm upstream's URL, where the handler tests build their
//! own context.
//! No test here reaches the network: upstreams are local servers on threads of the test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `nora serve` with its storage in a fresh directory. Ready means this server's own start-up
/// line, not any listener on the port; a port taken in between makes it exit, and another port
/// is tried.
fn serve(env: &[(&str, &str)]) -> Server {
    let dir = tempfile::tempdir().unwrap();
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
            .env_remove("NORA_REGISTRIES_ENABLE")
            .env_remove("NORA_NPM_PROXY_AUTH")
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
        return Server { child, port, dir };
    }
    panic!("nora serve did not start on any of five ports");
}

/// The status line of `GET path`, over a plain HTTP/1.1 connection.
fn status_of(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response.lines().next().unwrap_or("").to_string()
}

/// A local upstream on a thread of its own: a request gets what `answer` makes of its request
/// line, and the line is kept.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

fn upstream(answer: impl Fn(&str) -> String + Send + 'static) -> Upstream {
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
            let _ = stream.write_all(answer(&line).as_bytes());
            log.lock().unwrap().push(line);
        }
    });
    Upstream { port, seen }
}

const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The quarantine ledger and the server's log name the upstream a tarball came from without
/// the credential in its URL.
#[test]
fn the_credential_in_the_upstream_url_is_not_written_down() {
    let registry = upstream(|line| {
        if line.starts_with("GET /pkg/-/pkg-1.0.0.tgz ") {
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nTGZ".to_string()
        } else {
            NOT_FOUND.to_string()
        }
    });
    let server = serve(&[
        (
            "NORA_NPM_PROXY",
            &format!("http://nora-user:s3cret-pass@127.0.0.1:{}", registry.port),
        ),
        ("NORA_CURATION_QUARANTINE", "observe"),
        ("RUST_LOG", "debug"),
    ]);
    let status = status_of(server.port, "/npm/pkg/-/pkg-1.0.0.tgz");
    assert!(status.contains(" 200 "), "{status}");
    let ledger = server.dir.path().join("data").join("quarantine.jsonl");
    let deadline = Instant::now() + Duration::from_secs(10);
    let written = loop {
        let written = std::fs::read_to_string(&ledger).unwrap_or_default();
        if written.contains("sha256:") || Instant::now() > deadline {
            break written;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        written.contains(&format!("127.0.0.1:{}", registry.port)),
        "the ledger does not name the upstream: {written:?}"
    );
    let log = std::fs::read_to_string(server.dir.path().join("nora.log")).unwrap();
    for (what, text) in [("ledger", &written), ("log", &log)] {
        for secret in ["s3cret-pass", "nora-user"] {
            assert!(!text.contains(secret), "{what} holds {secret}: {text}");
        }
    }
}
