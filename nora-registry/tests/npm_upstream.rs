// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! What `nora serve` does with an npm upstream, where the handler tests build their own
//! context: the client it fetches tarballs with, and what it writes down of the upstream's URL.
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
/// line, and the line is kept, ` +authorization` after it when the request carried one.
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
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            let line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let _ = stream.write_all(answer(&line).as_bytes());
            let authorized = head.lines().any(|h| h.starts_with("authorization:"));
            log.lock().unwrap().push(format!(
                "{line}{}",
                if authorized { " +authorization" } else { "" }
            ));
        }
    });
    Upstream { port, seen }
}

const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A packument listing `pkg@1.0.0` at `http://127.0.0.1:<port>/pkg/-/pkg-1.0.0.tgz`: the
/// upstream's origin, as a registry names its own tarballs.
fn listing(port: u16) -> String {
    let body = format!(
        r#"{{"name":"pkg","versions":{{"1.0.0":{{"dist":{{"tarball":"http://127.0.0.1:{port}/pkg/-/pkg-1.0.0.tgz"}}}}}}}}"#
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A listed tarball the upstream keeps on another origin (GitHub Packages' storage host) is
/// fetched from there, and the upstream's credential goes no further than its origin: neither
/// the first hop off it nor a later one on that other host carries it.
#[test]
fn a_tarball_redirected_to_another_origin_is_fetched_without_the_credential() {
    let foreign = upstream(|line| {
        if line.starts_with("GET /hop1 ") {
            "HTTP/1.1 302 Found\r\nLocation: /files/pkg-1.0.0.tgz\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string()
        } else {
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nELSEWHERE".to_string()
        }
    });
    let to = foreign.port;
    let registry = Arc::new(Mutex::new(0u16));
    let own = Arc::clone(&registry);
    let registry_upstream = upstream(move |line| {
        if line.starts_with("GET /pkg/-/pkg-1.0.0.tgz ") {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{to}/hop1\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        } else if line.starts_with("GET /pkg ") {
            listing(*own.lock().unwrap())
        } else {
            NOT_FOUND.to_string()
        }
    });
    *registry.lock().unwrap() = registry_upstream.port;
    let server = serve(&[
        (
            "NORA_NPM_PROXY",
            &format!(
                "http://nora-user:s3cret-pass@127.0.0.1:{}",
                registry_upstream.port
            ),
        ),
        ("RUST_LOG", "debug"),
    ]);
    let status = status_of(server.port, "/npm/pkg/-/pkg-1.0.0.tgz");
    assert!(status.contains(" 200 "), "{status}");
    let asked = registry_upstream.seen.lock().unwrap().clone();
    assert!(
        asked
            .iter()
            .any(|line| line.starts_with("GET /pkg/-/pkg-1.0.0.tgz ")
                && line.ends_with(" +authorization")),
        "the upstream was not asked with its credential: {asked:?}"
    );
    let elsewhere = foreign.seen.lock().unwrap().clone();
    assert_eq!(elsewhere.len(), 2, "{elsewhere:?}");
    assert!(
        elsewhere
            .iter()
            .all(|line| !line.contains("+authorization")),
        "the credential left the upstream's origin: {elsewhere:?}"
    );
    // Of where it pointed, the log names only the host: the path names the package.
    let log = std::fs::read_to_string(server.dir.path().join("nora.log")).unwrap();
    assert!(log.contains(r#""to":"127.0.0.1""#), "{log}");
    assert!(!log.contains("/hop1"), "{log}");
    for secret in ["s3cret-pass", "nora-user"] {
        assert!(!log.contains(secret), "{log}");
    }
}

/// The quarantine ledger and the server's log name the upstream a tarball came from without
/// the credential in its URL.
#[test]
fn the_credential_in_the_upstream_url_is_not_written_down() {
    let port = Arc::new(Mutex::new(0u16));
    let own = Arc::clone(&port);
    let registry = upstream(move |line| {
        if line.starts_with("GET /pkg/-/pkg-1.0.0.tgz ") {
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nTGZ".to_string()
        } else if line.starts_with("GET /pkg ") {
            listing(*own.lock().unwrap())
        } else {
            NOT_FOUND.to_string()
        }
    });
    *port.lock().unwrap() = registry.port;
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
    let seen = registry.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|line| line.starts_with("GET /pkg/-/pkg-1.0.0.tgz ")),
        "the tarball did not come from the upstream: {seen:?}"
    );
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

/// A log line that carries the upstream's URL as it is (the retry of a 5xx) is masked on
/// stdout too.
#[test]
fn a_retried_upstream_url_is_logged_without_its_credential() {
    let registry = upstream(|_| {
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string()
    });
    let server = serve(&[
        (
            "NORA_NPM_PROXY",
            &format!("http://nora-user:s3cret-pass@127.0.0.1:{}", registry.port),
        ),
        ("RUST_LOG", "debug"),
    ]);
    let _ = status_of(server.port, "/npm/pkg");
    let log = std::fs::read_to_string(server.dir.path().join("nora.log")).unwrap();
    assert!(log.contains("retrying"), "no retry logged: {log}");
    for secret in ["s3cret-pass", "nora-user"] {
        assert!(!log.contains(secret), "log holds {secret}: {log}");
    }
}
