// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The local write probe of the server as it ships. A test build compiles the `cfg(test)`
//! code, so what `cfg(not(test))` code does to `/ready` shows only on the binary: here `nora
//! serve` runs as a process on a local store and `/ready` is asked over a socket.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// The status of `GET /ready`.
fn ready(port: u16) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    write!(
        stream,
        "GET /ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer[9..12].parse().unwrap()
}

/// `nora serve` with its local store at `root`.
fn serve(dir: &Path, root: &Path) -> common::Nora {
    match common::start(dir, &[("NORA_STORAGE_PATH", root.to_str().unwrap())]) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A store that takes writes is ready once the first tick probed it, and stays ready when it
/// turns read-only until the next tick (`/ready` answers the last verdict and probes nothing);
/// a store read-only from the start is never ready, for well past the time the writable one
/// took. Skipped where a read-only directory still takes a file (a run as root).
#[test]
fn the_shipped_server_is_ready_only_on_a_store_its_probe_wrote_to() {
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    set_mode(&locked, 0o500);
    if std::fs::write(locked.join("x"), b"").is_ok() {
        set_mode(&locked, 0o700);
        eprintln!("skipped: a read-only directory takes a file here");
        return;
    }

    let writable = dir.path().join("writable");
    let started = Instant::now();
    let nora = serve(dir.path(), &writable);
    while ready(nora.port) != 200 {
        assert!(
            started.elapsed() < common::DEADLINE,
            "a writable store never got ready"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = started.elapsed();
    set_mode(&writable, 0o500);
    let after_lock = ready(nora.port);
    set_mode(&writable, 0o700);
    drop(nora);
    assert_eq!(after_lock, 200, "/ready probed the store on the request");

    let watched = (took * 3).max(Duration::from_secs(2));
    let started = Instant::now();
    let nora = serve(dir.path(), &locked);
    while started.elapsed() < watched {
        assert_eq!(ready(nora.port), 503, "a read-only store reported ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(nora);
    set_mode(&locked, 0o700);
}
