//! A SIGHUP makes the running server re-read its configuration file and decide curation by it:
//! the signal, the file the server was started with, and the engine it installs, end to end.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

const PACKAGE: &str = "leftpad";

/// An npm upstream on a port it holds, whose versions were all published just now.
fn upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let at = base.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            if reader.read_line(&mut request).is_err() {
                continue;
            }
            let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let body = if path.contains("/-/") {
                format!("tarball {path}").into_bytes()
            } else {
                packument(&at).into_bytes()
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    base
}

fn packument(base: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let version = |v: &str| {
        serde_json::json!({
            "name": PACKAGE, "version": v,
            "dist": {"tarball": format!("{base}/{PACKAGE}/-/{PACKAGE}-{v}.tgz")}
        })
    };
    serde_json::json!({
        "name": PACKAGE,
        "dist-tags": {"latest": "2.0.0"},
        "versions": {"1.0.0": version("1.0.0"), "2.0.0": version("2.0.0")},
        "time": {"created": now, "modified": now, "1.0.0": now, "2.0.0": now}
    })
    .to_string()
}

/// The status of a tarball download of `version` from `nora`.
fn download(nora: &common::Nora, version: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", nora.port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    write!(
        stream,
        "GET /npm/{PACKAGE}/-/{PACKAGE}-{version}.tgz HTTP/1.1\r\nHost: nora\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status in {response:?}"))
}

fn config(upstream: &str, data: &str, curation: &str) -> String {
    format!(
        "[server]\ntrust_upstream_dates = true\n\n[storage]\npath = \"{data}\"\n\n\
         [registries]\nenable = [\"npm\"]\n\n[npm]\nproxy = \"{upstream}\"\n\n\
         [curation]\nmode = \"enforce\"\nquarantine = \"observe\"\n{curation}"
    )
}

/// NORA starts with no release-age rule; the file gains one and a new quarantine TTL, and a
/// SIGHUP follows. The server reports the reload, warns that the quarantine change waits for
/// a restart, naming the key, and refuses a version published just now, which it served before
/// the signal.
#[test]
fn a_sighup_applies_the_release_age_rule_the_file_gained() {
    let upstream = upstream();
    let dir = tempfile::tempdir().unwrap();
    // Not `config.toml`: a reload that ignored the file it was started with would find none.
    let file = dir.path().join("nora.toml");
    let data = dir.path().join("data");
    let data = data.to_str().unwrap();
    std::fs::write(&file, config(&upstream, data, "")).unwrap();
    let mut nora = match common::start(dir.path(), &[("NORA_CONFIG_PATH", file.to_str().unwrap())])
    {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("exited with {code:?}: {stderr}"),
    };
    assert_eq!(download(&nora, "1.0.0"), 200, "{}", nora.log());

    std::fs::write(
        &file,
        config(
            &upstream,
            data,
            "min_release_age = \"1h\"\nquarantine_ttl = \"3d\"\n",
        ),
    )
    .unwrap();
    nora.signal("HUP");
    let log = nora
        .until(|log| log.contains("Curation policy reloaded successfully"))
        .unwrap_or_else(|| panic!("nora exited on SIGHUP:\n{}", nora.log()));
    let warned = log
        .lines()
        .find(|line| line.contains("WARN") && line.contains("restart"))
        .unwrap_or_else(|| panic!("no warning that the quarantine waits for a restart:\n{log}"));
    assert!(warned.contains("curation.quarantine_ttl"), "{warned}");
    // The keys are listed quoted: the global mode, which the file left as it was, is not.
    assert!(warned.contains(r#"curation.quarantine_ttl\""#), "{warned}");
    assert!(!warned.contains(r#"curation.quarantine\""#), "{warned}");
    assert_eq!(
        download(&nora, "2.0.0"),
        403,
        "published just now, younger than the 1h the file gained:\n{}",
        nora.log()
    );
}
