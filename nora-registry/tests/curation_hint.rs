//! A curation refusal's hint, copied as it is into a shell, runs and explains the refusal;
//! its docs link is the curation page (#1099).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BLOCKLIST: &str = r#"{"version": 1, "rules": [
    {"registry": "npm", "name": "is-number", "version": "*", "reason": "r"},
    {"registry": "npm", "name": "@scope/pkg", "version": "*", "reason": "r"},
    {"registry": "raw", "name": "dir/my file.txt", "version": "*", "reason": "r"}
]}"#;

/// The curation settings both the server and the hint's command run with.
fn curation_env(command: &mut Command, dir: &Path) {
    command
        .current_dir(dir)
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_STORAGE_PATH", dir.join("data"))
        .env("NORA_CURATION_MODE", "enforce")
        .env("NORA_CURATION_BLOCKLIST_PATH", dir.join("blocklist.json"));
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve(dir: &Path, port: u16) -> Server {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command.arg("serve").env("NORA_PORT", port.to_string());
    curation_env(&mut command, dir);
    let mut server = Server(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(server.0.try_wait().unwrap().is_none(), "nora serve exited");
        assert!(Instant::now() < deadline, "nora serve did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    server
}

/// `GET path`: the status and the body.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").unwrap().1.to_string();
    (status, body)
}

#[test]
fn the_hint_of_a_refusal_runs_in_a_shell_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blocklist.json"), BLOCKLIST).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _server = serve(dir.path(), port);
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_nora")).parent().unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    for url in [
        "/npm/is-number/-/is-number-7.0.0.tgz",
        "/npm/@scope/pkg/-/pkg-1.0.0.tgz",
        // A tarball whose version cannot be read: the hint names no version.
        "/npm/@scope/pkg/-/unversioned.tgz",
        "/raw/dir/my%20file.txt",
    ] {
        let (status, body) = get(port, url);
        assert_eq!(status, 403, "{url}: {body}");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            json["docs"], "https://getnora.dev/configuration/curation/",
            "{url}"
        );
        let hint = json["hint"].as_str().unwrap();
        let command = hint.strip_prefix("Run: ").unwrap();

        let mut shell = Command::new("sh");
        shell.arg("-c").arg(command).env("PATH", &path);
        curation_env(&mut shell, dir.path());
        let out = shell.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{url}: `{command}`: {stdout}{stderr}");
        assert!(
            stdout.contains("Decision: Block") && stdout.contains("Decided by: blocklist"),
            "{url}: `{command}` does not explain the refusal: {stdout}"
        );
    }
}
