//! `nora serve` with a configuration it cannot start with stops with EX_CONFIG (78), which the
//! packaged systemd units do not restart into (`RestartPreventExitStatus=78`): a curation file
//! NORA refuses in enforce mode stops the service instead of putting it into a restart loop.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

enum Outcome {
    /// The process exited: its code (`None` when a signal ended it) and what it wrote to stderr.
    Exited(Option<i32>, String),
    /// The process accepted a connection on its port, and was stopped by the test.
    Serving,
}

/// `nora serve` with a blocklist whose one rule names `registry`, in curation `mode`.
fn serve_with_blocklist(registry: &str, mode: &str) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        format!(
            r#"{{"version": 1, "rules": [{{"registry": "{registry}", "name": "six", "version": "*", "reason": "r"}}]}}"#
        ),
    )
    .unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nora"))
        .arg("serve")
        .current_dir(dir.path())
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.path().join("data"))
        .env("NORA_CURATION_MODE", mode)
        .env("NORA_CURATION_BLOCKLIST_PATH", &blocklist)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            return Outcome::Exited(status.code(), stderr);
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            child.kill().unwrap();
            child.wait().unwrap();
            return Outcome::Serving;
        }
        assert!(
            Instant::now() < deadline,
            "nora serve neither stopped nor served"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn an_unknown_registry_in_enforce_mode_stops_with_ex_config() {
    match serve_with_blocklist("pyip", "enforce") {
        Outcome::Exited(code, stderr) => {
            assert_eq!(code, Some(78), "{stderr}");
            assert!(stderr.contains("unknown registry 'pyip'"), "{stderr}");
        }
        Outcome::Serving => panic!("served with a blocklist naming an unknown registry"),
    }
}

/// The same file in audit mode, and a known registry in enforce mode, start and serve.
#[test]
fn audit_mode_and_a_known_registry_start() {
    for (registry, mode) in [("pyip", "audit"), ("PyPI", "enforce")] {
        match serve_with_blocklist(registry, mode) {
            Outcome::Serving => {}
            Outcome::Exited(code, stderr) => {
                panic!("{registry} in {mode}: exited with {code:?}: {stderr}")
            }
        }
    }
}
