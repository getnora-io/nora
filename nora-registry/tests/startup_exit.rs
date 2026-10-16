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
    serve(&[
        ("NORA_CURATION_MODE", mode),
        ("NORA_CURATION_BLOCKLIST_PATH", blocklist.to_str().unwrap()),
    ])
}

/// `nora serve` with the settings in `envs`.
fn serve(envs: &[(&str, &str)]) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command
        .arg("serve")
        .current_dir(dir.path())
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.path().join("data"));
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command
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

/// #1099: a curation duration that does not parse stops startup with EX_CONFIG and names
/// itself, in every mode — `quarantine_ttl = "30m"` used to become 14 days without a
/// word, and an unparsable `min_release_age` outside enforce was only logged.
#[test]
fn an_unparsable_curation_duration_stops_with_ex_config_naming_it() {
    for (env, value, key, mode) in [
        (
            "NORA_CURATION_QUARANTINE_TTL",
            "30m",
            "curation.quarantine_ttl",
            "off",
        ),
        (
            "NORA_CURATION_NPM_QUARANTINE_TTL",
            "30m",
            "curation.npm.quarantine_ttl",
            "enforce",
        ),
        (
            "NORA_CURATION_MIN_RELEASE_AGE",
            "7x",
            "curation.min_release_age",
            "audit",
        ),
        (
            "NORA_CURATION_PYPI_MIN_RELEASE_AGE",
            "7x",
            "curation.pypi.min_release_age",
            "off",
        ),
        // a value the startup validator accepts but the consumer cannot
        // parse (a leading space) must be refused, not silently taken as 14d —
        // the validator parses exactly as `digest_quarantine`/`docker` do (no trim).
        (
            "NORA_CURATION_QUARANTINE_TTL",
            " 2d",
            "curation.quarantine_ttl",
            "off",
        ),
    ] {
        match serve(&[
            ("NORA_CURATION_MODE", mode),
            ("NORA_CURATION_QUARANTINE", "observe"),
            (env, value),
        ]) {
            Outcome::Exited(code, stderr) => {
                assert_eq!(code, Some(78), "{env}: {stderr}");
                assert!(
                    stderr.contains(&format!("{key}=\"{value}\"")),
                    "{env}: {stderr}"
                );
            }
            Outcome::Serving => panic!("{env}={value} in {mode}: served"),
        }
    }
}

/// #1099: when more than one curation duration is unparsable, startup
/// names EVERY one, not just the first — an operator fixing the first typo would
/// otherwise hit the second on the next start.
#[test]
fn every_unparsable_curation_duration_is_named_not_just_the_first() {
    match serve(&[
        ("NORA_CURATION_MODE", "off"),
        ("NORA_CURATION_QUARANTINE", "observe"),
        ("NORA_CURATION_QUARANTINE_TTL", "30m"),
        ("NORA_CURATION_NPM_MIN_RELEASE_AGE", "7x"),
    ]) {
        Outcome::Exited(code, stderr) => {
            assert_eq!(code, Some(78), "{stderr}");
            assert!(
                stderr.contains("curation.quarantine_ttl=\"30m\""),
                "first bad key not named: {stderr}"
            );
            assert!(
                stderr.contains("curation.npm.min_release_age=\"7x\""),
                "second bad key not named: {stderr}"
            );
        }
        Outcome::Serving => panic!("served with two unparsable durations"),
    }
}

/// Valid durations start as before.
#[test]
fn valid_curation_durations_start() {
    match serve(&[
        ("NORA_CURATION_MODE", "audit"),
        ("NORA_CURATION_QUARANTINE", "observe"),
        ("NORA_CURATION_QUARANTINE_TTL", "36h"),
        ("NORA_CURATION_NPM_QUARANTINE_TTL", "1w2d"),
        ("NORA_CURATION_MIN_RELEASE_AGE", "7d"),
    ]) {
        Outcome::Serving => {}
        Outcome::Exited(code, stderr) => panic!("exited with {code:?}: {stderr}"),
    }
}
