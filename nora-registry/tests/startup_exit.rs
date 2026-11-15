//! `nora serve` with a configuration it cannot start with stops with EX_CONFIG (78), which the
//! packaged systemd units do not restart into (`RestartPreventExitStatus=78`): a curation file
//! NORA refuses in enforce mode stops the service instead of putting it into a restart loop.

mod common;

enum Outcome {
    /// The process exited: its code (`None` when a signal ended it) and what it wrote to stderr.
    Exited(Option<i32>, String),
    /// The process logged that it bound its port, and was stopped by the test.
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
    let data = dir.path().join("data");
    let mut envs = envs.to_vec();
    envs.push(("NORA_STORAGE_PATH", data.to_str().unwrap()));
    match common::start(dir.path(), &envs) {
        common::Started::Serving(_) => Outcome::Serving,
        common::Started::Exited(code, stderr) => Outcome::Exited(code, stderr),
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

/// A port that answers is not NORA serving: with the port held by another listener, a start
/// that refuses its configuration is seen to exit with EX_CONFIG, and one that would serve is
/// seen to fail to bind — neither is taken for serving because something accepted the
/// connection.
#[test]
fn a_port_another_process_holds_is_not_taken_for_nora_serving() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "pyip", "name": "six", "version": "*", "reason": "r"}]}"#,
    )
    .unwrap();
    let data = dir.path().join("data");
    let data = data.to_str().unwrap();
    for (mode, refused) in [("enforce", true), ("audit", false)] {
        let envs = [
            ("NORA_CURATION_MODE", mode),
            ("NORA_CURATION_BLOCKLIST_PATH", blocklist.to_str().unwrap()),
            ("NORA_STORAGE_PATH", data),
        ];
        match common::start_on(dir.path(), &envs, port) {
            common::Started::Exited(code, stderr) if refused => {
                assert_eq!(code, Some(78), "{mode}: {stderr}")
            }
            common::Started::Exited(_, stderr) => {
                assert!(stderr.contains("Failed to bind"), "{mode}: {stderr}")
            }
            common::Started::Serving(_) => {
                panic!("{mode}: a port held by another listener was taken for nora serving")
            }
        }
    }
    drop(held);
}

/// A signing key file NORA will not sign with — one it cannot parse, or one whose primary key is
/// not Ed25519 — is a configuration it cannot start with: EX_CONFIG, so the unit stops instead of
/// restarting into the same refusal every few seconds. A key file that cannot be read at all is
/// not that: a volume mounted late can still appear, so it keeps the code a restart follows.
#[test]
fn a_signing_key_nora_will_not_sign_with_stops_with_ex_config() {
    use pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder};
    use pgp::crypto::ecc_curve::ECCCurve;

    let dir = tempfile::tempdir().unwrap();
    let ecdsa = SecretKeyParamsBuilder::default()
        .key_type(KeyType::ECDSA(ECCCurve::P256))
        .can_sign(true)
        .primary_user_id("operator key".into())
        .build()
        .unwrap()
        .generate(rand::thread_rng())
        .unwrap()
        .to_armored_string(ArmorOptions::default())
        .unwrap();
    let ecdsa_path = dir.path().join("ecdsa.key");
    std::fs::write(&ecdsa_path, &ecdsa).unwrap();
    let corrupt_path = dir.path().join("corrupt.key");
    std::fs::write(&corrupt_path, "not a pgp key").unwrap();
    let unreadable_path = dir.path().join("a-directory.key");
    std::fs::create_dir(&unreadable_path).unwrap();

    for (path, code, says) in [
        (&ecdsa_path, 78, "ECDSA keys are not accepted"),
        (&corrupt_path, 78, "parse signing key"),
        (&unreadable_path, 1, "read signing key"),
    ] {
        let path_str = path.to_str().unwrap();
        match serve(&[
            ("NORA_REGISTRIES_ENABLE", "rpm,deb"),
            ("NORA_SIGNING_ENABLED", "true"),
            ("NORA_SIGNING_KEY_PATH", path_str),
        ]) {
            Outcome::Exited(got, stderr) => {
                assert_eq!(got, Some(code), "{path_str}: {stderr}");
                assert!(stderr.contains(says), "{path_str}: {stderr}");
            }
            Outcome::Serving => panic!("{path_str}: served with a key it must refuse"),
        }
    }
    // The refusal leaves the operator's file as it was.
    assert_eq!(std::fs::read_to_string(&ecdsa_path).unwrap(), ecdsa);
}
