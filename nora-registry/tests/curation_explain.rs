//! `nora curation explain` builds the same minimum-release-age filter as the server: a
//! per-registry value is shown and applied without a global one (#1098).

use std::process::{Command, Output};

/// `nora curation explain <package>` with the curation settings in `envs`.
fn explain(package: &str, envs: &[(&str, &str)]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command
        .args(["curation", "explain", package])
        .current_dir(dir.path())
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_STORAGE_PATH", dir.path().join("data"));
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

#[test]
fn a_per_registry_min_release_age_is_shown_without_a_global_one() {
    let out = explain(
        "npm:is-number@7.0.0",
        &[
            ("NORA_CURATION_MODE", "enforce"),
            ("NORA_CURATION_NPM_MIN_RELEASE_AGE", "3d"),
            ("NORA_CURATION_QUARANTINE", "observe"),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Min-release-age: npm: 3d"), "{stdout}");
}

#[test]
fn a_global_min_release_age_alone_is_shown_as_before() {
    // With no per-registry value, the line is the one 1.3.6 printed.
    let out = explain(
        "npm:is-number@7.0.0",
        &[
            ("NORA_CURATION_MODE", "enforce"),
            ("NORA_CURATION_MIN_RELEASE_AGE", "7d"),
            ("NORA_CURATION_QUARANTINE", "observe"),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.lines().any(|l| l == "Min-release-age: 7d (604800s)"),
        "{stdout}"
    );
}

#[test]
fn every_per_registry_value_is_shown_beside_the_global_one() {
    let out = explain(
        "npm:is-number@7.0.0",
        &[
            ("NORA_CURATION_MODE", "enforce"),
            ("NORA_CURATION_MIN_RELEASE_AGE", "7d"),
            ("NORA_CURATION_NPM_MIN_RELEASE_AGE", "3d"),
            ("NORA_CURATION_PYPI_MIN_RELEASE_AGE", "2d"),
            ("NORA_CURATION_GEMS_MIN_RELEASE_AGE", "1w"),
            ("NORA_CURATION_QUARANTINE", "observe"),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout
            .lines()
            .any(|l| l == "Min-release-age: 7d (npm: 3d, pypi: 2d, gems: 1w)"),
        "{stdout}"
    );
}
