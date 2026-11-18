// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora gc --apply` and `nora retention-apply --yes` against the storage of a running server
//! (#988). Their deletions take the command's own, empty publish-lock map, not the server's, so
//! they are not serialized with the server's publishes. The commands say so on stderr when a
//! server is running on the storage, and when they cannot tell (an object store); a local
//! store with no server, or only the leftovers of a dead one, gets no warning.
//!
//! The server and the commands run as the shipped binary: whether a server is running is a
//! question one process asks about another.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// What both warnings say.
const NOT_SERIALIZED: &str = "are not serialized with the server's publishes";
/// The warning when a server is running on the storage.
const RUNNING: &str = "a NORA server is running on this storage";
/// The warning when the command cannot tell.
const CANNOT_TELL: &str = "cannot tell whether a NORA server is running";

/// The commands that delete, and the dry runs of the same commands.
const DELETING: [&[&str]; 2] = [&["gc", "--apply"], &["retention-apply", "--yes"]];
const DRY_RUNS: [&[&str]; 3] = [&["gc"], &["retention-plan"], &["retention-apply"]];

/// Runs `nora <args>` in `dir` with `envs` to its end: exit success and stderr.
fn run(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command
        .args(args)
        .current_dir(dir)
        .env_remove("NORA_CONFIG_PATH");
    for (key, value) in envs {
        command.env(key, value);
    }
    let started = Instant::now();
    let out = command.output().unwrap();
    assert!(
        started.elapsed() < common::DEADLINE,
        "nora {args:?} took {:?}",
        started.elapsed()
    );
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The lines of `stderr` that warn about the server.
fn warnings(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.contains(NOT_SERIALIZED))
        .collect()
}

/// Every deleting command warns, in one line, that a server is running and names itself;
/// no dry run warns.
fn assert_running_warning(dir: &Path, envs: &[(&str, &str)]) {
    for args in DELETING {
        let (ok, stderr) = run(dir, envs, args);
        assert!(ok, "nora {args:?} failed: {stderr}");
        let lines = warnings(&stderr);
        assert_eq!(lines.len(), 1, "nora {args:?}: {stderr}");
        assert!(lines[0].contains(RUNNING), "nora {args:?}: {stderr}");
        assert!(lines[0].contains(args[0]), "nora {args:?}: {stderr}");
    }
    assert_no_warning(dir, envs, &DRY_RUNS);
}

fn assert_no_warning(dir: &Path, envs: &[(&str, &str)], commands: &[&[&str]]) {
    for args in commands {
        let (ok, stderr) = run(dir, envs, args);
        assert!(ok, "nora {args:?} failed: {stderr}");
        assert!(warnings(&stderr).is_empty(), "nora {args:?}: {stderr}");
    }
}

/// A server running on the local store: the deleting commands warn.
#[test]
fn deleting_commands_warn_while_a_server_runs_on_the_local_store() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let envs = [("NORA_STORAGE_PATH", data.to_str().unwrap())];
    let _server = match common::start(dir.path(), &envs) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("exited with {code:?}: {stderr}"),
    };
    assert_running_warning(dir.path(), &envs);
}

/// A local store no server ever ran on: no warning.
#[test]
fn no_warning_on_a_local_store_without_a_server() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let envs = [("NORA_STORAGE_PATH", data.to_str().unwrap())];
    assert_no_warning(dir.path(), &envs, &DELETING);
}

/// A server killed with SIGKILL leaves its staging directory and lock file behind, but the
/// kernel released its lock with the process: no warning. A stale marker that a dead server
/// cannot clear is exactly what this check does not use.
#[test]
fn no_warning_after_the_server_was_killed() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let envs = [("NORA_STORAGE_PATH", data.to_str().unwrap())];
    match common::start(dir.path(), &envs) {
        // Dropping it kills it with SIGKILL and waits for it.
        common::Started::Serving(nora) => drop(nora),
        common::Started::Exited(code, stderr) => panic!("exited with {code:?}: {stderr}"),
    }
    let leftovers = std::fs::read_dir(data.join(".nora-staging"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().join("lock").exists())
        .count();
    assert_eq!(
        leftovers, 1,
        "the killed server left no staging lock behind"
    );
    assert_no_warning(dir.path(), &envs, &DELETING);
}

/// An S3 store: whether a server runs on it cannot be told, so the deleting commands say
/// that; no dry run warns.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_commands_on_an_object_store_say_they_cannot_tell() {
    use wiremock::matchers::{any, method, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let store = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("list-type", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>",
        ))
        .mount(&store)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404).set_body_string(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code></Error>",
        ))
        .mount(&store)
        .await;
    let uri = store.uri();
    tokio::task::spawn_blocking(move || {
        let dir = tempfile::tempdir().unwrap();
        let envs = [
            ("NORA_STORAGE_MODE", "s3"),
            ("NORA_STORAGE_S3_URL", uri.as_str()),
            ("NORA_STORAGE_BUCKET", "b"),
            ("NORA_STORAGE_ANSWER_TIMEOUT_SECS", "5"),
        ];
        for args in DELETING {
            let (_, stderr) = run(dir.path(), &envs, args);
            let lines = warnings(&stderr);
            assert_eq!(lines.len(), 1, "nora {args:?}: {stderr}");
            assert!(lines[0].contains(CANNOT_TELL), "nora {args:?}: {stderr}");
            assert!(lines[0].contains(args[0]), "nora {args:?}: {stderr}");
        }
        for args in DRY_RUNS {
            let (_, stderr) = run(dir.path(), &envs, args);
            assert!(warnings(&stderr).is_empty(), "nora {args:?}: {stderr}");
        }
    })
    .await
    .unwrap();
    // Keep the store up until the commands ended.
    drop(store);
}
