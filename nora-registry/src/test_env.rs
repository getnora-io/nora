// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The one lock for every test that touches process env, and the test that keeps it so.
//!
//! Env vars are per-process state and `cargo test` runs tests as threads of one process,
//! so a test that skips this lock can read a value another test set — or, on glibc, call
//! `getenv` while another thread is inside `setenv`. One lock per module is not enough:
//! `config/storage.rs` and `config/mod.rs` both set `NORA_STORAGE_MODE`, and before this
//! module the first did so with no lock and the second under a lock private to its file,
//! so `test_unknown_mode_still_fails_closed` failed about once in five full runs.

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

/// Takes the env lock for the rest of the test: `let _lock = env_lock();` as the first
/// statement of the test body.
///
/// The mutex lives inside this function, so there is no way to lock it that skips the
/// poison reset: ~90 tests share it, and after one panicking test every later `lock()`
/// would fail too, turning a single failure into ninety that bury it.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    if ENV_MUTEX.is_poisoned() {
        ENV_MUTEX.clear_poison();
    }
    ENV_MUTEX.lock().unwrap()
}

/// Every env-touching test of the crate holds [`env_lock`].
///
/// A test is env-touching when its body writes env (`set_var`/`remove_var` in any path
/// form) or calls a function of the same file whose body touches env — `validate()` and
/// `apply_env_overrides()` read env themselves, so a test that only calls them is exposed
/// too. The scan covers every `.rs` under `src/`, so a new file is covered without a list
/// to update, and comments and string literals are blanked first, so neither a lock in a
/// comment nor a fixture in a string counts.
///
/// Known limit: readers are matched by name within one file. A test that reaches env only
/// through a function of another file is not seen; crate-wide names collide (`load` is
/// both `Config::load` and `AtomicUsize::load`), so widening needs real name resolution.
#[test]
fn every_env_touching_test_holds_the_env_lock() {
    matcher_self_test();

    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src_dir, &mut files);
    files.sort();

    let mut offenders = Vec::new();
    let mut env_test_files = Vec::new();
    let mut lock_defs = Vec::new();
    let mut config_readers = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let code = mask(&std::fs::read_to_string(path).unwrap());
        let scan = scan(&code);
        if scan.exposed_tests > 0 {
            env_test_files.push(rel.clone());
        }
        if rel == "config/mod.rs" {
            config_readers = scan.readers.clone();
        }
        offenders.extend(scan.offenders.into_iter().map(|t| format!("{rel}::{t}")));
        for item in fn_items(&code) {
            if item.name == "env_lock" {
                lock_defs.push(rel.clone());
            }
        }
        if rel != "test_env.rs" && has_ident(&code, "ENV_MUTEX") {
            lock_defs.push(format!("{rel} (ENV_MUTEX)"));
        }
    }

    // A scan that sees nothing passes everything: pin files known to hold env tests.
    for known in ["config/mod.rs", "config/storage.rs", "secrets/env.rs"] {
        assert!(
            env_test_files.iter().any(|f| f == known),
            "the scan no longer sees the env-touching tests of {known}; seen: {env_test_files:?}"
        );
    }
    for known in ["apply_env_overrides", "enabled_registries", "validate"] {
        assert!(
            config_readers.iter().any(|r| r == known),
            "the reader list of config/mod.rs lost {known}: {config_readers:?}"
        );
    }
    assert!(
        offenders.is_empty(),
        "these tests touch process env without holding the env lock: {}; \
         add `let _lock = crate::test_env::env_lock();` as the first statement",
        offenders.join(", ")
    );
    assert_eq!(
        lock_defs,
        vec!["test_env.rs".to_string()],
        "a second env lock serializes nothing against the first: use test_env::env_lock"
    );
}

/// Fixtures that a neutered matcher would pass in silence.
fn matcher_self_test() {
    let offenders = |src: &str| scan(&mask(src)).offenders;
    let none: Vec<String> = Vec::new();
    let t = |name: &str| vec![name.to_string()];

    // writers, in every path form, in sync and async tests
    assert_eq!(
        offenders("#[test]\nfn w() { std::env::set_var(\"A\", \"1\"); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[test]\nfn w() { env::remove_var(\"A\"); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[test]\nfn w() { set_var(\"A\", \"1\"); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[tokio::test]\nasync fn w() { set_var(\"A\", \"1\"); }"),
        t("w")
    );
    // a reader of the same file, but not a name that merely ends with it
    let reader = "fn rd() -> bool { env::var(\"A\").is_ok() }\n";
    assert_eq!(
        offenders(&format!("{reader}#[test]\nfn r() {{ rd(); }}")),
        t("r")
    );
    assert_eq!(
        offenders(&format!("{reader}#[test]\nfn r() {{ x.rd(); }}")),
        t("r")
    );
    assert_eq!(
        offenders(&format!("{reader}#[test]\nfn r() {{ hard(); }}")),
        none
    );
    // held: plain and by path
    assert_eq!(
        offenders("#[test]\nfn w() { let _lock = env_lock(); set_var(\"A\", \"1\"); }"),
        none
    );
    assert_eq!(
        offenders(
            "#[test]\nfn w() { let _g = crate::test_env::env_lock(); set_var(\"A\", \"1\"); }"
        ),
        none
    );
    // not held: dropped at once, taken late, scoped to an inner block, only in a comment
    assert_eq!(
        offenders("#[test]\nfn w() { let _ = env_lock(); set_var(\"A\", \"1\"); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[test]\nfn w() { set_var(\"A\", \"1\"); let _lock = env_lock(); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[test]\nfn w() { { let _lock = env_lock(); } set_var(\"A\", \"1\"); }"),
        t("w")
    );
    assert_eq!(
        offenders("#[test]\nfn w() { // let _lock = env_lock();\n set_var(\"A\", \"1\"); }"),
        t("w")
    );
    // text that only looks like env access is not env access
    assert_eq!(
        offenders("#[test]\nfn s() { let x = \"env::set_var(\"; }"),
        none
    );
    assert_eq!(offenders("#[test]\nfn s() { /* set_var(A) */ }"), none);
    // a '{' char literal must not break brace matching for the test after it
    assert_eq!(
        offenders("fn b(c: char) -> bool { c == '{' }\n#[test]\nfn w() { set_var(\"A\", \"1\"); }"),
        t("w")
    );
    // a non-test fn that writes env is a reader, not an offender
    assert_eq!(offenders("fn helper() { set_var(\"A\", \"1\"); }"), none);
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

struct Scan {
    /// Non-test functions of the file whose body touches env.
    readers: Vec<String>,
    /// Tests of the file that touch env, locked or not.
    exposed_tests: usize,
    /// Names of tests that touch env without holding the lock.
    offenders: Vec<String>,
}

const WRITERS: [&str; 2] = ["set_var", "remove_var"];
const READERS: [&str; 4] = ["env::var", "env::var_os", "env::vars", "env::vars_os"];

/// Scans one masked file: its env-touching functions are readers, and every test that
/// writes env or calls a reader must take the lock before the first such statement.
fn scan(code: &str) -> Scan {
    let items = fn_items(code);
    let touches = |body: &str| first_touch(body, &[]).is_some();
    let readers: Vec<&str> = items
        .iter()
        .filter(|f| !f.is_test && touches(&code[f.open..=f.close]))
        .map(|f| f.name)
        .collect();
    let mut scan = Scan {
        readers: readers.iter().map(|r| r.to_string()).collect(),
        exposed_tests: 0,
        offenders: Vec::new(),
    };
    for f in items.iter().filter(|f| f.is_test) {
        let body = &code[f.open..=f.close];
        let Some(first) = first_touch(body, &readers) else {
            continue;
        };
        scan.exposed_tests += 1;
        if !lock_held_before(body, first) {
            scan.offenders.push(f.name.to_string());
        }
    }
    scan
}

/// Offset in `body` of the first env write, env read or call of one of `readers`.
fn first_touch(body: &str, readers: &[&str]) -> Option<usize> {
    let calls = WRITERS.iter().chain(READERS.iter()).chain(readers.iter());
    calls.filter_map(|name| first_call(body, name)).min()
}

/// Offset of the first `name(` in `body` that starts at an identifier boundary.
fn first_call(body: &str, name: &str) -> Option<usize> {
    let needle = format!("{name}(");
    body.match_indices(&needle)
        .map(|(i, _)| i)
        .find(|&i| i == 0 || !is_ident_byte(body.as_bytes()[i - 1]))
}

/// Whether `body` binds the lock to a named guard at its top level before offset `first`.
fn lock_held_before(body: &str, first: usize) -> bool {
    body.match_indices("env_lock()").any(|(i, _)| {
        if i >= first || !is_ident_boundary(body, i) {
            return false;
        }
        // only the body's own braces may be open: a guard in an inner block is dropped
        let depth = body[..i].matches('{').count() - body[..i].matches('}').count();
        let before = body[..i].trim_end_matches(|c: char| is_ident_byte(c as u8) || c == ':');
        let Some(before) = before.trim_end().strip_suffix('=') else {
            return false;
        };
        let before = before.trim_end();
        let ident_at = before
            .rfind(|c: char| !is_ident_byte(c as u8))
            .map_or(0, |p| p + 1);
        let ident = &before[ident_at..];
        let is_let = before[..ident_at].trim_end().ends_with("let");
        depth == 1 && is_let && !ident.is_empty() && ident != "_"
    })
}

struct FnItem<'a> {
    name: &'a str,
    is_test: bool,
    open: usize,
    close: usize,
}

/// Every `fn` with a body in masked `code`, with whether a test attribute precedes it.
fn fn_items(code: &str) -> Vec<FnItem<'_>> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for (kw, _) in code.match_indices("fn ") {
        if !is_ident_boundary(code, kw) {
            continue;
        }
        let rest = &code[kw + 3..];
        let name_len = rest.find(|c: char| !is_ident_byte(c as u8)).unwrap_or(0);
        if name_len == 0 {
            continue;
        }
        let after = kw + 3 + name_len;
        let Some(open) = code[after..].find(['{', ';']).map(|i| after + i) else {
            continue;
        };
        if bytes[open] == b';' {
            continue; // a declaration without a body
        }
        let mut depth = 0usize;
        let Some(close) = bytes[open..].iter().enumerate().find_map(|(i, b)| {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + i);
                    }
                }
                _ => {}
            }
            None
        }) else {
            continue;
        };
        // attributes sit between the previous item's end and this `fn`
        let attrs_from = code[..kw].rfind(['{', '}', ';']).map_or(0, |i| i + 1);
        let attrs = &code[attrs_from..kw];
        let is_test = attrs.contains("#[test]") || attrs.contains("#[tokio::test");
        out.push(FnItem {
            name: &rest[..name_len],
            is_test,
            open,
            close,
        });
    }
    out
}

fn has_ident(code: &str, ident: &str) -> bool {
    code.match_indices(ident).any(|(i, _)| {
        is_ident_boundary(code, i)
            && code
                .as_bytes()
                .get(i + ident.len())
                .is_none_or(|&b| !is_ident_byte(b))
    })
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_boundary(code: &str, i: usize) -> bool {
    i == 0 || !is_ident_byte(code.as_bytes()[i - 1])
}

/// `src` with comments and the contents of string and char literals replaced by spaces,
/// byte for byte, so offsets stay valid and only code is left to match.
fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to.min(b.len())] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        // `r` opens a raw string unless it ends an identifier; `br` is a byte raw string
        let raw_prefix_ok = i == 0
            || !is_ident_byte(b[i - 1])
            || (b[i - 1] == b'b' && (i < 2 || !is_ident_byte(b[i - 2])));
        if b[i..].starts_with(b"//") {
            let end = src[i..].find('\n').map_or(b.len(), |e| i + e);
            blank(&mut out, i, end);
            i = end;
        } else if b[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if b[i] == b'r' && raw_prefix_ok && matches!(b.get(i + 1), Some(b'"' | b'#')) {
            let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                i += 1;
                continue;
            }
            let start = i + 2 + hashes;
            let close = format!("\"{}", "#".repeat(hashes));
            let end = src[start..].find(&close).map_or(b.len(), |e| start + e);
            blank(&mut out, start, end);
            i = end + close.len();
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if b[i] == b'\'' {
            // a char literal ends with a quote one char (or one escape) later; a lifetime does not
            let end = if b.get(i + 1) == Some(&b'\\') {
                src[i + 3..].find('\'').map(|e| i + 3 + e)
            } else {
                src[i + 1..]
                    .chars()
                    .next()
                    .map(|c| i + 1 + c.len_utf8())
                    .filter(|&e| b.get(e) == Some(&b'\''))
            };
            match end {
                Some(end) => {
                    blank(&mut out, i + 1, end);
                    i = end + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
