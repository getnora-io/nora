//! The binary as a release builds it carries no fault-injection route. Whatever turns the
//! `fault-injection` feature on — another feature, a build script, a `cfg`, a Cargo config —
//! shows in what is built, so this reads the result instead of the ways in: the `nora` binary
//! cargo builds for these tests, with the default features, as `cargo build --release` and the
//! Dockerfile do. A test run with `--features fault-injection` fails here, as it should: that
//! binary is the one `scripts/release-panic-check.sh` builds, never one that ships.

/// The prefix of every fault-injection route (`src/fault_injection.rs`).
const FAULT_ROUTES: &[u8] = b"/__fi/";

/// How many times `needle` occurs in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    memchr::memmem::find_iter(haystack, needle).count()
}

#[test]
fn the_binary_built_without_features_has_no_fault_injection_route() {
    let path = env!("CARGO_BIN_EXE_nora");
    let binary = std::fs::read(path).unwrap();
    assert!(binary.len() > 1_000_000, "{path} is the server binary");
    assert!(
        occurrences(&binary, b"/health") > 0,
        "{path}: the routes are found by their path"
    );
    assert_eq!(
        occurrences(&binary, FAULT_ROUTES),
        0,
        "{path} serves the fault-injection routes"
    );
}

#[test]
fn a_route_is_found_wherever_it_is_in_the_binary() {
    assert_eq!(occurrences(b"/__fi/panic", FAULT_ROUTES), 1);
    assert_eq!(
        occurrences(b"\0\0/__fi/panic\0/__fi/hang-maint", FAULT_ROUTES),
        2
    );
    assert_eq!(occurrences(b"/__f/panic /_fi/", FAULT_ROUTES), 0);
}

/// The mark the checks look for is in every fault-injection route, each added by `.route`: a
/// route renamed off it, or mounted under another prefix, would pass them unseen.
#[test]
fn every_fault_injection_route_carries_the_mark() {
    let module = concat!(env!("CARGO_MANIFEST_DIR"), "/src/fault_injection.rs");
    let text = std::fs::read_to_string(module).unwrap();
    let routes: Vec<&str> = text
        .match_indices(".route(")
        .map(|(at, _)| text[at + ".route(".len()..].trim_start())
        .collect();
    assert!(routes.len() >= 5, "{module}: {} routes", routes.len());
    for other in [".nest", ".route_service", ".fallback", ".merge"] {
        assert!(!text.contains(other), "{module}: routes added by {other}");
    }
    for route in routes {
        let mark = std::str::from_utf8(FAULT_ROUTES).unwrap();
        assert!(
            route.starts_with(&format!("\"{mark}")),
            "{module}: {route:.40}"
        );
    }
}

/// Each stage of the Dockerfile that builds the binary refuses one carrying the mark, in the
/// same instruction: the release binaries and images are built there.
#[test]
fn every_dockerfile_build_refuses_a_binary_with_a_fault_injection_route() {
    let dockerfile = concat!(env!("CARGO_MANIFEST_DIR"), "/../Dockerfile");
    let text = std::fs::read_to_string(dockerfile).unwrap();
    let builds: Vec<String> = text
        .replace("\\\n", " ")
        .lines()
        .filter(|line| line.trim_start().starts_with("RUN") && line.contains("cargo build"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(builds.len(), 2, "the amd64 and arm64 builds");
    let mark = std::str::from_utf8(FAULT_ROUTES).unwrap();
    for build in builds {
        assert!(
            build.ends_with(&format!("&& ! grep -qF '{mark}' /nora")),
            "{build}"
        );
    }
}
