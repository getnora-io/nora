// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![no_main]
//! URL-leak fuzz target (#385): a proxy-response rewrite must never leak the
//! configured upstream host into client-facing output. Feeds arbitrary npm
//! metadata bytes to `rewrite_tarball_urls` and asserts the exact configured
//! upstream URL never survives the rewrite — the #439 byte-level safety-net is
//! supposed to replace every occurrence, so any survivor (or a panic) is a
//! finding. Run: `cargo +nightly fuzz run fuzz_url_leak`.
use libfuzzer_sys::fuzz_target;
use nora_registry::npm_fuzz::rewrite_tarball_urls;

// RFC 6761 reserved `.invalid` TLD: never a real registry, so any surviving
// occurrence is rewrite-produced, not a fixture coincidence. The nora base is
// sentinel-free so a match is unambiguous. Scope: the EXACT configured upstream
// URL (what the rewrite is given); scheme/case variants are a separate concern.
const UPSTREAM: &str = "https://upstream-host.invalid";
const NORA_BASE: &str = "http://nora.test";

fuzz_target!(|data: &[u8]| {
    if let Ok(out) = rewrite_tarball_urls(data, NORA_BASE, UPSTREAM) {
        let leaked = out
            .windows(UPSTREAM.len())
            .any(|w| w == UPSTREAM.as_bytes());
        assert!(
            !leaked,
            "upstream URL leaked into rewritten npm metadata (#385)"
        );
    }
});
