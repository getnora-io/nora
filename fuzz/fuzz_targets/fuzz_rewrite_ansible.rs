// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![no_main]
//! #385: the ansible raw-JSON URL rewrite must never leak the configured upstream
//! URL into client-facing output — neither the plain `https://host` form nor the
//! JSON slash-escaped `https:\/\/host` form that dodges a naive `.replace()`. Feeds
//! arbitrary text through `rewrite_ansible_urls` (which has a catch-all, so every
//! occurrence of the exact upstream URL is rewritten) and asserts neither form
//! survives. Run: `cargo +nightly fuzz run fuzz_rewrite_ansible`.
//!
//! NB: the invariant is on the exact upstream URL, not the bare host — arbitrary
//! fuzz bytes may contain the bare host without it being a rewrite failure.
use libfuzzer_sys::fuzz_target;
use nora_registry::rewrite_fuzz::rewrite_ansible_urls;

const UPSTREAM: &str = "https://origin-host.invalid";
const NORA_BASE: &str = "http://nora.test";

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let out = rewrite_ansible_urls(text, UPSTREAM, NORA_BASE);
        assert!(
            !out.contains(UPSTREAM),
            "plain upstream URL leaked through ansible rewrite (#385)"
        );
        let escaped = UPSTREAM.replace('/', "\\/");
        assert!(
            !out.contains(&escaped),
            "slash-escaped upstream URL leaked through ansible rewrite (#385)"
        );
    }
});
