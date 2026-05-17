#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::npm_fuzz::rewrite_tarball_urls;
use nora_registry::version_fuzz::parse_npm_tarball_version;

fuzz_target!(|data: &[u8]| {
    // Fuzz npm metadata JSON rewriting — must never panic
    let _ = rewrite_tarball_urls(data, "http://nora:5000", "https://registry.npmjs.org");

    // Fuzz version parsing from tarball filenames
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_npm_tarball_version("lodash", s);
        let _ = parse_npm_tarball_version("@scope/name", s);
    }
});
