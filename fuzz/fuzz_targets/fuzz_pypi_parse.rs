#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::pypi_fuzz::{extract_filename, parse_upstream_html};
use nora_registry::version_fuzz::parse_pypi_version;

fuzz_target!(|data: &str| {
    // Fuzz PyPI filename extraction from URLs — must never panic
    let _ = extract_filename(data);

    // Fuzz PyPI HTML index parsing — must never panic on any HTML
    let _ = parse_upstream_html(data);

    // Fuzz PyPI version parsing from filenames
    let _ = parse_pypi_version("my-package", data);
    let _ = parse_pypi_version("numpy", data);
});
