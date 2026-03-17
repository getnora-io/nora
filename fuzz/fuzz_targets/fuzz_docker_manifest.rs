#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::docker_fuzz::detect_manifest_media_type;

fuzz_target!(|data: &[u8]| {
    // Fuzz Docker manifest parser — must never panic on any input
    let _ = detect_manifest_media_type(data);
});
