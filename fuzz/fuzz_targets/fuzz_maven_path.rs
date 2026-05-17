#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::maven_fuzz::{
    classify_path, compare_maven_versions, is_checksum_file, is_snapshot, xml_escape,
};

fuzz_target!(|data: &str| {
    // Fuzz Maven path classification — must never panic on any input
    let _ = classify_path(data);

    // Fuzz checksum/snapshot detection
    let _ = is_checksum_file(data);
    let _ = is_snapshot(data);

    // Fuzz XML escaping — must never panic
    let _ = xml_escape(data);

    // Fuzz version comparison — must never panic
    let _ = compare_maven_versions(data, "1.0.0");
    let _ = compare_maven_versions("1.0.0", data);
    let _ = compare_maven_versions(data, data);
});
